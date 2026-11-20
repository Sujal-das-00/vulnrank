"""GAS_PRICE_GENERAL and ONCHAIN_TX_LOOKUP_GENERAL over public JSON-RPC, two independent operators per chain."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

CHAINS: dict[str, dict[str, Any]] = {
    "eth": {"name": "Ethereum", "symbol": "ETH", "rpcs": ["https://ethereum-rpc.publicnode.com", "https://1rpc.io/eth"]},
    "base": {"name": "Base", "symbol": "ETH", "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com"]},
    "arbitrum": {"name": "Arbitrum One", "symbol": "ETH", "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"]},
    "polygon": {"name": "Polygon", "symbol": "POL", "rpcs": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.drpc.org"]},
    "optimism": {"name": "Optimism", "symbol": "ETH", "rpcs": ["https://mainnet.optimism.io", "https://optimism-rpc.publicnode.com"]},
}
ALIASES = {
    "ethereum": "eth", "mainnet": "eth", "ether": "eth", "eth": "eth", "base": "base", "arbitrum": "arbitrum", "arb": "arbitrum",
    "arbitrum one": "arbitrum", "polygon": "polygon", "matic": "polygon", "pol": "polygon", "optimism": "optimism", "op": "optimism",
}
TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}\b")
MAX_GAS_DISAGREE = 1.5  # ratio between the two operators' quotes beyond which we flag a conflict


def resolve_chain(params: dict[str, Any]) -> tuple[str | None, bool]:
    """-> (chain key or None, named). `named` is True when the caller named a chain we do not serve."""
    raw = first(params, "chain", "network", "chain_id", "blockchain")
    if raw:
        low = raw.lower().strip()
        if low in ALIASES:
            return ALIASES[low], True
        if low.isdigit():
            ids = {"1": "eth", "8453": "base", "42161": "arbitrum", "137": "polygon", "10": "optimism"}
            return ids.get(low), True
        for a in sorted(ALIASES, key=len, reverse=True):
            if re.search(rf"\b{a}\b", low):
                return ALIASES[a], True
        return None, True
    text = free_text(params).lower()
    for a in sorted(ALIASES, key=len, reverse=True):
        if re.search(rf"\b{a}\b", text):
            return ALIASES[a], True
    return None, False


async def rpc(f: Fetcher, url: str, method: str, args: list, timeout: float, deadline: float | None) -> Any:
    status, js = await f.get_json(url, timeout=timeout, deadline=deadline,
                                  json_body={"jsonrpc": "2.0", "id": 1, "method": method, "params": args})
    if not isinstance(js, dict) or js.get("error") or "result" not in js:
        raise SourceError("malformed", f"{url} returned an RPC error or no result for {method}")
    return js["result"]


def _hex(v: Any) -> int:
    return int(v, 16)


def _fmt_gwei(wei: int) -> float:
    return round(wei / 1e9, 9)


async def _gas_quote(f: Fetcher, url: str, timeout: float, deadline: float | None) -> dict[str, Any]:
    price, block = await asyncio.gather(rpc(f, url, "eth_gasPrice", [], timeout, deadline),
                                        rpc(f, url, "eth_getBlockByNumber", ["latest", False], timeout, deadline))
    return {"wei": _hex(price), "block": _hex(block["number"]), "base_fee_wei": _hex(block["baseFeePerGas"]) if block.get("baseFeePerGas") else None,
            "block_time": _hex(block["timestamp"])}


async def gas_price(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    chain, named = resolve_chain(params)
    if chain is None:
        msg = ("The requested network is not supported (supported: " + ", ".join(c["name"] for c in CHAINS.values()) + ")."
               if named else "No blockchain network was named, so no gas price is given. Supply chain (eth, base, arbitrum, polygon, optimism).")
        return soft("chain_not_identified", msg, gas_price_gwei=None, chain=None)
    meta = CHAINS[chain]
    results = await asyncio.gather(*(_gas_quote(f, u, timeout, deadline) for u in meta["rpcs"]), return_exceptions=True)
    quotes = [(u, r) for u, r in zip(meta["rpcs"], results) if isinstance(r, dict)]
    if not quotes:
        return soft("unavailable", f"No {meta['name']} RPC answered, so no gas price is given rather than a guess.", gas_price_gwei=None, chain=chain)
    quotes.sort(key=lambda t: -t[1]["block"])  # freshest head first
    best = quotes[0][1]
    conflict = False
    if len(quotes) == 2:
        lo, hi = sorted(q["wei"] for _, q in quotes)
        conflict = hi > MAX_GAS_DISAGREE * max(lo, 1) and hi - lo > 1e8  # >0.1 gwei and >50% apart
    conf = 0.95 if len(quotes) == 2 and not conflict else (0.5 if conflict else 0.7)
    gwei = _fmt_gwei(best["wei"])
    cost_native = best["wei"] * 21000 / 1e18
    shown = f"{gwei:.4f}" if gwei < 1 else f"{gwei:.2f}"
    answer = (f"The current {meta['name']} gas price is {shown} Gwei at block {best['block']:,}; a 21,000-gas transfer costs about "
              f"{cost_native:.8f} {meta['symbol']}.")
    answer += (" Two RPC operators agree." if conf == 0.95 else " The two RPC operators disagree materially; the freshest head is shown." if conflict
               else " Only one RPC operator answered.")
    return ok(answer, conf, gas_price_gwei=gwei, gas_price_wei=str(best["wei"]), chain=chain, chain_name=meta["name"], block_number=best["block"],
              base_fee_gwei=_fmt_gwei(best["base_fee_wei"]) if best["base_fee_wei"] is not None else None,
              transfer_cost_native=round(cost_native, 12), native_symbol=meta["symbol"], sources_agreeing=len(quotes) if not conflict else 1,
              unit="gwei")


async def _tx_view(f: Fetcher, url: str, tx_hash: str, timeout: float, deadline: float | None) -> dict[str, Any] | None:
    tx = await rpc(f, url, "eth_getTransactionByHash", [tx_hash], timeout, deadline)
    if not tx:
        return None
    out: dict[str, Any] = {"tx": tx, "receipt": None, "head": None}
    if tx.get("blockNumber"):
        out["receipt"], out["head"] = await asyncio.gather(rpc(f, url, "eth_getTransactionReceipt", [tx_hash], timeout, deadline),
                                                           rpc(f, url, "eth_blockNumber", [], timeout, deadline))
    return out


async def tx_lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    raw = first(params, "tx_hash", "hash", "txhash", "transaction", "tx", "transaction_hash") or ""
    m = TX_HASH.search(raw) or TX_HASH.search(free_text(params))
    if not m:
        return soft("no_tx_hash", "No transaction hash (0x followed by 64 hex characters) was found, so nothing can be looked up.",
                    status=None, tx_hash=None)
    tx_hash = m.group(0).lower()
    chain, named = resolve_chain(params)
    if chain is None and named:
        return soft("chain_not_supported", "The requested network is not supported (supported: " + ", ".join(c["name"] for c in CHAINS.values()) + ").",
                    tx_hash=tx_hash)
    candidates = [chain] if chain else list(CHAINS)
    probes = await asyncio.gather(*(rpc(f, CHAINS[c]["rpcs"][0], "eth_getTransactionByHash", [tx_hash], timeout, deadline) for c in candidates),
                                  return_exceptions=True)
    found = [c for c, r in zip(candidates, probes) if isinstance(r, dict)]
    if not found:
        failed = [c for c, r in zip(candidates, probes) if isinstance(r, Exception)]
        # the primary RPC of a chain may be down: retry those chains once through the second operator
        if failed:
            again = await asyncio.gather(*(rpc(f, CHAINS[c]["rpcs"][1], "eth_getTransactionByHash", [tx_hash], timeout, deadline) for c in failed),
                                         return_exceptions=True)
            found = [c for c, r in zip(failed, again) if isinstance(r, dict)]
            failed = [c for c, r in zip(failed, again) if isinstance(r, Exception)]
        if not found:
            if failed:
                return soft("unavailable", "Blockchain RPCs were unavailable, so the transaction status is unknown (not reported as missing).",
                            tx_hash=tx_hash)
            where = CHAINS[chain]["name"] if chain else "any supported network (" + ", ".join(c["name"] for c in CHAINS.values()) + ")"
            return ok(f"Transaction {tx_hash} was not found on {where}.", 0.8, tx_hash=tx_hash, status="not_found", chain=chain,
                      chain_name=CHAINS[chain]["name"] if chain else None)
    if len(found) > 1:
        return soft("ambiguous_chain", f"Transaction {tx_hash} exists on several networks ({', '.join(found)}); specify chain.", tx_hash=tx_hash)
    chain = found[0]
    meta = CHAINS[chain]
    views = await asyncio.gather(*(_tx_view(f, u, tx_hash, timeout, deadline) for u in meta["rpcs"]), return_exceptions=True)
    views = [v for v in views if isinstance(v, dict)]
    if not views:
        return soft("unavailable", "Blockchain RPCs were unavailable, so the transaction status is unknown.", tx_hash=tx_hash)
    hashes = {v["tx"].get("blockHash") for v in views}
    if len(hashes) > 1:
        return soft("conflicting", "Two RPC operators report different blocks for this transaction (possible reorg); no status is given.", tx_hash=tx_hash, chain=chain)
    v = views[0]
    tx, rc = v["tx"], v["receipt"]
    value_wei = _hex(tx.get("value") or "0x0")
    to = tx.get("to")
    base = {"tx_hash": tx_hash, "chain": chain, "chain_name": meta["name"], "from": tx.get("from"), "to": to,
            "value_wei": str(value_wei), "native_symbol": meta["symbol"], "contract_creation": to is None,
            "method_selector": (tx.get("input") or "0x")[:10] if len(tx.get("input") or "0x") >= 10 else None,
            "sources_agreeing": len(views)}
    conf = 0.95 if len(views) == 2 else 0.7
    if not tx.get("blockNumber") or not rc:
        return ok(f"Transaction {tx_hash} on {meta['name']} is pending: it has been seen by the network but is not yet in a block.", conf,
                  status="pending", block_number=None, value_eth=None, **base)
    bn = _hex(tx["blockNumber"])
    success = _hex(rc["status"]) == 1 if rc.get("status") is not None else None
    status = "confirmed" if success else "reverted" if success is False else "confirmed"
    confirmations = max(0, _hex(v["head"]) - bn + 1) if v["head"] else None
    # a reverted transaction transfers nothing
    value_eth = 0.0 if status == "reverted" else value_wei / 1e18
    gas_used = _hex(rc["gasUsed"]) if rc.get("gasUsed") else None
    eff = _hex(rc["effectiveGasPrice"]) if rc.get("effectiveGasPrice") else None
    base.update({"value_eth": value_eth, "block_number": bn, "block_hash": tx.get("blockHash"), "gas_used": gas_used,
                 "effective_gas_price_gwei": _fmt_gwei(eff) if eff is not None else None, "confirmations": confirmations,
                 "receipt_status": None if success is None else int(success)})
    if status == "confirmed":
        answer = (f"Transaction {tx_hash} on {meta['name']} is confirmed in block {bn:,} ({confirmations:,} confirmations): "
                  f"{value_eth:g} {meta['symbol']} from {tx.get('from')} to {to or 'a new contract'}, {gas_used:,} gas used.")
    else:
        answer = f"Transaction {tx_hash} on {meta['name']} was mined in block {bn:,} but REVERTED, so no {meta['symbol']} was transferred."
    return ok(answer, conf if confirmations and confirmations >= 3 else min(conf, 0.8), status=status, **base)
