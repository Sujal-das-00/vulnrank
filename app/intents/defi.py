"""TVL_LOOKUP_GENERAL, CRYPTO_YIELD_RATE_GENERAL and LIQUIDITY_DEPTH_VERIFY_GENERAL from DefiLlama (keyless public API).

One upstream, so confidence is capped below the two-source intents and the answer names the source. A pool or protocol that is not
found is reported as not found; an outage is reported as unavailable."""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.evm import ADDR
from app.sources.base import Fetcher, SourceError

TVL_URL, CHAINS_URL, POOLS_URL = "https://api.llama.fi/tvl/{slug}", "https://api.llama.fi/v2/chains", "https://yields.llama.fi/pools"
POOLS_TTL, CHAINS_TTL = 1800.0, 900.0
MIN_POOL_TVL = 10_000
CHAIN_ALIASES = {"eth": "Ethereum", "ethereum": "Ethereum", "mainnet": "Ethereum", "base": "Base", "arbitrum": "Arbitrum", "arb": "Arbitrum", "polygon": "Polygon", "matic": "Polygon",
                 "optimism": "Optimism", "op": "Optimism", "bsc": "BSC", "bnb": "BSC", "avalanche": "Avalanche", "avax": "Avalanche", "solana": "Solana", "sol": "Solana", "tron": "Tron",
                 "fantom": "Fantom", "gnosis": "Gnosis", "linea": "Linea", "scroll": "Scroll", "zksync": "zkSync Era", "mantle": "Mantle", "blast": "Blast", "sui": "Sui", "aptos": "Aptos"}
NOISE = re.compile(r"\b(?:what|whats|what's|is|the|of|on|in|for|total|value|locked|tvl|protocol|pool|chain|network|current|currently|right now|now|how much|much|give|me|show|a|an|does|have|has|its|it|how|big|large|usd|dollars)\b", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DefiIndex:
    """Process-wide cache of the DefiLlama pool list (about 6 MB) and chain TVLs; refreshed in the background, stale data kept on failure."""

    def __init__(self, fetcher: Fetcher):
        self.f = fetcher
        self.pools: list[dict[str, Any]] = []
        self.pools_at = 0.0
        self.chains: dict[str, float] = {}
        self.chains_at = 0.0
        self._ptask: asyncio.Future | None = None
        self._ctask: asyncio.Future | None = None

    async def _load_pools(self) -> None:
        _, js = await self.f.get_json(POOLS_URL, timeout=40.0)
        rows = js.get("data") if isinstance(js, dict) else None
        if not isinstance(rows, list):
            raise SourceError("malformed", "unexpected yields response")
        keep = ("chain", "project", "symbol", "tvlUsd", "apy", "apyBase", "apyReward", "pool", "poolMeta", "volumeUsd1d", "underlyingTokens", "stablecoin", "ilRisk")
        self.pools = [{k: r.get(k) for k in keep} for r in rows if isinstance(r, dict) and (r.get("tvlUsd") or 0) >= MIN_POOL_TVL]
        self.pools_at = time.time()

    async def _load_chains(self) -> None:
        _, js = await self.f.get_json(CHAINS_URL, timeout=15.0)
        if not isinstance(js, list):
            raise SourceError("malformed", "unexpected chains response")
        self.chains = {str(c["name"]): float(c.get("tvl") or 0) for c in js if isinstance(c, dict) and c.get("name")}
        self.chains_at = time.time()

    async def _ensure(self, attr: str, at: str, ttl: float, loader, deadline: float | None) -> bool:
        if getattr(self, attr) and time.time() - getattr(self, at) < ttl:
            return True
        tname = "_ptask" if attr == "pools" else "_ctask"
        task = getattr(self, tname)
        if task is None or task.done():
            task = asyncio.ensure_future(loader())
            setattr(self, tname, task)
        remaining = None if deadline is None else max(0.1, deadline - time.monotonic())
        await asyncio.wait({task}, timeout=remaining)
        if task.done() and task.exception():
            task.exception()  # retrieved, so it is not logged as never-awaited; stale data (if any) is served
        return bool(getattr(self, attr))

    async def ensure_pools(self, deadline: float | None = None) -> bool:
        return await self._ensure("pools", "pools_at", POOLS_TTL, self._load_pools, deadline)

    async def ensure_chains(self, deadline: float | None = None) -> bool:
        return await self._ensure("chains", "chains_at", CHAINS_TTL, self._load_chains, deadline)


def resolve_chain_name(raw: str | None) -> str | None:
    if not raw:
        return None
    low = raw.lower().strip()
    return CHAIN_ALIASES.get(low) or next((v for k, v in CHAIN_ALIASES.items() if re.search(rf"\b{re.escape(k)}\b", low)), None)


def _slug_candidates(name: str) -> list[str]:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    out = [base]
    trimmed = re.sub(r"-(?:finance|protocol|dao|network|swap|exchange)$", "", base)
    for extra in (trimmed, base.replace("-v", "-v") if "-v" in base else None):
        if extra and extra not in out:
            out.append(extra)
    return out[:3]


async def tvl_lookup(f: Fetcher, idx: DefiIndex, params: dict[str, Any], *, timeout: float, deadline: float | None, **_: Any) -> dict[str, Any]:
    text = free_text(params)
    raw = first(params, "protocol", "name", "chain", "pool", "project", "token") or ""
    chain_param = first(params, "chain", "network")
    combined = f"{raw} {text}".strip()
    if not combined:
        return soft("no_protocol", "No protocol, pool or chain was named, so no TVL is given.", tvl_usd=None, protocol_or_chain=None)
    chain_name = resolve_chain_name(chain_param) or (resolve_chain_name(text) if not raw else None)
    m = ADDR.search(combined)
    if m:  # a token contract: total liquidity of the DEX pairs it sits in, from the pool index
        token = m.group(0).lower()
        if not await idx.ensure_pools(deadline):
            return soft("unavailable", "The DeFi data source is unavailable, so no liquidity figure is given.", tvl_usd=None, protocol_or_chain=token)
        pairs = [p for p in idx.pools if "-" in (p["symbol"] or "") and token in [str(t).lower() for t in (p.get("underlyingTokens") or [])]
                 and (not chain_name or p["chain"] == chain_name)]
        if not pairs:
            return soft("not_found", f"No DEX pool containing {token}{' on ' + chain_name if chain_name else ''} was found in DefiLlama's yield pools (pools under $10,000 are not indexed), so no liquidity is given.",
                        tvl_usd=None, protocol_or_chain=token)
        total = sum(p["tvlUsd"] for p in pairs)
        top = sorted(pairs, key=lambda p: -p["tvlUsd"])[:3]
        answer = (f"Token {token} has ${total:,.0f} of liquidity across {len(pairs)} DEX pool(s)"
                  + (f" on {chain_name}" if chain_name else "") + "; largest: " + ", ".join(f"{p['project']} {p['symbol']} on {p['chain']} (${p['tvlUsd']:,.0f})" for p in top) + ". Source: DefiLlama.")
        return ok(answer, 0.75, protocol_or_chain=token, tvl_usd=round(total, 2), chain_tvl_usd=None, pool_count=len(pairs), as_of=_now(), source="DefiLlama")
    cleaned = NOISE.sub(" ", raw or text)
    cleaned = re.sub(r"[?!.,'\"]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        cleaned = raw
    chain_only = resolve_chain_name(cleaned) if len(cleaned.split()) <= 2 else None
    proto_tvl, proto_slug, failed = None, None, False
    if not chain_only or chain_only.lower() != cleaned.lower():
        for slug in _slug_candidates(cleaned):
            try:
                status, js = await f.get_json(TVL_URL.format(slug=slug), timeout=timeout, deadline=deadline, soft_statuses=frozenset({400}))
            except SourceError:
                failed = True
                break
            if status == 200 and isinstance(js, (int, float)):
                proto_tvl, proto_slug = float(js), slug
                break
    chain_tvl = None
    want_chain = chain_name or chain_only
    if want_chain or proto_tvl is None:
        if await idx.ensure_chains(deadline):
            key = next((k for k in idx.chains if k.lower() == (want_chain or cleaned).lower()), None)
            chain_tvl = idx.chains.get(key) if key else None
            if want_chain is None and key:
                want_chain = key
        elif proto_tvl is None:
            failed = True
    if proto_tvl is None and chain_tvl is None:
        if failed:
            return soft("unavailable", "The DeFi data source is unavailable, so no TVL is given (not reported as zero).", tvl_usd=None, protocol_or_chain=cleaned)
        return soft("not_found", f"No DeFi protocol or chain matching '{cleaned}' was found in DefiLlama, so no TVL is given. Try the protocol's DefiLlama name, such as aave-v3 or uniswap-v3.",
                    tvl_usd=None, protocol_or_chain=cleaned)
    if proto_tvl is not None:
        answer = f"The total value locked in {proto_slug} is ${proto_tvl:,.0f}" + (f"; {want_chain} chain TVL is ${chain_tvl:,.0f}" if chain_tvl is not None else "") + ". Source: DefiLlama."
        return ok(answer, 0.8, protocol_or_chain=proto_slug, tvl_usd=round(proto_tvl, 2), chain_tvl_usd=None if chain_tvl is None else round(chain_tvl, 2),
                  chain=want_chain, as_of=_now(), source="DefiLlama")
    answer = f"The total value locked on {want_chain} is ${chain_tvl:,.0f}. Source: DefiLlama."
    return ok(answer, 0.8, protocol_or_chain=want_chain, tvl_usd=round(chain_tvl, 2), chain_tvl_usd=round(chain_tvl, 2), chain=want_chain, as_of=_now(), source="DefiLlama")


def _sym_tokens(sym: str) -> list[str]:
    return [t for t in re.split(r"[-/ ]+", (sym or "").upper()) if t]


async def yield_rate(f: Fetcher, idx: DefiIndex, params: dict[str, Any], *, timeout: float, deadline: float | None, **_: Any) -> dict[str, Any]:
    text = free_text(params).lower()
    project = (first(params, "project", "protocol", "platform") or "").lower().strip()
    symbol = (first(params, "symbol", "token", "asset") or "").upper().strip()
    chain = resolve_chain_name(first(params, "chain", "network")) or resolve_chain_name(text)
    if not project and not symbol and text:
        m = re.search(r"\b(aave|compound|morpho|lido|spark|maker|sky|curve|uniswap|rocket|ethena|pendle|convex|yearn|fluid|euler|venus|benqi|kamino|jito|marinade)\b", text)
        project = m.group(1) if m else ""
        m2 = re.search(r"\b(usdc|usdt|dai|eth|weth|wbtc|steth|sol|usde|susde|frax|btc)\b", text)
        symbol = m2.group(1).upper() if m2 else ""
    if not project and not symbol:
        return soft("no_pool_identified", "No protocol or token was named, so no yield is given. Supply project and symbol, for example project=aave, symbol=USDC, chain=ethereum.", supply_apy=None)
    if not await idx.ensure_pools(deadline):
        return soft("unavailable", "The DeFi yield data source is unavailable, so no APY is given.", supply_apy=None)
    cands = [p for p in idx.pools
             if (not project or project in p["project"].lower())
             and (not symbol or symbol in _sym_tokens(p["symbol"]) or symbol == (p["symbol"] or "").upper())
             and (not chain or p["chain"] == chain) and p.get("apy") is not None]
    exact = [p for p in cands if not symbol or (p["symbol"] or "").upper() == symbol]
    pick_from = exact or cands
    if not pick_from:
        return soft("not_found", f"No DefiLlama pool matched project '{project or '*'}', symbol '{symbol or '*'}'" + (f" on {chain}" if chain else "") + " with at least $10,000 of liquidity, so no yield is given.",
                    supply_apy=None, project=project or None, symbol=symbol or None, chain=chain)
    best = max(pick_from, key=lambda p: p["tvlUsd"])  # the deepest matching pool is the reference market
    apy = round(float(best["apy"]), 4)
    others = len(pick_from) - 1
    answer = (f"{best['project']} {best['symbol']} on {best['chain']} currently yields {apy:.2f}% APY"
              + (f" ({best['apyBase']:.2f}% base" + (f" + {best['apyReward']:.2f}% rewards)" if best.get("apyReward") else ")") if best.get("apyBase") is not None else "")
              + f", with ${best['tvlUsd']:,.0f} deposited" + (f". Chosen as the largest of {len(pick_from)} matching pools." if others else ".") + " Source: DefiLlama; APY varies continuously.")
    return ok(answer, 0.8 if not others else 0.65, supply_apy=apy, apy_base=best.get("apyBase"), apy_reward=best.get("apyReward"), project=best["project"], symbol=best["symbol"],
              chain=best["chain"], tvl_usd=round(best["tvlUsd"], 2), pool_id=best["pool"], pool_meta=best.get("poolMeta"), matching_pools=len(pick_from), unit="percent per year",
              as_of=_now(), source="DefiLlama")


def _trade_size_usd(text: str) -> float | None:
    m = re.search(r"\$\s?(\d[\d,]*(?:\.\d+)?)\s?(k|m|million|thousand)?", text, re.I)
    if not m:
        return None
    v = float(m.group(1).replace(",", ""))
    return v * {"k": 1e3, "thousand": 1e3, "m": 1e6, "million": 1e6}.get((m.group(2) or "").lower(), 1)


async def liquidity_depth(f: Fetcher, idx: DefiIndex, params: dict[str, Any], *, timeout: float, deadline: float | None, **_: Any) -> dict[str, Any]:
    text = free_text(params)
    pool_raw = first(params, "pool", "pair", "market", "symbol") or ""
    chain = resolve_chain_name(first(params, "chain", "network")) or resolve_chain_name(text) or resolve_chain_name(pool_raw)
    src = pool_raw or text
    if not src:
        return soft("no_pool_identified", "No pool or pair was named, so no liquidity is given.", liquidity_usd=None)
    if not await idx.ensure_pools(deadline):
        return soft("unavailable", "The DeFi data source is unavailable, so no liquidity figure is given.", liquidity_usd=None)
    uuid = re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", src)
    if uuid:
        pools = [p for p in idx.pools if p["pool"] == uuid.group(0)]
    else:
        toks = [t for t in re.findall(r"\b[A-Za-z][A-Za-z0-9]{1,9}\b", pool_raw or text.upper()) if t.upper() in {w.upper() for w in re.findall(r"[A-Za-z0-9]+", src)}]
        pair = re.search(r"\b([A-Za-z0-9]{2,10})\s*[-/]\s*([A-Za-z0-9]{2,10})\b", src)
        want = {pair.group(1).upper(), pair.group(2).upper()} if pair else None
        proj = next((p for p in ("uniswap-v3", "uniswap-v2", "uniswap-v4", "aerodrome", "velodrome", "curve", "pancakeswap", "sushiswap", "balancer", "camelot", "raydium", "orca") if p.split("-")[0] in src.lower()), None)
        if not want:
            return soft("no_pool_identified", "No trading pair (for example WETH/USDC) or pool id was found, so no liquidity is given.", liquidity_usd=None)
        aliasmap = {"ETH": {"ETH", "WETH"}, "WETH": {"ETH", "WETH"}, "BTC": {"WBTC", "BTC", "CBBTC"}, "WBTC": {"WBTC", "BTC", "CBBTC"}}
        wants = [aliasmap.get(w, {w}) for w in want]
        pools = [p for p in idx.pools if "-" in (p["symbol"] or "") and len(_sym_tokens(p["symbol"])) == 2
                 and all(any(t in w for t in _sym_tokens(p["symbol"])) for w in wants)
                 and (not chain or p["chain"] == chain) and (not proj or p["project"].startswith(proj))]
        del toks
    if not pools:
        return soft("not_found", f"No indexed DEX pool matched '{src[:60]}'" + (f" on {chain}" if chain else "") + " (pools under $10,000 are not indexed), so no liquidity is given.", liquidity_usd=None)
    best = max(pools, key=lambda p: p["tvlUsd"])
    liq = round(best["tvlUsd"], 2)
    trade = _trade_size_usd(text)
    extra: dict[str, Any] = {}
    note = ""
    if trade and liq > 0:
        slip = round(100 * trade / (liq / 2 + trade), 3)  # constant-product price impact with each side holding half the pool value
        extra = {"trade_size_usd": trade, "estimated_slippage_pct": slip, "slippage_model": "constant-product approximation from pool TVL (concentrated-liquidity pools are usually tighter near the price)"}
        note = f" A ${trade:,.0f} swap would move the price about {slip:.2f}% under a constant-product approximation."
    answer = (f"The deepest matching pool, {best['project']} {best['symbol']} on {best['chain']}" + (f" ({best['poolMeta']})" if best.get("poolMeta") else "")
              + f", holds ${liq:,.0f} of liquidity" + (f" and traded ${best['volumeUsd1d']:,.0f} in the last day." if best.get("volumeUsd1d") else ".") + note + " Source: DefiLlama; this is pool TVL, not order-book depth.")
    return ok(answer, 0.7, liquidity_usd=liq, pool=best["symbol"], pool_id=best["pool"], project=best["project"], chain=best["chain"], volume_24h_usd=best.get("volumeUsd1d"),
              matching_pools=len(pools), as_of=_now(), source="DefiLlama", **extra)
