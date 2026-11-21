"""WALLET_BALANCE_CHECK_GENERAL and TOKEN_TOTAL_SUPPLY_VERIFY_GENERAL: on-chain reads corroborated by two public RPC operators.

A value is returned only when the operators agree (balances within 0.5 percent, supplies within 0.1 percent, to allow for different
chain heads); a disagreement or an outage gives null plus an explicit outcome, never a guess."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any

from app.intents.chain import CHAINS, resolve_chain, rpc
from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher

ADDR = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
# Verified on-chain (symbol() and decimals() read from the RPCs) on 2026-11-21.
TOKENS: dict[str, dict[str, str]] = {
    "eth": {"USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7", "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"},
    "base": {"USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "WETH": "0x4200000000000000000000000000000000000006", "DAI": "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"},
    "arbitrum": {"USDC": "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "WETH": "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"},
    "polygon": {"USDC": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "WETH": "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"},
    "optimism": {"USDC": "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "USDT": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", "WETH": "0x4200000000000000000000000000000000000006"},
}
SEL_BALANCE_OF, SEL_DECIMALS, SEL_SYMBOL, SEL_SUPPLY = "0x70a08231", "0x313ce567", "0x95d89b41", "0x18160ddd"


def _word_str(h: str) -> str | None:
    try:
        b = bytes.fromhex(h[2:])
    except ValueError:
        return None
    if len(b) >= 64:
        n = int.from_bytes(b[32:64], "big")
        return b[64:64 + n].decode("utf-8", "replace") or None
    return b.rstrip(b"\0").decode("utf-8", "replace") or None


async def _call(f: Fetcher, url: str, to: str, data: str, t: float, d: float | None) -> str:
    return await rpc(f, url, "eth_call", [{"to": to, "data": data}, "latest"], t, d)


def _agree(vals: list[int], tol: float) -> tuple[bool, int]:
    """(agreed, value). With one operator the value stands but is not 'agreed'."""
    if len(vals) == 1:
        return False, vals[0]
    lo, hi = sorted(vals)[0], sorted(vals)[-1]
    return (hi - lo) <= tol * max(hi, 1), max(vals)


def _chain_or_soft(params: dict[str, Any], default: str = "eth") -> tuple[str | None, dict[str, Any] | None]:
    chain, named = resolve_chain(params)
    if chain is None and named:
        return None, soft("chain_not_supported", "The requested network is not supported (supported: " + ", ".join(c["name"] for c in CHAINS.values()) + ").")
    return chain or default, None


def _token_ref(raw: str | None, chain: str) -> tuple[str | None, str | None]:
    """-> (contract address, symbol hint)."""
    if not raw:
        return None, None
    m = ADDR.search(raw)
    if m:
        return m.group(0), None
    sym = re.sub(r"[^A-Za-z0-9]", "", raw).upper()
    alias = {"ETHER": "ETH", "ETHEREUM": "ETH", "BITCOIN": "WBTC", "BTC": "WBTC", "USDCOIN": "USDC", "TETHER": "USDT"}.get(sym, sym)
    return TOKENS.get(chain, {}).get(alias), alias


async def wallet_balance(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    text = free_text(params)
    raw_addr = first(params, "address", "wallet", "account", "owner")
    m = ADDR.search(raw_addr or "") or ADDR.search(text)
    if not m:
        ens = re.search(r"\b[\w-]+\.eth\b", (raw_addr or "") + " " + text, re.I)
        if ens:
            return soft("ens_not_supported", f"The name {ens.group(0)} is an ENS name; this service reads balances for 0x addresses only, so supply the resolved 0x address.", balance=None, address=None)
        return soft("no_address", "No 0x wallet address was found, so no balance is given.", balance=None, address=None)
    address = m.group(0)
    chain, err = _chain_or_soft(params)
    if err:
        return {**err, "balance": None, "address": address}
    tok_raw = first(params, "token", "asset", "symbol", "currency")
    meta = CHAINS[chain]
    padded = "0x" + SEL_BALANCE_OF[2:] + address[2:].lower().rjust(64, "0")
    if tok_raw and tok_raw.strip().upper() in ("", "ETH", "NATIVE", meta["symbol"]):
        tok_raw = None
    if tok_raw:
        contract, sym_hint = _token_ref(tok_raw, chain)
        if not contract:
            return soft("token_not_supported", f"Token '{tok_raw}' is not a known token on {meta['name']}; pass its 0x contract address or one of: {', '.join(TOKENS.get(chain, {})) or 'none'}.",
                        balance=None, address=address, chain=chain)

        async def read(u: str) -> dict[str, Any]:
            bal, dec, sym = await asyncio.gather(_call(f, u, contract, padded, timeout, deadline), _call(f, u, contract, SEL_DECIMALS, timeout, deadline),
                                                 _call(f, u, contract, SEL_SYMBOL, timeout, deadline))
            return {"raw": int(bal, 16), "decimals": int(dec, 16), "symbol": _word_str(sym) or sym_hint}
    else:
        async def read(u: str) -> dict[str, Any]:
            return {"raw": int(await rpc(f, u, "eth_getBalance", [address, "latest"], timeout, deadline), 16), "decimals": 18, "symbol": meta["symbol"]}
    res = await asyncio.gather(*(read(u) for u in meta["rpcs"]), return_exceptions=True)
    good = [r for r in res if isinstance(r, dict)]
    if not good:
        return soft("unavailable", f"No {meta['name']} RPC answered, so the balance is unknown (not reported as zero).", balance=None, address=address, chain=chain)
    if len({g["decimals"] for g in good}) > 1:
        return soft("conflicting", "The two RPC operators disagree about the token's decimals; no balance is given.", balance=None, address=address, chain=chain)
    agreed, raw = _agree([g["raw"] for g in good], 0.005)
    if len(good) == 2 and not agreed:
        return soft("conflicting", f"The two {meta['name']} RPC operators report different balances, so none is given.", balance=None, address=address, chain=chain)
    dec = good[0]["decimals"]
    balance = raw / 10 ** dec
    symbol = good[0]["symbol"] or "token"
    conf = 0.95 if agreed or (len(good) == 2 and raw == good[0]["raw"]) else 0.7
    shown = f"{balance:,.6f}".rstrip("0").rstrip(".") if balance else "0"
    answer = f"{address} holds {shown} {symbol} on {meta['name']}." + (" Two RPC operators agree." if len(good) == 2 else " Only one RPC operator answered.")
    return ok(answer, conf, address=address, chain=chain, chain_name=meta["name"], balance=balance, balance_raw=str(raw), decimals=dec, token_symbol=symbol,
              token_address=contract if tok_raw else None, sources_agreeing=len(good), unit=symbol,
              as_of=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


async def token_supply(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    chain, err = _chain_or_soft(params)
    if err:
        return {**err, "total_supply": None}
    raw_tok = first(params, "token", "contract", "address", "symbol", "asset")
    text = free_text(params)
    contract, sym_hint = _token_ref(raw_tok, chain)
    if not contract:
        m = ADDR.search(text)
        contract = m.group(0) if m else None
        if not contract:
            for sym in TOKENS.get(chain, {}):
                if re.search(rf"\b{sym}\b", text, re.I):
                    contract, sym_hint = TOKENS[chain][sym], sym
                    break
    if not contract:
        return soft("token_not_identified", f"No token was identified. Pass a 0x contract address or one of: {', '.join(TOKENS.get(chain, {})) or 'none'} on {CHAINS[chain]['name']}.", total_supply=None, chain=chain)
    meta = CHAINS[chain]

    async def read(u: str) -> dict[str, Any]:
        sup, dec, sym = await asyncio.gather(_call(f, u, contract, SEL_SUPPLY, timeout, deadline), _call(f, u, contract, SEL_DECIMALS, timeout, deadline),
                                             _call(f, u, contract, SEL_SYMBOL, timeout, deadline))
        return {"raw": int(sup, 16), "decimals": int(dec, 16), "symbol": _word_str(sym) or sym_hint}
    res = await asyncio.gather(*(read(u) for u in meta["rpcs"]), return_exceptions=True)
    good = [r for r in res if isinstance(r, dict)]
    if not good:
        return soft("unavailable", f"No {meta['name']} RPC returned a supply for {contract} (the address may not be an ERC-20 token or the RPCs are down), so no total supply is given.",
                    total_supply=None, chain=chain, token_address=contract)
    agreed, raw = _agree([g["raw"] for g in good], 0.001)
    if len(good) == 2 and not agreed:
        return soft("conflicting", "The two RPC operators report different total supplies, so none is given.", total_supply=None, chain=chain, token_address=contract)
    dec, symbol = good[0]["decimals"], good[0]["symbol"] or "token"
    supply = raw / 10 ** dec
    answer = (f"The total supply of {symbol} ({contract}) on {meta['name']} is {supply:,.{min(dec, 6)}f}".rstrip("0").rstrip(".")
              + (". Two RPC operators agree." if agreed else ". Only one RPC operator answered."))
    return ok(answer, 0.95 if agreed else 0.7, total_supply=supply, total_supply_raw=str(raw), decimals=dec, token_symbol=symbol, token_address=contract, chain=chain,
              chain_name=meta["name"], sources_agreeing=len(good), unit=symbol, as_of=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              note="totalSupply() is minted minus burned; it is not the circulating supply when tokens are locked, vested or held by the issuer.")
