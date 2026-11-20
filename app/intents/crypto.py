"""CRYPTO_PRICE_USD: current USD spot price, Coinbase corroborated by Kraken."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.clock import utc_iso
from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

COINBASE = "https://api.coinbase.com/v2/prices/{sym}-USD/spot"
KRAKEN = "https://api.kraken.com/0/public/Ticker"
MAX_SPREAD_PCT = 2.0

NAMES = {
    "bitcoin cash": "BCH", "usd coin": "USDC", "shiba inu": "SHIB", "bitcoin": "BTC", "ethereum": "ETH", "ether": "ETH",
    "solana": "SOL", "ripple": "XRP", "dogecoin": "DOGE", "cardano": "ADA", "litecoin": "LTC", "polkadot": "DOT",
    "chainlink": "LINK", "avalanche": "AVAX", "polygon": "POL", "matic": "POL", "tether": "USDT", "uniswap": "UNI",
    "stellar": "XLM", "cosmos": "ATOM", "tron": "TRX", "aptos": "APT", "arbitrum": "ARB", "optimism": "OP",
    "toncoin": "TON", "sui": "SUI", "pepe": "PEPE", "binance coin": "BNB", "filecoin": "FIL", "aave": "AAVE",
}
TICKERS = set(NAMES.values())
KRAKEN_ALIAS = {"BTC": "XBT", "DOGE": "XDG"}


def resolve_symbol(params: dict[str, Any]) -> str | None:
    explicit = first(params, "symbol", "asset", "coin", "ticker", "token", "currency", "pair")
    for text in (explicit, free_text(params)):
        if not text:
            continue
        low = text.lower()
        for name in sorted(NAMES, key=len, reverse=True):
            if re.search(rf"\b{re.escape(name)}\b", low):
                return NAMES[name]
        for tok in re.findall(r"[A-Za-z0-9]{2,10}", text):
            if tok.upper() in TICKERS:
                return tok.upper()
        if text is explicit:  # a bare ticker or pair such as "DOGE" or "BTC-USD"
            m = re.fullmatch(r"([A-Za-z0-9]{2,10})(?:[-/ ]?(?:USD|usd))?", text.strip())
            if m:
                return m.group(1).upper()
    return None


async def _coinbase(f: Fetcher, sym: str, timeout: float, deadline: float | None):
    url = COINBASE.format(sym=sym)
    try:
        status, js = await f.get_json(url, timeout=timeout, deadline=deadline)
        if status == 404:
            return None, "not_found", url
        return float(js["data"]["amount"]), "available", url
    except SourceError as e:
        return None, e.kind, url
    except (KeyError, TypeError, ValueError):
        return None, "malformed", url


async def _kraken(f: Fetcher, sym: str, timeout: float, deadline: float | None):
    pair = f"{KRAKEN_ALIAS.get(sym, sym)}USD"
    try:
        status, js = await f.get_json(KRAKEN, {"pair": pair}, timeout=timeout, deadline=deadline)
        if status == 404 or js.get("error"):
            return None, "not_found", f"{KRAKEN}?pair={pair}"
        price = float(next(iter(js["result"].values()))["c"][0])
        return price, "available", f"{KRAKEN}?pair={pair}"
    except SourceError as e:
        return None, e.kind, f"{KRAKEN}?pair={pair}"
    except (KeyError, TypeError, ValueError, StopIteration, AttributeError, IndexError):
        return None, "malformed", f"{KRAKEN}?pair={pair}"


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    sym = resolve_symbol(params)
    if not sym:
        return soft("no_asset_identified", "No cryptocurrency was identified in the request, so no price is given. "
                    "Supply symbol (for example BTC, ETH, SOL) or name the asset.", price_usd=None, symbol=None)
    (cb, cb_st, cb_url), (kr, kr_st, kr_url) = await asyncio.gather(
        _coinbase(f, sym, timeout, deadline), _kraken(f, sym, timeout, deadline))
    sources = [{"source": n, "price_usd": p, "status": s, "url": u}
               for n, p, s, u in (("Coinbase", cb, cb_st, cb_url), ("Kraken", kr, kr_st, kr_url))]
    live = [p for p in (cb, kr) if p is not None and p > 0]
    if not live:
        down = any(s not in ("available", "not_found") for s in (cb_st, kr_st))
        msg = (f"Price sources were unavailable for {sym}, so no price is given rather than a guess." if down
               else f"{sym} has no USD spot market on Coinbase or Kraken, so no price is given.")
        return soft("unavailable" if down else "not_found", msg, price_usd=None, symbol=sym, sources=sources)
    if len(live) == 2:
        spread = abs(live[0] - live[1]) / min(live) * 100
        if spread > MAX_SPREAD_PCT:
            return soft("conflicting", f"Coinbase (${cb:,.2f}) and Kraken (${kr:,.2f}) disagree by {spread:.1f}% for {sym}, "
                        "so no single price is given.", price_usd=None, symbol=sym, sources=sources, spread_pct=round(spread, 3))
        price, conf = (cb + kr) / 2, 0.95
        basis = f"mean of Coinbase (${cb:,.2f}) and Kraken (${kr:,.2f}); spread {spread:.2f}%"
        extra = {"spread_pct": round(spread, 3)}
    else:
        price, conf, extra = live[0], 0.7, {}
        who = "Coinbase" if cb is not None else "Kraken"
        basis = f"{who} only; the second source was unavailable"
    price = round(price, 8 if price < 1 else 4)
    answer = f"{sym} is trading at ${price:,.4f} USD ({basis})." if price < 1000 else f"{sym} is trading at ${price:,.2f} USD ({basis})."
    return ok(answer, conf, price_usd=price, price_usd_cents=int(round(price * 100)), symbol=sym, currency="USD",
              sources=sources, retrieved_at=utc_iso(), **extra)
