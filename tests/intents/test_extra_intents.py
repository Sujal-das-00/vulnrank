"""The five extra intents, with every upstream mocked (no network)."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app

CB = "https://api.coinbase.com/v2/prices/ETH-USD/spot"
KR = "https://api.kraken.com/0/public/Ticker"
GEO = "https://geocoding-api.open-meteo.com/v1/search"
FC = "https://api.open-meteo.com/v1/forecast"
GOOGLE, CLOUDFLARE = "https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"
BASE_RPCS = ["https://mainnet.base.org", "https://base-rpc.publicnode.com"]
H = "0x" + "ab" * 32


@pytest.fixture
def client(settings, mock):
    with TestClient(create_app(settings)) as c:
        yield c


def cb(mock, price="3000.00", status=200):
    mock.get(CB).respond(status, json={"data": {"amount": price, "base": "ETH", "currency": "USD"}})


def kr(mock, price="3001.50"):
    mock.get(KR).respond(200, json={"error": [], "result": {"XETHZUSD": {"c": [price, "0.1"]}}})


# ---- crypto -------------------------------------------------------------------------------------
def test_crypto_two_sources_agree(client, mock):
    cb(mock), kr(mock)
    j = client.get("/crypto-price", params={"symbol": "eth"}).json()
    assert j["price_usd"] == 3000.75 and j["symbol"] == "ETH" and j["outcome"] == "ok" and j["confidence"] >= 0.9
    assert {s["source"] for s in j["sources"]} == {"Coinbase", "Kraken"}


def test_crypto_name_in_question_and_single_source(client, mock):
    mock.get("https://api.coinbase.com/v2/prices/BTC-USD/spot").respond(200, json={"data": {"amount": "60000.10"}})
    mock.get(KR).respond(503)
    j = client.get("/crypto-price", params={"question": "What is the price of Bitcoin right now?"}).json()
    assert j["price_usd"] == 60000.1 and j["symbol"] == "BTC" and j["confidence"] < 0.9


def test_crypto_sources_disagree_gives_null(client, mock):
    cb(mock, "3000"), kr(mock, "3300")
    j = client.get("/crypto-price", params={"symbol": "ETH"}).json()
    assert j["price_usd"] is None and j["outcome"] == "conflicting"


def test_crypto_all_down_never_guesses(client, mock):
    mock.get(CB).respond(500), mock.get(KR).respond(500)
    j = client.get("/crypto-price", params={"symbol": "ETH"}).json()
    assert j["price_usd"] is None and j["outcome"] == "unavailable"


def test_crypto_no_asset(client):
    r = client.get("/crypto-price", params={"question": "how are markets"})
    assert r.status_code == 200 and r.json()["price_usd"] is None and r.json()["outcome"] == "no_asset_identified"


# ---- weather ------------------------------------------------------------------------------------
def geo_rows(*rows):
    return {"results": [dict(r) for r in rows]}


MIAMI_FL = {"name": "Miami", "admin1": "Florida", "country": "United States", "country_code": "US", "latitude": 25.77, "longitude": -80.19, "population": 442000}
MIAMI_OK = {"name": "Miami", "admin1": "Oklahoma", "country": "United States", "country_code": "US", "latitude": 36.87, "longitude": -94.88, "population": 13000}


def forecast(mock, t=21.46):
    mock.get(FC).respond(200, json={"current": {"time": "2026-11-20T13:15", "temperature_2m": t}})


def test_weather_place_with_state_qualifier(client, mock):
    mock.get(GEO).respond(200, json=geo_rows(MIAMI_FL, MIAMI_OK)), forecast(mock)
    j = client.get("/weather-temperature", params={"question": "What is the temperature in Miami, OK right now?"}).json()
    assert j["temperature_c"] == 21.5 and "Oklahoma" in j["place"] and j["latitude"] == 36.87


def test_weather_coordinates_skip_geocoder(client, mock):
    forecast(mock, -3.04)
    j = client.get("/weather-temperature", params={"location": "52.52,13.41"}).json()
    assert j["temperature_c"] == -3.0 and not mock.calls.call_count == 0 and not any("geocoding" in str(c.request.url) for c in mock.calls)


def test_weather_ambiguous_name_lowers_confidence(client, mock):
    mock.get(GEO).respond(200, json=geo_rows({**MIAMI_FL, "population": 100}, {**MIAMI_OK, "population": 90})), forecast(mock)
    j = client.get("/weather-temperature", params={"location": "Miami"}).json()
    assert j["temperature_c"] is not None and j["confidence"] < 0.7 and j["note"]


def test_weather_unknown_place_and_source_down(client, mock):
    mock.get(GEO).respond(200, json={})
    j = client.get("/weather-temperature", params={"location": "Atlantis"}).json()
    assert j["temperature_c"] is None and j["outcome"] == "location_not_resolved"
    mock.get(GEO).respond(200, json=geo_rows(MIAMI_FL)), mock.get(FC).respond(500)
    j = client.get("/weather-temperature", params={"location": "Miami"}).json()
    assert j["temperature_c"] is None and j["outcome"] == "unavailable"


def test_weather_no_location(client):
    assert client.get("/weather-temperature").json()["outcome"] == "no_location"


# ---- JSON-RPC (gas, tx) ----------------------------------------------------------------------------
def rpc_mock(mock, urls, *, gas=0x5F5E100, head=0x1000, tx=None, receipt="__default__", fail=()):
    """Configure the fake JSON-RPC operators for `urls`. Calling it again re-configures them (respx keeps the first route)."""
    from app.intents.chain import CHAINS
    cfg = getattr(mock, "_rpc_cfg", None)
    if cfg is None:
        cfg = mock._rpc_cfg = {}

        def handler(request: httpx.Request):
            c = cfg.get(str(request.url).rstrip("/"), {"tx": None, "gas": 0, "head": 0x1000, "receipt": None, "down": False})
            if c["down"]:
                return httpx.Response(500)
            m = json.loads(request.content)["method"]
            res = {"eth_gasPrice": hex(c["gas"]),
                   "eth_getBlockByNumber": {"number": hex(c["head"]), "timestamp": "0x6000", "baseFeePerGas": hex(c["gas"] // 2)},
                   "eth_blockNumber": hex(c["head"] + 10), "eth_getTransactionByHash": c["tx"],
                   "eth_getTransactionReceipt": c["receipt"]}.get(m)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": res})
        for chain in CHAINS.values():
            for u in chain["rpcs"]:
                mock.post(u).mock(side_effect=handler)
    for u in urls:
        cfg[u] = {"tx": tx, "gas": gas, "head": head, "receipt": receipt, "down": u in fail}


def test_gas_price_two_operators(client, mock):
    rpc_mock(mock, BASE_RPCS, gas=6_000_000)
    j = client.get("/gas-price", params={"chain": "base"}).json()
    assert j["gas_price_gwei"] == 0.006 and j["chain"] == "base" and j["sources_agreeing"] == 2 and j["confidence"] >= 0.9


def test_gas_price_one_operator_down_and_chain_in_question(client, mock):
    rpc_mock(mock, BASE_RPCS, gas=6_000_000, fail=(BASE_RPCS[0],))
    j = client.get("/gas-price", params={"question": "Base fees felt high yesterday, what are they now?"}).json()
    assert j["gas_price_gwei"] == 0.006 and j["sources_agreeing"] == 1 and j["confidence"] < 0.9


def test_gas_price_unsupported_or_missing_chain_and_all_down(client, mock):
    assert client.get("/gas-price", params={"chain": "solana"}).json()["gas_price_gwei"] is None
    assert client.get("/gas-price").json()["outcome"] == "chain_not_identified"
    rpc_mock(mock, BASE_RPCS, fail=tuple(BASE_RPCS))
    j = client.get("/gas-price", params={"chain": "base"}).json()
    assert j["gas_price_gwei"] is None and j["outcome"] == "unavailable"


MINED = {"hash": H, "from": "0x" + "1" * 40, "to": "0x" + "2" * 40, "value": hex(2 * 10**18), "blockNumber": hex(0x1000),
         "blockHash": "0x" + "cd" * 32, "input": "0xa9059cbb0000"}


def all_chain_rpcs():
    from app.intents.chain import CHAINS
    return [u for c in CHAINS.values() for u in c["rpcs"]]


def test_tx_confirmed_found_without_chain(client, mock):
    # every chain's RPCs answer "not found" except Base, so the chain is discovered by probing
    rpc_mock(mock, [u for u in all_chain_rpcs() if u not in BASE_RPCS], tx=None)
    rpc_mock(mock, BASE_RPCS, tx=MINED, receipt={"status": "0x1", "gasUsed": hex(21000), "effectiveGasPrice": hex(10**9)})
    j = client.get("/tx-lookup", params={"tx_hash": H}).json()
    assert j["status"] == "confirmed" and j["chain"] == "base" and j["value_eth"] == 2.0 and j["block_number"] == 0x1000
    assert j["from"] == MINED["from"] and j["to"] == MINED["to"] and j["confirmations"] == 11 and j["sources_agreeing"] == 2


def test_tx_reverted_transfers_nothing(client, mock):
    rpc_mock(mock, BASE_RPCS, tx=MINED, receipt={"status": "0x0", "gasUsed": hex(30000)})
    j = client.get("/tx-lookup", params={"tx_hash": H, "chain": "base"}).json()
    assert j["status"] == "reverted" and j["value_eth"] == 0.0 and j["receipt_status"] == 0


def test_tx_pending_and_not_found_and_unavailable(client, mock):
    rpc_mock(mock, BASE_RPCS, tx={**MINED, "blockNumber": None, "blockHash": None}, receipt=None)
    assert client.get("/tx-lookup", params={"tx_hash": H, "chain": "base"}).json()["status"] == "pending"
    rpc_mock(mock, BASE_RPCS, tx=None)
    assert client.get("/tx-lookup", params={"tx_hash": H, "chain": "base"}).json()["status"] == "not_found"
    rpc_mock(mock, BASE_RPCS, fail=tuple(BASE_RPCS))
    j = client.get("/tx-lookup", params={"tx_hash": H, "chain": "base"}).json()
    assert j["status"] is None and j["outcome"] == "unavailable"  # an outage is never "not found"


def test_tx_bad_input(client):
    j = client.get("/tx-lookup", params={"tx_hash": "0x1234"}).json()
    assert j["status"] is None and j["outcome"] == "no_tx_hash"


# ---- DNS ----------------------------------------------------------------------------------------
def dns(mock, url, status=0, answers=None):
    mock.get(url).respond(200, json={"Status": status, **({"Answer": answers} if answers else {})})


MX = [{"name": "example.com.", "type": 15, "TTL": 300, "data": "10 mail.example.com."}]


def test_dns_agreed_present_and_cname_ignored_for_a(client, mock):
    ans = [{"name": "www.example.com.", "type": 5, "TTL": 60, "data": "example.com."}, {"name": "example.com.", "type": 1, "TTL": 120, "data": "93.184.216.34"}]
    dns(mock, GOOGLE, answers=ans), dns(mock, CLOUDFLARE, answers=ans)
    j = client.get("/dns-lookup", params={"name": "www.example.com", "record_type": "a"}).json()
    assert j["has_record"] is True and j["records"] == ["93.184.216.34"] and j["ttl"] == 120 and j["confidence"] >= 0.9


def test_dns_absent_nxdomain_and_nodata(client, mock):
    dns(mock, GOOGLE, status=3), dns(mock, CLOUDFLARE, status=3)
    j = client.get("/dns-lookup", params={"name": "nope.example", "record_type": "A"}).json()
    assert j["has_record"] is False and j["nxdomain"] is True
    dns(mock, GOOGLE), dns(mock, CLOUDFLARE)
    j = client.get("/dns-lookup", params={"name": "example.com", "record_type": "MX"}).json()
    assert j["has_record"] is False and j["nxdomain"] is False


def test_dns_resolvers_disagree_or_fail(client, mock):
    dns(mock, GOOGLE, answers=MX), dns(mock, CLOUDFLARE)
    assert client.get("/dns-lookup", params={"name": "example.com", "record_type": "MX"}).json()["has_record"] is None
    dns(mock, GOOGLE, status=2), dns(mock, CLOUDFLARE, status=2)  # SERVFAIL says nothing about existence
    j = client.get("/dns-lookup", params={"name": "example.com", "record_type": "MX"}).json()
    assert j["has_record"] is None and j["outcome"] == "unavailable"
    dns(mock, GOOGLE, status=2), dns(mock, CLOUDFLARE, answers=MX)
    j = client.get("/dns-lookup", params={"name": "example.com", "record_type": "MX"}).json()
    assert j["has_record"] is True and j["confidence"] < 0.9


def test_dns_name_from_question_url_and_bad_input(client, mock):
    dns(mock, GOOGLE, answers=MX), dns(mock, CLOUDFLARE, answers=MX)
    j = client.get("/dns-lookup", params={"question": "Does https://Example.com/path have MX records?"}).json()
    assert j["name"] == "example.com" and j["record_type"] == "MX" and j["has_record"] is True
    assert client.get("/dns-lookup", params={"name": "not a domain!"}).json()["outcome"] == "no_name"
    assert client.get("/dns-lookup", params={"name": "example.com", "record_type": "BOGUS"}).json()["outcome"] == "unsupported_record_type"


def test_unlisted_hosts_remain_blocked():
    from app.sources.base import ALLOWED_HOSTS
    assert {"api.coinbase.com", "dns.google", "mainnet.base.org"} <= ALLOWED_HOSTS and "evil.example" not in ALLOWED_HOSTS
