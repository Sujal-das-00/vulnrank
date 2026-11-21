"""The seventeen intents added on 2026-11-21 (language, blockchain, legal and compliance). Upstreams mocked, no network."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.intents import compliance, nlp, solidity
from app.main import EXTRA_ROUTES, create_app

ETH_RPCS = ["https://ethereum-rpc.publicnode.com", "https://1rpc.io/eth"]
ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
LLAMA_TVL = "https://api.llama.fi/tvl/{}"
LLAMA_CHAINS = "https://api.llama.fi/v2/chains"
LLAMA_POOLS = "https://yields.llama.fi/pools"
GOOGLE, CLOUDFLARE = "https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"


@pytest.fixture
def client(settings, mock):
    with TestClient(create_app(settings)) as c:
        yield c


def ask(client, route, **p):
    r = client.get(route, params=p)
    assert r.status_code == 200
    return r.json()


# ---- every route answers 200 with its graded field present, even with no input ------------------------------------------
@pytest.mark.parametrize("route,intent", EXTRA_ROUTES)
def test_every_route_is_a_soft_200_without_input(client, route, intent):
    j = ask(client, route)
    assert j["outcome"] != "ok" and j["answer"] and j["confidence"] == 0.0


def test_post_body_is_accepted_for_long_text(client):
    r = client.post("/text-summarization", json={"text": ("The council met on Tuesday to vote. " * 3 + "The budget passed after a long debate. " * 3 + "Roads will be built in spring. ") * 2})
    assert r.status_code == 200 and r.json()["outcome"] == "ok" and r.json()["summary"]


# ---- AI / language ------------------------------------------------------------------------------------------------------
def test_classification_picks_supported_label_and_refuses_to_guess():
    j = nlp.text_classification({"text": "I can't log into my account, my password is wrong", "categories": "billing, technical, account"})
    assert j["category"] == "account" and j["confidence"] > 0.5 and "password" in j["reason"]
    j = nlp.text_classification({"question": "Classify this ticket as billing, technical, or account issue: 'I was charged twice for my subscription.'"})
    assert j["category"] == "billing"
    j = nlp.text_classification({"text": "The weather is lovely", "categories": "billing, technical"})
    assert j["category"] is None and j["outcome"] == "no_signal"


def test_keywords_are_strings_best_first():
    j = nlp.keyword_extraction({"text": "Machine learning models need large datasets. Deep learning, a subset of machine learning, trains neural networks on GPUs. Neural networks learn representations."})
    assert all(isinstance(k, str) for k in j["keywords"]) and "machine learning" in j["keywords"] and j["keyword_count"] == len(j["keywords"])
    assert nlp.keyword_extraction({"text": "the and of"})["keywords"] == []


def test_similarity_orders_pairs_sensibly():
    near = nlp.semantic_similarity({"text_a": "The cat sat on the mat", "text_b": "A cat was sitting on the mat"})["similarity"]
    far = nlp.semantic_similarity({"text_a": "I want to buy a car", "text_b": "Stock markets fell sharply today"})["similarity"]
    assert near > 0.3 > far == 0.0
    assert nlp.semantic_similarity({"question": '"I like apples" vs "I like apples"'})["similarity"] == 1.0
    assert nlp.semantic_similarity({"text_a": "only one"})["similarity"] is None


def test_entities_have_offsets_and_split_person_from_organisation():
    t = "Dr. Jane Smith of Acme Corp emailed bob@acme.com on March 12, 2026 about $1,200 in London. See https://acme.com and CVE-2021-44228."
    j = nlp.entity_extraction({"text": t})
    got = {(e["type"], e["text"]) for e in j["entities"]}
    assert {("PERSON", "Jane Smith"), ("ORGANIZATION", "Acme Corp"), ("EMAIL", "bob@acme.com"), ("DATE", "March 12, 2026"), ("MONEY", "$1,200"),
            ("LOCATION", "London"), ("URL", "https://acme.com"), ("CVE", "CVE-2021-44228")} <= got
    assert all(t[e["start"]:e["end"]] == e["text"] for e in j["entities"])
    assert ("ORGANIZATION", "Bank of America") in {(e["type"], e["text"]) for e in nlp.extract_entities("She works at Bank of America.")}


def test_summary_is_extractive_and_in_order():
    text = ("The city council voted on Tuesday to approve a new budget. The budget includes funding for roads, schools and parks. Residents spoke for three hours. "
            "Some opposed higher taxes. Others praised new school funding. The mayor said the budget balances growth and fairness. Construction begins in spring.")
    j = nlp.text_summarization({"text": text})
    assert j["outcome"] == "ok" and 1 < len(j["summary_sentences"]) <= 4 and all(s in text for s in j["summary_sentences"])
    assert [text.index(s) for s in j["summary_sentences"]] == sorted(text.index(s) for s in j["summary_sentences"])
    assert nlp.text_summarization({"text": text, "sentences": "1"})["summary_sentences"].__len__() == 1


def test_llm_output_evaluation_flags_structural_problems():
    good = nlp.llm_output_evaluation({"task": "Explain photosynthesis in under 30 words", "output": "Photosynthesis is how plants convert sunlight, water and carbon dioxide into glucose and oxygen."})
    bad = nlp.llm_output_evaluation({"task": "Return JSON with name and age", "output": "As an AI language model I cannot do that [insert name]"})
    assert good["rating"] in ("good", "excellent") and not good["errors"]
    assert bad["rating"] == "poor" and len(bad["errors"]) == 3
    assert nlp.llm_output_evaluation({"task": "x", "output": ""})["rating"] is None


def test_ai_detection_needs_text_and_is_capped():
    ai = ("In today's rapidly evolving digital landscape, it is important to note that artificial intelligence plays a crucial role. Furthermore, organizations must leverage "
          "comprehensive strategies to navigate the multifaceted challenges. Moreover, a holistic approach underscores the testament to innovation. In conclusion, stakeholders should foster collaboration.")
    hum = ("honestly i wasnt sure about the movie at first lol. my friend dragged me there and we got there late, missed the first ten minutes! but wow, I ended up loving it. "
           "we're gonna see it again this weekend, can't wait.") * 2
    assert nlp.ai_text_detection({"text": ai})["verdict"] == "likely_ai"
    assert nlp.ai_text_detection({"text": hum})["verdict"] == "likely_human"
    short = nlp.ai_text_detection({"text": "Too short to tell."})
    assert short["verdict"] is None and short["outcome"] == "text_too_short"
    assert nlp.ai_text_detection({"text": ai})["confidence"] <= 0.6


# ---- blockchain -------------------------------------------------------------------------------------------------------------
def eth_rpc(mock, *, balances=(10**18, 10**18), supply=(10**12, 10**12), fail=()):
    def make(i, url):
        def handler(request):
            if url in fail:
                return httpx.Response(500)
            body = json.loads(request.content)
            m, p = body["method"], body["params"]
            if m == "eth_getBalance":
                res = hex(balances[i])
            elif m == "eth_call":
                d = p[0]["data"]
                res = hex(supply[i]) if d.startswith("0x18160ddd") else hex(6) if d.startswith("0x313ce567") else hex(5 * 10**6) if d.startswith("0x70a08231") else \
                    "0x" + "20".rjust(64, "0") + "3".rjust(64, "0") + "555344".ljust(64, "0")  # symbol() -> "USD"
            else:
                res = "0x1"
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": res})
        return handler
    for i, u in enumerate(ETH_RPCS):
        mock.post(u).mock(side_effect=make(i, u))


def test_wallet_native_balance_two_sources_agree(client, mock):
    eth_rpc(mock)
    j = ask(client, "/wallet-balance", address=ADDR, chain="ethereum")
    assert j["balance"] == 1.0 and j["token_symbol"] == "ETH" and j["confidence"] >= 0.9 and j["sources_agreeing"] == 2


def test_wallet_token_balance_uses_decimals(client, mock):
    eth_rpc(mock)
    j = ask(client, "/wallet-balance", address=ADDR, token="USDC")
    assert j["balance"] == 5.0 and j["token_symbol"] == "USD" and j["token_address"] == USDC


def test_wallet_disagreement_outage_and_unsupported_inputs(client, mock):
    eth_rpc(mock, balances=(10**18, 3 * 10**18))
    j = ask(client, "/wallet-balance", address=ADDR)
    assert j["balance"] is None and j["outcome"] == "conflicting"
    mock.reset()
    eth_rpc(mock, fail=tuple(ETH_RPCS))
    assert ask(client, "/wallet-balance", address=ADDR)["outcome"] == "unavailable"
    mock.reset()
    eth_rpc(mock, fail=(ETH_RPCS[0],))
    j = ask(client, "/wallet-balance", address=ADDR)
    assert j["balance"] == 1.0 and j["confidence"] < 0.9                      # one operator: answer stands, confidence drops
    assert ask(client, "/wallet-balance", question="What is the balance of vitalik.eth?")["outcome"] == "ens_not_supported"
    assert ask(client, "/wallet-balance", address=ADDR, chain="solana")["outcome"] == "chain_not_supported"
    assert ask(client, "/wallet-balance", address=ADDR, token="SHIB")["outcome"] == "token_not_supported"


def test_token_supply(client, mock):
    eth_rpc(mock)
    j = ask(client, "/token-supply", token="USDC")
    assert j["total_supply"] == 10**12 / 10**6 and j["token_address"] == USDC and j["sources_agreeing"] == 2
    j = ask(client, "/token-supply", question="What is the total supply of DAI?")
    assert j["total_supply"] is not None
    assert ask(client, "/token-supply", token="NOPE")["outcome"] == "token_not_identified"
    mock.reset()
    eth_rpc(mock, supply=(10**12, 2 * 10**12))
    assert ask(client, "/token-supply", token="USDC")["outcome"] == "conflicting"


POOLS = {"status": "success", "data": [
    {"chain": "Ethereum", "project": "aave-v3", "symbol": "USDC", "tvlUsd": 1_000_000_000, "apy": 2.4, "apyBase": 2.4, "apyReward": None, "pool": "aaaaaaaa-0000-0000-0000-000000000001", "poolMeta": None},
    {"chain": "Ethereum", "project": "aave-v3", "symbol": "USDC", "tvlUsd": 50_000_000, "apy": 4.3, "apyBase": 2.4, "apyReward": 1.9, "pool": "aaaaaaaa-0000-0000-0000-000000000002", "poolMeta": "Umbrella"},
    {"chain": "Base", "project": "uniswap-v3", "symbol": "WETH-USDC", "tvlUsd": 80_000_000, "apy": 9.0, "apyBase": 9.0, "pool": "bbbbbbbb-0000-0000-0000-000000000001", "poolMeta": "0.3%",
     "volumeUsd1d": 1.8e8, "underlyingTokens": ["0x4200000000000000000000000000000000000006", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]},
    {"chain": "Base", "project": "uniswap-v3", "symbol": "WETH-USDC", "tvlUsd": 10_000_000, "apy": 5.0, "pool": "bbbbbbbb-0000-0000-0000-000000000002", "poolMeta": "0.05%",
     "underlyingTokens": ["0x4200000000000000000000000000000000000006", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]},
    {"chain": "Base", "project": "tiny", "symbol": "X-Y", "tvlUsd": 100, "apy": 1.0, "pool": "cccccccc-0000-0000-0000-000000000001"}]}


def llama(mock):
    mock.get(LLAMA_TVL.format("aave")).respond(200, json=16_304_595_035.5)
    mock.get(LLAMA_TVL.format("nonexistentxyz")).respond(400, text="Protocol not found")
    mock.get(LLAMA_CHAINS).respond(200, json=[{"name": "Base", "tvl": 4.6e9}, {"name": "Ethereum", "tvl": 7e10}])
    mock.get(LLAMA_POOLS).respond(200, json=POOLS)


def test_tvl_protocol_chain_token_and_not_found(client, mock):
    llama(mock)
    j = ask(client, "/tvl", protocol="aave")
    assert j["tvl_usd"] == 16304595035.5 and j["protocol_or_chain"] == "aave"
    j = ask(client, "/tvl", protocol="Base")
    assert j["tvl_usd"] == 4.6e9 and j["chain_tvl_usd"] == 4.6e9
    j = ask(client, "/tvl", question="How deep is the liquidity of token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 on base?")
    assert j["tvl_usd"] == 90_000_000 and j["pool_count"] == 2
    j = ask(client, "/tvl", protocol="nonexistentxyz")
    assert j["tvl_usd"] is None and j["outcome"] == "not_found"
    assert ask(client, "/tvl", protocol="aave", chain="ethereum")["chain_tvl_usd"] == 7e10


def test_a_400_for_an_unknown_protocol_does_not_open_the_circuit(client, mock):
    llama(mock)
    for _ in range(8):
        ask(client, "/tvl", protocol="nonexistentxyz")
    assert ask(client, "/tvl", protocol="aave")["outcome"] == "ok"


def test_defillama_outage_is_unavailable_not_zero(client, mock):
    mock.get(LLAMA_TVL.format("aave")).respond(503)
    mock.get(LLAMA_CHAINS).respond(503)
    mock.get(LLAMA_POOLS).respond(503)
    for route, p in [("/tvl", {"protocol": "aave"}), ("/yield-rate", {"project": "aave-v3", "symbol": "USDC"}), ("/liquidity-depth", {"pool": "WETH/USDC"})]:
        j = ask(client, route, **p)
        assert j["outcome"] == "unavailable" and j["confidence"] == 0.0


def test_yield_picks_largest_matching_pool(client, mock):
    llama(mock)
    j = ask(client, "/yield-rate", project="aave-v3", symbol="USDC", chain="ethereum")
    assert j["supply_apy"] == 2.4 and j["tvl_usd"] == 1_000_000_000 and j["matching_pools"] == 2
    j = ask(client, "/yield-rate", question="What is the aave USDC yield on ethereum?")
    assert j["supply_apy"] == 2.4
    assert ask(client, "/yield-rate", project="nothing", symbol="ZZZ")["outcome"] == "not_found"


def test_liquidity_depth_with_slippage(client, mock):
    llama(mock)
    j = ask(client, "/liquidity-depth", pool="WETH/USDC", chain="base", question="slippage on a $50,000 swap?")
    assert j["liquidity_usd"] == 80_000_000 and j["project"] == "uniswap-v3" and abs(j["estimated_slippage_pct"] - 0.125) < 0.01
    j = ask(client, "/liquidity-depth", pool="USDC/ETH", chain="base")
    assert j["liquidity_usd"] == 80_000_000 and "estimated_slippage_pct" not in j
    assert ask(client, "/liquidity-depth", pool="FOO/BAR", chain="base")["outcome"] == "not_found"
    assert ask(client, "/liquidity-depth", pool="bbbbbbbb-0000-0000-0000-000000000002")["liquidity_usd"] == 10_000_000


VAULT = '''pragma solidity ^0.7.0;
contract Vault {
  mapping(address=>uint) public balances;
  function deposit() public payable { balances[msg.sender] += msg.value; }
  function withdraw(uint amt) public {
    require(balances[msg.sender] >= amt);
    (bool ok,) = msg.sender.call{value: amt}("");
    balances[msg.sender] -= amt;
  }
  function kill() public { selfdestruct(payable(msg.sender)); }
  function auth() public { require(tx.origin == owner); }
}'''
SAFE = '''// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Vault is ReentrancyGuard, Ownable {
  mapping(address=>uint) public balances;
  function withdraw(uint amt) external nonReentrant {
    balances[msg.sender] -= amt;
    (bool ok,) = msg.sender.call{value: amt}("");
    require(ok);
  }
  function setFee(uint f) external onlyOwner { fee = f; }
}'''


def test_solidity_audit_finds_the_classic_bugs_and_keeps_line_numbers():
    j = solidity.smart_contract_audit({"contract": VAULT})
    ids = {(f["id"], f["line"]) for f in j["findings"]}
    assert j["verdict"] == "critical_issues_found" and {("SWC-107", 7), ("SWC-106", 10), ("SWC-115", 11), ("SWC-105", 10), ("SWC-103", 1), ("SWC-101", 1)} <= ids
    assert j["findings"][0]["severity"] == "high" and all(f["recommendation"] for f in j["findings"])


def test_solidity_audit_clean_source_is_never_called_secure():
    j = solidity.smart_contract_audit({"contract": SAFE})
    assert j["verdict"] == "no_issues_detected" and j["finding_count"] == 0 and "not a proof" in j["answer"]
    commented = "pragma solidity 0.8.24;\ncontract A { // selfdestruct(x); tx.origin\n function f() external {} }"
    assert solidity.smart_contract_audit({"contract": commented})["finding_count"] == 0       # comments are ignored


def test_solidity_audit_rejects_non_source():
    assert solidity.smart_contract_audit({"contract": ADDR})["outcome"] == "source_required"
    assert solidity.smart_contract_audit({"contract": "0x" + "60" * 200})["outcome"] == "source_required"
    assert solidity.smart_contract_audit({"contract": "just some prose about contracts"})["outcome"] == "not_solidity"


# ---- legal and compliance -----------------------------------------------------------------------------------------------------
def test_moderation_levels():
    assert compliance.content_moderation({"text": "I will kill you tomorrow"})["verdict"] == "unsafe"
    j = compliance.content_moderation({"text": "You're an idiot. Email me at a@b.com, card 4111 1111 1111 1111"})
    assert j["verdict"] == "review" and {"harassment", "personal_data"} <= set(j["categories"]) and j["flagged"] is True
    assert any("payment card number" in d["matches"] and "phone number" not in d["matches"] for d in j["details"])
    j = compliance.content_moderation({"text": "Thanks for the helpful review!"})
    assert j["verdict"] == "safe" and j["flagged"] is False
    assert compliance.content_moderation({"question": "Does this comment violate guidelines: 'You are stupid and worthless'?"})["verdict"] == "review"


def test_plagiarism_against_supplied_source_only():
    src = "Yesterday the quick brown fox jumps over the lazy dog near the river bank and then slept"
    j = compliance.plagiarism_detection({"text": "The quick brown fox jumps over the lazy dog near the river bank today", "source": src})
    assert j["verdict"] == "high_overlap" and j["plagiarized"] is True and j["similarity_pct"] > 80 and j["matched_passages"]
    j = compliance.plagiarism_detection({"text": "Completely different words about astronomy and distant galaxies forming slowly", "source": src})
    assert j["verdict"] == "no_overlap_found" and j["plagiarized"] is False
    j = compliance.plagiarism_detection({"text": "Some text here that is long enough to compare against nothing at all"})
    assert j["plagiarized"] is None and j["outcome"] == "no_reference"      # never claims originality without a source


def test_transaction_risk_scorecard():
    hi = compliance.transaction_risk({"transaction": "Score the chargeback risk of a $2,400 electronics purchase on a card that made 6 attempts in 10 minutes."})
    lo = compliance.transaction_risk({"transaction": "$40 grocery purchase, returning customer with 12 prior orders, 3DS passed"})
    crit = compliance.transaction_risk({"transaction": "$9,000 gift cards, 5 attempts in 5 minutes, 2 prior chargebacks, VPN, new account created today, CVV fail"})
    assert hi["risk_level"] == "high" and lo["risk_level"] == "low" and crit["risk_level"] == "critical"
    assert lo["risk_score"] < hi["risk_score"] < crit["risk_score"] and hi["signals"]
    j = compliance.transaction_risk({"transaction": "someone bought something"})
    assert j["risk_level"] is None and j["outcome"] == "insufficient_evidence"


def dns(mock, url, answers=None, status=0):
    mock.get(url, params={"type": "TXT"}).mock(side_effect=lambda req: httpx.Response(200, json={"Status": status, **({"Answer": answers(req.url.params["name"])} if answers else {})}))


def txt_records(**by_name):
    def f(name):
        return [{"name": name, "type": 16, "TTL": 300, "data": d} for d in by_name.get(name, [])]
    return f


def test_email_security_valid_setup_with_resolver_quoting_differences(client, mock):
    spf, dmarc = "v=spf1 include:_spf.example.net -all", "v=DMARC1; p=reject; rua=mailto:d@example.com"
    google = txt_records(**{"example.com": [f'"{spf}"'], "_dmarc.example.com": [f'"{dmarc}"']})       # Google quotes TXT data
    cloud = txt_records(**{"example.com": [spf], "_dmarc.example.com": [dmarc]})                       # Cloudflare does not
    dns(mock, GOOGLE, google), dns(mock, CLOUDFLARE, cloud)
    mock.get(GOOGLE, params={"type": "MX"}).respond(200, json={"Status": 0, "Answer": [{"name": "example.com", "type": 15, "TTL": 1, "data": "10 mx.example.com."}]})
    mock.get(CLOUDFLARE, params={"type": "MX"}).respond(200, json={"Status": 0, "Answer": [{"name": "example.com", "type": 15, "TTL": 1, "data": "10 mx.example.com."}]})
    j = ask(client, "/email-security", domain="example.com")
    assert j["lookup_ok"] is True and j["spf"]["valid"] and j["spf"]["policy"].startswith("fail") and j["spf"]["issues"] == []       # no false 'duplicate SPF'
    assert j["dmarc"]["policy"] == "reject" and j["grade"] == "A" and j["mx_present"] is True and ask(client, "/email-security", email="a@example.com")["domain"] == "example.com"


def test_email_security_weak_and_missing_records(client, mock):
    google = txt_records(**{"weak.test": ['"v=spf1 +all"'], "_dmarc.weak.test": ['"v=DMARC1; p=none"']})
    dns(mock, GOOGLE, google), dns(mock, CLOUDFLARE, google)
    for r in (GOOGLE, CLOUDFLARE):
        mock.get(r, params={"type": "MX"}).respond(200, json={"Status": 0})
    j = ask(client, "/email-security", domain="weak.test")
    assert j["lookup_ok"] is False and not j["spf"]["valid"] and j["dmarc"]["policy"] == "none" and j["grade"] in ("D", "E", "F")
    j = ask(client, "/email-security", domain="weak.test", record_type="DMARC")
    assert j["lookup_ok"] is True                                       # the requested record is valid even though it is weak
    dns(mock, GOOGLE, None, status=2), dns(mock, CLOUDFLARE, None, status=2)
    mock.get(GOOGLE, params={"type": "MX"}).respond(200, json={"Status": 2}), mock.get(CLOUDFLARE, params={"type": "MX"}).respond(200, json={"Status": 2})
    j = ask(client, "/email-security", domain="down.test")
    assert j["lookup_ok"] is None and j["outcome"] == "unavailable"       # SERVFAIL is not 'no record'


def test_dkim_revoked_key_is_not_counted(client, mock):
    def google(name):
        return [{"name": name, "type": 16, "TTL": 1, "data": '"v=DKIM1; p="'}] if name.endswith("_domainkey.rev.test") else (
            [{"name": name, "type": 16, "TTL": 1, "data": '"v=spf1 -all"'}] if name == "rev.test" else [])
    dns(mock, GOOGLE, google), dns(mock, CLOUDFLARE, google)
    for r in (GOOGLE, CLOUDFLARE):
        mock.get(r, params={"type": "MX"}).respond(200, json={"Status": 0})
    assert ask(client, "/email-security", domain="rev.test")["dkim"]["selectors_found"] == []


def test_new_hosts_are_allow_listed_and_arbitrary_hosts_are_not():
    from app.sources.base import ALLOWED_HOSTS
    assert {"api.llama.fi", "yields.llama.fi"} <= ALLOWED_HOSTS and "api.anthropic.com" not in ALLOWED_HOSTS and "evil.example" not in ALLOWED_HOSTS
