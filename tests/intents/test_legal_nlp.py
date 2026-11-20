"""Legal / compliance and NLP intents, upstreams mocked (no network)."""
import time
from datetime import date

import httpx
import pytest
from fastapi.testclient import TestClient

from app.intents import contract, sanctions
from app.main import create_app

SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
ALT_URL = "https://www.treasury.gov/ofac/downloads/alt.csv"
UN_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
OFAC_HOST = "https://sanctionslistservice.ofac.treas.gov/api/publicationpreview/exports"
GLEIF = "https://api.gleif.org/api/v1/lei-records"
VIES = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{n}"
TICKERS = "https://www.sec.gov/files/company_tickers.json"
MYMEMORY = "https://api.mymemory.translated.net/get"

SDN = ('1,"ROSNEFT",-0- ,"RUSSIA-EO14024",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XBT 1AbCdEfGhIjKlMnOpQrStUvWxYz12345; Website rosneft.com"\n'
       '2,"PETROV, Ivan Sergeevich","individual","UKRAINE-EO13660",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 12 Mar 1974; nationality Russia"\n'
       '3,"ACME TRADING LLC",-0- ,"[IRAN] [SDGT]",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \n')
ALT = '1,10,"aka","ROSNEFT OIL COMPANY",-0- \n'
UN = """<?xml version="1.0" encoding="UTF-8"?><CONSOLIDATED_LIST><INDIVIDUALS><INDIVIDUAL><DATAID>6908</DATAID><FIRST_NAME>Mohamed</FIRST_NAME>
<SECOND_NAME>Ali</SECOND_NAME><UN_LIST_TYPE>Al-Qaida</UN_LIST_TYPE><REFERENCE_NUMBER>QDi.001</REFERENCE_NUMBER>
<INDIVIDUAL_ALIAS><ALIAS_NAME>Abu Test</ALIAS_NAME></INDIVIDUAL_ALIAS><INDIVIDUAL_DATE_OF_BIRTH><YEAR>1970</YEAR></INDIVIDUAL_DATE_OF_BIRTH>
</INDIVIDUAL></INDIVIDUALS><ENTITIES></ENTITIES></CONSOLIDATED_LIST>"""


@pytest.fixture
def client(settings, mock):
    with TestClient(create_app(settings)) as c:
        yield c


def lists_up(mock):
    mock.get(SDN_URL).respond(302, headers={"Location": f"{OFAC_HOST}/sdn.csv"})
    mock.get(ALT_URL).respond(302, headers={"Location": f"{OFAC_HOST}/alt.csv"})
    mock.get(f"{OFAC_HOST}/sdn.csv").respond(200, text=SDN)
    mock.get(f"{OFAC_HOST}/alt.csv").respond(200, text=ALT)
    mock.get(UN_URL).respond(200, text=UN)


# ---- sanctions ----------------------------------------------------------------------------------
def test_sanctions_exact_alias_and_follows_allowlisted_redirect(client, mock):
    lists_up(mock)
    j = client.get("/sanctions-screening", params={"name": "Rosneft Oil Company"}).json()
    assert j["matched"] is True and j["verdict"] == "match" and j["matches"][0]["list"] == "OFAC SDN" and j["matches"][0]["score"] >= 0.97
    assert "EU and UK lists were not checked" in j["answer"] and {s["list"] for s in j["lists_checked"]} == {"OFAC SDN", "UN Security Council"}


def test_sanctions_clear_name_and_context_parsing(client, mock):
    lists_up(mock)
    assert client.get("/sanctions-screening", params={"name": "Jane Doe Bakery"}).json()["matched"] is False
    j = client.get("/sanctions-screening", params={"query": "Screen 'Ivan Petrov, DOB 1974, Russia' against the OFAC SDN list"}).json()
    assert j["subject"] == "Ivan Petrov" and j["birth_year"] == "1974" and j["matched"] is True and j["verdict"] == "potential_match"
    wrong_year = client.get("/sanctions-screening", params={"name": "Ivan Petrov", "year_of_birth": "1990"}).json()
    assert wrong_year["highest_score"] < j["highest_score"]  # a contradicting birth year lowers the score


def test_sanctions_program_cleanup_wallet_and_un_list(client, mock):
    lists_up(mock)
    j = client.get("/sanctions-screening", params={"name": "Acme Trading LLC"}).json()
    assert j["matches"][0]["program"] == "IRAN, SDGT"
    w = client.get("/sanctions-screening", params={"name": "1AbCdEfGhIjKlMnOpQrStUvWxYz12345"}).json()
    assert w["matched"] is True and w["subject_type"] == "wallet" and w["matches"][0]["name"] == "ROSNEFT"
    assert client.get("/sanctions-screening", params={"name": "1ZzzzzzzzzzzzzzzzzzzzzzzzzZ99999"}).json()["matched"] is False  # unknown wallet: exact only
    un = client.get("/sanctions-screening", params={"name": "Ali Mohamed"}).json()
    assert un["matched"] is True and un["matches"][0]["list"] == "UN Security Council"


def test_sanctions_lists_down_is_never_clear(client, mock):
    mock.get(SDN_URL).respond(503), mock.get(ALT_URL).respond(503), mock.get(UN_URL).respond(503)
    j = client.get("/sanctions-screening", params={"name": "Anyone At All"}).json()
    assert j["matched"] is None and j["outcome"] == "unavailable" and "NOT screened" in j["answer"]


def test_sanctions_partial_list_lowers_confidence(client, mock):
    mock.get(SDN_URL).respond(302, headers={"Location": f"{OFAC_HOST}/sdn.csv"}), mock.get(f"{OFAC_HOST}/sdn.csv").respond(200, text=SDN)
    mock.get(ALT_URL).respond(503), mock.get(UN_URL).respond(503)
    j = client.get("/sanctions-screening", params={"name": "Jane Doe Bakery"}).json()
    assert j["matched"] is False and j["confidence"] < 0.7 and "could not be refreshed" in j["answer"]
    assert {s["list"]: s["status"] for s in j["lists_checked"]}["UN Security Council"] == "unavailable"


def test_redirect_to_unlisted_host_is_blocked(client, mock):
    mock.get(SDN_URL).respond(302, headers={"Location": "https://evil.example/sdn.csv"})
    mock.get(ALT_URL).respond(503), mock.get(UN_URL).respond(503)
    evil = mock.get("https://evil.example/sdn.csv").respond(200, text=SDN)
    j = client.get("/sanctions-screening", params={"name": "Rosneft"}).json()
    assert j["matched"] is None and not evil.called


def test_sanctions_no_subject(client):
    assert client.get("/sanctions-screening").json()["outcome"] == "no_subject"


# ---- corporate registry (GLEIF) ------------------------------------------------------------------
def gleif_rec(name="Acme Holdings Ltd", lei="5493001KJTIIGC8Y1R12", status="ACTIVE", cc="GB", reg="12345678"):
    return {"id": lei, "attributes": {"lei": lei, "entity": {
        "legalName": {"name": name}, "status": status, "registeredAs": reg, "jurisdiction": cc, "creationDate": "2001-02-03T00:00:00Z",
        "legalAddress": {"addressLines": ["1 High St"], "city": "London", "country": cc, "postalCode": "E1 1AA"},
        "registeredAt": {"id": "RA000585"}, "legalForm": {"id": "H0PO"}, "category": "GENERAL"},
        "registration": {"status": "ISSUED", "nextRenewalDate": "2027-01-01T00:00:00Z"}}}


def test_registry_exact_record(client, mock):
    mock.get(GLEIF).respond(200, json={"data": [gleif_rec()]})
    j = client.get("/corporate-registry", params={"company": "Acme Holdings Ltd", "jurisdiction": "United Kingdom"}).json()
    assert j["legal_name"] == "Acme Holdings Ltd" and j["active"] is True and j["registration_id"] == "12345678" and j["incorporated"] == "2001-02-03"
    assert j["jurisdiction"] == "GB" and "1 High St" in j["registered_address"] and j["not_available"] == ["directors", "beneficial_owners"] and j["confidence"] >= 0.9


def test_registry_closest_match_is_not_called_exact(client, mock):
    mock.get(GLEIF).respond(200, json={"data": [gleif_rec(name="Acme Energy Ltd")]})
    j = client.get("/corporate-registry", params={"company": "Acme Ltd"}).json()
    assert j["matched_by"] == "closest legal-name match" and "No entity is registered under exactly" in j["answer"] and j["confidence"] <= 0.5


def test_registry_inactive_not_found_and_down(client, mock):
    mock.get(GLEIF).respond(200, json={"data": [gleif_rec(status="INACTIVE")]})
    j = client.get("/corporate-registry", params={"company": "Acme Holdings Ltd"}).json()
    assert j["active"] is False and "inactive" in j["answer"]
    mock.get("https://api.gleif.org/api/v1/fuzzycompletions").respond(200, json={"data": []})
    assert client.get("/corporate-registry").json()["outcome"] == "no_company"


def test_registry_not_found_and_outage_differ(client, mock):
    mock.get(GLEIF).respond(200, json={"data": []})
    mock.get("https://api.gleif.org/api/v1/fuzzycompletions").respond(200, json={"data": []})
    j = client.get("/corporate-registry", params={"company": "Nonexistent Widgets"}).json()
    assert j["outcome"] == "not_found" and "not proof" in j["answer"]


def test_registry_outage_is_unavailable(client, mock):
    mock.get(GLEIF).respond(503)
    j = client.get("/corporate-registry", params={"company": "Acme"}).json()
    assert j["legal_name"] is None and j["outcome"] == "unavailable"


# ---- vendor verification ------------------------------------------------------------------------
def vies(mock, cc, n, valid=True, name="ACME GMBH", err=None):
    mock.get(VIES.format(cc=cc, n=n)).respond(200, json={"isValid": valid, "userError": err or ("VALID" if valid else "INVALID"), "name": name, "address": "---"})


def test_vendor_verified(client, mock):
    lists_up(mock), vies(mock, "DE", "123456789"), mock.get(GLEIF).respond(200, json={"data": [gleif_rec(name="Acme GmbH", cc="DE")]})
    j = client.get("/vendor-verify", params={"vendor": "Acme GmbH", "vat_number": "DE 123456789"}).json()
    assert j["verdict"] == "verified" and j["valid"] is True and j["registered_name"] == "ACME GMBH" and not j["flags"]
    assert "bank account ownership" in j["not_checked"]


def test_vendor_invalid_vat_or_sanctioned_fails(client, mock):
    lists_up(mock), vies(mock, "DE", "123456789", valid=False), mock.get(GLEIF).respond(200, json={"data": []})
    mock.get("https://api.gleif.org/api/v1/fuzzycompletions").respond(200, json={"data": []})
    j = client.get("/vendor-verify", params={"vendor": "Acme GmbH", "vat_number": "DE123456789"}).json()
    assert j["verdict"] == "failed" and j["valid"] is False
    s = client.get("/vendor-verify", params={"vendor": "Rosneft"}).json()
    assert s["verdict"] == "failed" and any("sanctions" in f for f in s["flags"])


def test_vendor_vies_outage_needs_review_never_verified(client, mock):
    lists_up(mock), mock.get(VIES.format(cc="DE", n="123456789")).respond(200, json={"isValid": False, "userError": "MS_UNAVAILABLE"})
    mock.get(GLEIF).respond(200, json={"data": [gleif_rec(name="Acme GmbH", cc="DE")]})
    j = client.get("/vendor-verify", params={"vendor": "Acme GmbH", "vat_number": "DE123456789"}).json()
    assert j["verdict"] == "needs_review" and j["valid"] is None


def test_vendor_no_input(client):
    assert client.get("/vendor-verify").json()["outcome"] == "no_vendor"


# ---- SEC filings --------------------------------------------------------------------------------
def submissions(forms):
    n = len(forms)
    return {"name": "Tesla, Inc.", "filings": {"files": [], "recent": {
        "accessionNumber": [f"0001628280-26-0000{i:02d}" for i in range(n)], "filingDate": [d for _, d, _ in forms], "form": [f for f, _, _ in forms],
        "acceptanceDateTime": [f"{d}T20:00:00.000Z" for _, d, _ in forms], "reportDate": ["2026-09-30"] * n, "primaryDocument": ["doc.htm"] * n,
        "primaryDocDescription": [""] * n, "items": [it for _, _, it in forms]}}}


def filings_up(mock, forms):
    mock.get(TICKERS).respond(200, json={"0": {"cik_str": 1318605, "ticker": "TSLA", "title": "Tesla, Inc."},
                                         "1": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."}})
    mock.get("https://data.sec.gov/submissions/CIK0001318605.json").respond(200, json=submissions(forms))


FORMS = [("10-Q", "2026-10-22", ""), ("8-K", "2026-10-10", "2.02,9.01"), ("10-Q", "2026-07-23", ""), ("10-K", "2026-01-29", ""), ("10-Q", "2025-10-23", "")]


def test_filings_by_name_form_and_period(client, mock):
    filings_up(mock, FORMS)
    j = client.get("/filing-monitor", params={"entity": "Tesla", "form": "10-Q", "period": "2026"}).json()
    assert j["filing_count"] == 2 and j["cik"] == "0001318605" and j["latest_filing"]["filing_date"] == "2026-10-22" and j["ticker"] == "TSLA"
    assert j["urls"][0].startswith("https://www.sec.gov/Archives/edgar/data/1318605/") and "filing text itself was not read" in j["answer"]


def test_filings_question_items_and_zero(client, mock):
    filings_up(mock, FORMS)
    j = client.get("/filing-monitor", params={"question": "Has Tesla filed an 8-K recently?"}).json()
    assert j["form"] == "8-K" and j["filing_count"] == 1 and j["latest_filing"]["items"][0] == {"item": "2.02", "meaning": "results of operations and financial condition"}
    z = client.get("/filing-monitor", params={"entity": "TSLA", "form": "S-1"}).json()
    assert z["filing_count"] == 0 and z["outcome"] == "ok"  # zero filings is an answer, an outage is not


def test_filings_unknown_entity_and_outage(client, mock):
    filings_up(mock, FORMS)
    assert client.get("/filing-monitor", params={"entity": "Zzyzx Nonexistent Corp"}).json()["outcome"] == "entity_not_found"
    mock.get("https://data.sec.gov/submissions/CIK0000320193.json").respond(503)
    j = client.get("/filing-monitor", params={"entity": "AAPL"}).json()
    assert j["filing_count"] is None and j["outcome"] == "unavailable"


def test_filings_sends_descriptive_user_agent_without_contact_details(client, mock):
    filings_up(mock, FORMS)
    client.get("/filing-monitor", params={"entity": "TSLA"})
    ua = [c.request.headers["user-agent"] for c in mock.calls if "sec.gov" in str(c.request.url)]
    assert ua and all("VulnRank" in u and "@" not in u for u in ua)


# ---- contract obligations ----------------------------------------------------------------------
CONTRACT = """1. Deliverables
1.1 The Supplier shall deliver the Phase 1 design documents by 2026-03-01.
1.2 The Supplier shall deliver the final build no later than 30 June 2027.
2. Payment
2.1 The Client shall pay the Supplier $25,000 within 30 days of delivery of Phase 1 on 2026-03-01.
2.2 The Client has paid the initial deposit of $5,000 which was paid in full on 2026-01-10 and shall remit the balance.
3. Confidentiality
3.1 Each party shall not disclose Confidential Information.
3.2 The Supplier will provide support during the warranty period."""


def test_contract_extracts_dates_amounts_and_status():
    r = contract.run({"contract": CONTRACT}, today=date(2026, 11, 20))
    ob = {o["clause"]: o for o in r["obligations"]}
    assert ob["1.1"]["type"] == "deliverable" and ob["1.1"]["status"] == "past_due_date" and ob["1.1"]["due_date"] == "2026-03-01"
    assert ob["1.2"]["status"] == "upcoming" and ob["1.2"]["due_date"] == "2027-06-30" and ob["1.2"]["days_remaining"] == 222
    assert ob["2.1"]["type"] == "payment" and ob["2.1"]["amount"] == "$25,000" and ob["2.1"]["due_date"] == "2026-03-31"
    assert ob["2.2"]["status"] == "completed_per_text" and ob["3.1"]["type"] == "restriction" and ob["3.2"]["status"] == "undated"
    assert r["verdict"] == "past_due_dates_found" and "no evidence these were completed" in r["answer"] and r["clauses"][:2] == ["1.1", "1.2"]


def test_contract_net_terms_empty_and_no_modal():
    r = contract.run({"contract": "Invoices are payable net 45 from the invoice date. The parties meet annually."}, today=date(2026, 1, 1))
    assert r["obligations"][0]["type"] == "payment" and r["obligations"][0]["due_basis"] == "net 45 days from invoice"
    assert contract.run({"contract": "Hello"})["outcome"] == "no_contract"
    assert contract.run({"contract": "This agreement is made between two parties for a purpose."})["verdict"] == "no_obligations_found"


def test_contract_endpoint_get_and_post(client):
    assert client.get("/contract-audit", params={"contract": CONTRACT, "as_of": "2026-11-20"}).json()["obligation_count"] >= 6
    j = client.post("/contract-audit", json={"contract": CONTRACT}).json()
    assert j["verdict"] in ("past_due_dates_found", "obligations_found") and j["outcome"] == "ok"
    assert client.post("/contract-audit", json={}).json()["outcome"] == "no_contract"


# ---- sentiment ----------------------------------------------------------------------------------
def test_sentiment_labels_and_extraction(client):
    j = client.get("/sentiment", params={"question": "What's the sentiment of this review: 'The product broke after one day, terrible quality.'?"}).json()
    assert j["sentiment"] == "negative" and j["score"] < -0.5 and any(c["word"] == "terrible" for c in j["cues"]) and j["confidence"] > 0.8
    assert client.get("/sentiment", params={"text": "I absolutely love this, best purchase ever!"}).json()["sentiment"] == "positive"
    assert client.get("/sentiment", params={"text": "The meeting is at three."}).json()["sentiment"] == "neutral"
    assert client.get("/sentiment", params={"text": "Great screen but the battery is awful and terrible"}).json()["sentiment"] in ("mixed", "negative")


def test_sentiment_non_english_low_confidence_and_empty(client):
    j = client.get("/sentiment", params={"text": "Das Produkt ist wirklich sehr schlecht und teuer"}).json()
    assert j["confidence"] <= 0.4 and j["language_note"]
    e = client.get("/sentiment").json()
    assert e["sentiment"] is None and e["outcome"] == "no_text"


# ---- translation --------------------------------------------------------------------------------
def test_translate_question_and_params(client, mock):
    mock.get(MYMEMORY).respond(200, json={"responseStatus": 200, "responseData": {"translatedText": "Où est la gare la plus proche ?", "match": 0.99}})
    j = client.get("/translate", params={"question": "Translate this sentence into French: 'Where is the nearest train station?'"}).json()
    assert j["translation"] == "Où est la gare la plus proche ?" and j["target_language"] == "fr" and j["answer"] == j["translation"] and j["confidence"] >= 0.9
    q = [c.request.url.params for c in mock.calls][0]
    assert q["q"] == "Where is the nearest train station?" and q["langpair"] == "Autodetect|fr"
    j2 = client.get("/translate", params={"text": "Hallo", "target_language": "English", "source_language": "German"}).json()
    assert j2["target_language"] == "en" and j2["source_language"] == "de"


def test_translate_failures(client, mock):
    mock.get(MYMEMORY).respond(200, json={"responseStatus": 429, "quotaFinished": True, "responseData": {"translatedText": "MYMEMORY WARNING: YOU USED ALL AVAILABLE FREE TRANSLATIONS"}})
    j = client.get("/translate", params={"text": "Hello", "target_language": "fr"}).json()
    assert j["translation"] is None and j["outcome"] == "unavailable"
    assert client.get("/translate", params={"text": "Hello", "target_language": "Klingonese"}).json()["outcome"] == "no_target_language"
    assert client.get("/translate", params={"target_language": "fr"}).json()["outcome"] == "no_text"
    assert client.get("/translate", params={"text": "x" * 2000, "target_language": "fr"}).json()["outcome"] == "text_too_long"
    same = client.get("/translate", params={"text": "Hello", "source_language": "en", "target_language": "English"}).json()
    assert same["translation"] == "Hello"


def test_new_hosts_allow_listed_but_others_blocked():
    from app.sources.base import ALLOWED_HOSTS
    assert {"api.gleif.org", "data.sec.gov", "ec.europa.eu", "api.mymemory.translated.net", "scsanctions.un.org"} <= ALLOWED_HOSTS
    assert "evil.example" not in ALLOWED_HOSTS
