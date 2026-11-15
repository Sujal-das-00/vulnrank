import datetime as dt

from app.review.evidence import Doc, extract_signals
from app.review.legal import attach_security_relevance, evaluate, infer_sector, load_rules, parse_jurisdictions, parse_sector
from app.review.findings import Finding

TODAY = dt.date(2026, 11, 16)
SHOP = [
    Doc("templates/index.html", "file", '<html lang="en"><script src="https://www.googletagmanager.com/gtag/js"></script><a href="/privacy">Privacy Policy</a> '
                                         'add to cart <a href="mailto:care@shop.com">care@shop.com</a></html>'),
    Doc("app/pay.py", "file", 'x = request.form["card_number"]\n'),
]


def statuses(res):
    return {c["id"]: c["status"] for c in res.checklist}


def test_rules_table_is_well_formed():
    cfg = load_rules()
    regimes, ids = cfg["regimes"], set()
    for r in cfg["rules"]:
        assert r["id"] not in ids and r["regime"] in regimes
        ids.add(r["id"])
        assert r["severity"] in {"critical", "high", "medium", "low"} and r["cite"] and r["fix"] and r["title"] and r["check"]
        assert r.get("present") or r.get("absent")
        assert set(r["jurisdictions"]) <= {"eu", "india", "us"} and set(r["sectors"]) <= {"saas", "ecommerce"}
    for g in regimes.values():
        assert g["url"].startswith("https://") and g["verification"] in {"checked", "knowledge"} and g["ceiling"]


def test_shop_eu_findings_and_passes():
    sig = extract_signals(SHOP)
    res = evaluate(sig, ["eu"], "ecommerce", today=TODAY)
    st = statuses(res)
    assert st["eu-privacy-notice"] == "passed"
    assert st["eu-cookie-consent"] == "not_detected"      # tracker but no consent tool
    assert st["eu-withdrawal-info"] == "not_detected"
    assert st["eu-withdrawal-function"] == "not_detected"  # in force since 2026-06-19
    assert st["eu-data-rights"] == "not_applicable"
    assert st["any-pci-raw-card"] == "not_detected"
    f = {x.id: x for x in res.findings}
    assert f["legal:eu-cookie-consent"].basis["law"].startswith("ePrivacy") and f["legal:eu-cookie-consent"].basis["url"].startswith("https://eur-lex")
    assert f["legal:eu-withdrawal-function"].confidence == "low"
    assert all(x.category == "compliance" for x in res.findings)


def test_jurisdiction_and_sector_scoping():
    sig = extract_signals(SHOP)
    eu = {c["id"] for c in evaluate(sig, ["eu"], "ecommerce", today=TODAY).checklist}
    assert "eu-privacy-notice" in eu and "in-privacy-notice" not in eu and "us-privacy-policy" not in eu
    saas = {c["id"] for c in evaluate(sig, ["eu", "india", "us"], "saas", today=TODAY).checklist}
    assert "eu-withdrawal-info" not in saas and "in-grievance-officer" not in saas


def test_dpdp_is_upcoming_not_failing():
    sig = extract_signals([Doc("index.html", "file", "<html lang=en><script src=//www.google-analytics.com/a.js></script></html>")])
    res = evaluate(sig, ["india"], "saas", today=TODAY)
    st = statuses(res)
    assert st["in-privacy-notice"] == "upcoming" and st["in-consent"] == "upcoming"
    up = next(f for f in res.findings if f.id == "legal:in-privacy-notice")
    assert up.severity == "info" and "upcoming" in up.tags and up.detail["applies_from"] == "2027-05-14"
    after = evaluate(sig, ["india"], "saas", today=dt.date(2027, 6, 1))
    assert statuses(after)["in-privacy-notice"] == "not_detected"


def test_backend_only_repo_gets_low_confidence_and_caveat():
    sig = extract_signals([Doc("app/main.py", "file", "def f(): pass\n")])
    assert not sig.has_web_ui
    res = evaluate(sig, ["eu"], "saas", today=TODAY)
    pn = next(c for c in res.checklist if c["id"] == "eu-privacy-notice")
    assert pn["status"] == "not_detected" and pn["confidence"] == "low" and "No web pages" in pn["caveat"]


def test_contact_consistency_heuristic():
    ok = extract_signals([Doc("a.html", "file", "x support@acme.com privacy@acme.com")])
    assert not ok.has("mixed_contacts")
    bad = extract_signals([Doc("a.html", "file", "x support@acme.com"), Doc("b.html", "file", "y acme.helper@gmail.com z founder@other.io")])
    assert bad.has("mixed_contacts")
    res = evaluate(bad, ["eu"], "saas", today=TODAY)
    assert statuses(res)["any-contact-consistency"] == "not_detected"
    ign = extract_signals([Doc("a.html", "file", "noreply@acme.com me@example.com logo@2x.png")])
    assert not ign.emails


def test_test_paths_do_not_count_as_evidence():
    sig = extract_signals([Doc("tests/test_x.py", "file", "privacy policy cookiebot unsubscribe request.form['cvv']")])
    assert not sig.has("privacy_policy") and not sig.has("cookie_consent") and not sig.has("raw_card_fields")


def test_sector_and_text_parsing():
    assert infer_sector(extract_signals(SHOP)) == "ecommerce"
    assert infer_sector(extract_signals([Doc("a.py", "file", "x")])) == "saas"
    assert parse_jurisdictions("launch in the EU and India, then California") == ["eu", "india", "us"]
    assert parse_jurisdictions("hello world") == []
    assert parse_sector("our online store") == "ecommerce" and parse_sector("a B2B SaaS app") == "saas" and parse_sector("???") is None


def test_security_findings_get_legal_relevance():
    a = Finding("dep:1", "security", "dependency", "t", "critical", "f", tags=["CISA-KEV"])
    b = Finding("code:1", "security", "code_pattern", "t", "low", "f")
    c = Finding("legal:x", "compliance", "legal_check", "t", "high", "f")
    attach_security_relevance([a, b, c], ["eu", "us"])
    assert "legal_relevance" in a.detail and any("GDPR Art. 32" in s for s in a.detail["legal_relevance"]) and any("KEV" in s for s in a.detail["legal_relevance"])
    assert "legal_relevance" not in b.detail and "legal_relevance" not in c.detail


def test_templates_in_docs_examples_tests_do_not_count_as_web_ui():
    sig = extract_signals([Doc("docs/_templates/page.html", "file", "<html lang=en></html>"), Doc("examples/app/index.html", "file", "<html></html>"),
                           Doc("tests/templates/x.html", "file", "<html></html>"), Doc("src/lib.py", "file", "x=1")])
    assert not sig.has_web_ui
    assert extract_signals([Doc("app/templates/index.html", "file", "<html lang=en></html>")]).has_web_ui
    assert extract_signals([Doc("https://shop.example/", "page", "<html></html>")]).has_web_ui
