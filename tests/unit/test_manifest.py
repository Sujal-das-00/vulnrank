"""The Telegraph schema is a closed set: any unknown key is rejected at registration, so check it here."""
from pathlib import Path

import yaml

_DIR = Path(__file__).parents[2] / "telegraph"
# the manifest currently lives in vulnrank-fixed.yaml (vulnrank.yaml was removed from the working tree); accept either name
M = yaml.safe_load(next(p for p in (_DIR / "vulnrank-fixed.yaml", _DIR / "vulnrank.yaml") if p.exists()).read_text())

ROOT_KEYS = {"version", "kind", "id", "slug", "protocol", "name", "description", "base_url", "input_schema", "output_schema",
             "intent_mapping", "polling", "cache_ttl_sec", "rate_limit_per_sec", "circuit_threshold", "circuit_cooldown_seconds",
             "auth", "endpoints", "semantics", "docs", "limitations", "errors", "on_chain"}
ENDPOINT_KEYS = {"path", "external_path", "method", "description", "intents", "params", "endpoint_base_url", "content_type",
                 "multipart_fields", "param_map"}


def test_closed_set_keys():
    assert set(M) <= ROOT_KEYS
    assert {"version", "kind", "id", "slug", "name", "base_url"} <= set(M)
    for e in M["endpoints"]:
        assert set(e) <= ENDPOINT_KEYS and e["description"] and e["intents"]
    assert set(M["semantics"]["signal_mapping"]) <= {"confidence_field", "label_field", "reason_field"}


def test_intent_is_canonical_and_consistent():
    assert M["semantics"]["supported_intents"] == [
        "VULNERABILITY_TRIAGE_GENERAL", "SECURITY_REVIEW_GENERAL", "CRYPTO_PRICE_USD", "WEATHER_CHECK_TEMPERATURE",
        "GAS_PRICE_GENERAL", "ONCHAIN_TX_LOOKUP_GENERAL", "DNS_RECORD_LOOKUP_GENERAL",
        "SANCTIONS_SCREENING_MATCH_GENERAL", "CORPORATE_REGISTRY_LOOKUP_GENERAL", "VENDOR_VERIFY_GENERAL", "REGULATORY_FILING_MONITOR_GENERAL",
        "CONTRACT_OBLIGATION_AUDIT_GENERAL", "SENTIMENT_ANALYSIS_GENERAL", "LANGUAGE_TRANSLATION_GENERAL"]
    assert all(set(e["intents"]) <= set(M["semantics"]["supported_intents"]) for e in M["endpoints"])
    assert set(M["intent_mapping"]) == set(M["semantics"]["supported_intents"])
    paths = {e["path"]: e for e in M["endpoints"]}
    for intent, m in M["intent_mapping"].items():            # every mapping points at a declared endpoint that serves that intent
        assert m["endpoint"] in paths and intent in paths[m["endpoint"]]["intents"]
        declared = {p["name"] for where in paths[m["endpoint"]]["params"].values() for grp in where.values() for p in grp}
        assert set(m["input"]) <= declared


def test_security_review_mapping_matches_intent_contract():
    m = M["intent_mapping"]["SECURITY_REVIEW_GENERAL"]
    # every field of the intent's response format must be mapped, or the node reports it `missing`
    assert set(m["output"]) == {"verdict", "vulnerability_count", "issues", "summary"} and m["output"]["verdict"]["path"] == "verdict"
    assert m["output"]["issues"]["path"] == "issues[]"
    assert "required" not in M["input_schema"]          # two endpoints with different request shapes


def test_kebab_slug_and_scored_field():
    import re
    assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", M["slug"])
    assert "cvss_base_score" in M["output_schema"]["properties"]
    assert M["intent_mapping"]["VULNERABILITY_TRIAGE_GENERAL"]["output"]["cvss_base_score"]["path"] == "cvss_base_score"


def test_no_secrets():
    assert "auth" not in M and "key" not in str(M).lower().replace("keyless", "")


def test_extra_intent_mappings_point_at_real_response_fields():
    graded = {"CRYPTO_PRICE_USD": ("price_usd",), "WEATHER_CHECK_TEMPERATURE": ("temperature_c",), "GAS_PRICE_GENERAL": ("gas_price_gwei",),
              "ONCHAIN_TX_LOOKUP_GENERAL": ("status", "block_number", "value_eth"), "DNS_RECORD_LOOKUP_GENERAL": ("has_record",),
              "SANCTIONS_SCREENING_MATCH_GENERAL": ("matched", "match_count", "highest_score"),
              "CORPORATE_REGISTRY_LOOKUP_GENERAL": ("legal_name", "registration_id", "active", "registered_address", "incorporated"),
              "VENDOR_VERIFY_GENERAL": ("valid", "registered_name", "verdict"), "REGULATORY_FILING_MONITOR_GENERAL": ("entity", "filing_count"),
              "CONTRACT_OBLIGATION_AUDIT_GENERAL": ("verdict",), "SENTIMENT_ANALYSIS_GENERAL": ("sentiment", "score"),
              "LANGUAGE_TRANSLATION_GENERAL": ("translation", "target_language", "source_language")}
    for intent, fields in graded.items():
        out = M["intent_mapping"][intent]["output"]
        assert all(f in out and out[f]["path"] == f for f in fields), intent
        assert all(f in M["output_schema"]["properties"] for f in fields), intent
    assert len({m["endpoint"] for m in M["intent_mapping"].values()}) == len(M["intent_mapping"])  # one endpoint per intent
