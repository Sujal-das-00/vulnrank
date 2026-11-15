"""The Telegraph schema is a closed set: any unknown key is rejected at registration, so check it here."""
from pathlib import Path

import yaml

M = yaml.safe_load((Path(__file__).parents[2] / "telegraph" / "vulnrank.yaml").read_text())

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
    assert M["semantics"]["supported_intents"] == ["VULNERABILITY_TRIAGE_GENERAL", "SECURITY_REVIEW_GENERAL"]
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
