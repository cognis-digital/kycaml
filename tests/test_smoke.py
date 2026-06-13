"""Tests for kycaml. No network — the local mock adapter is deterministic."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kycaml import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, TECHNIQUES, CATEGORIES, CAPABILITIES,
    list_techniques, get_technique, techniques_by_capability,
    PROVIDERS, list_providers, get_provider, providers_with_capability,
    get_adapter, LocalMockAdapter, NotConfigured, Orchestrator, recommend_providers,
)
from kycaml.cli import main  # noqa: E402


def test_metadata():
    assert TOOL_NAME == "kycaml"
    assert TOOL_VERSION.count(".") == 2


def test_taxonomy_integrity():
    assert len(TECHNIQUES) >= 15
    ids = [t.id for t in TECHNIQUES]
    assert len(ids) == len(set(ids))  # unique ids
    for t in TECHNIQUES:
        assert t.category in CATEGORIES
        assert t.red_flags and t.controls and t.capabilities
        for c in t.capabilities:
            assert c in CAPABILITIES  # capabilities are from the known set


def test_get_technique_and_filter():
    t = get_technique("ka-idf-001")  # case-insensitive
    assert t and t.name == "Synthetic identity"
    assert get_technique("nope") is None
    ml = list_techniques("ml_layering")
    assert ml and all(x.category == "ml_layering" for x in ml)


def test_provider_catalog():
    assert len(PROVIDERS) >= 15
    assert get_provider("chainalysis").segment == "crypto"
    assert get_provider("nope") is None
    sanc = providers_with_capability("sanctions_screening")
    assert any(p.key == "comply_advantage" for p in sanc)


def test_capability_cross_links():
    # every technique capability is offered by at least one provider
    for t in TECHNIQUES:
        for cap in t.capabilities:
            assert providers_with_capability(cap), f"no provider for {cap}"


def test_local_adapter_identity():
    a = get_adapter("local")
    clean = a.verify_identity({"document": "d", "selfie": "s"})
    assert clean.verified and clean.score >= 0.7 and not clean.flags
    synth = a.verify_identity({"document": "d", "selfie": "s", "synthetic_signals": True})
    assert not synth.verified and "KA-IDF-001" in synth.flags


def test_local_adapter_sanctions():
    a = get_adapter("local")
    hit = a.screen_sanctions({"name": "Ivan Petrov"})
    assert hit.hit and "KA-SAN-001" in hit.flags
    clean = a.screen_sanctions({"name": "Jane Q. Public"})
    assert not clean.hit


def test_local_adapter_monitoring():
    a = get_adapter("local")
    m = a.monitor_transaction({"amount": 9500, "reporting_threshold": 10000,
                               "count_24h": 12, "crypto_exposure": ["mixer"]})
    assert m.alert
    assert "structuring_near_threshold" in m.rules_fired
    assert "mixer_exposure" in m.rules_fired
    assert "KA-MLP-001" in m.flags and "KA-CRY-001" in m.flags


def test_real_stub_makes_no_calls():
    stub = get_adapter("jumio")            # no client configured
    try:
        stub.verify_identity({"document": "d"})
        assert False, "should have raised NotConfigured"
    except NotConfigured:
        pass


def test_orchestrator_clear():
    d = Orchestrator.local().assess(subject={"name": "Jane Public", "document": "d",
                                             "selfie": "s"})
    assert d.outcome == "clear" and d.risk_score < 0.4 and not d.techniques


def test_orchestrator_deny_on_sanctions():
    d = Orchestrator.local().assess(subject={"name": "Ivan Petrov", "document": "d",
                                             "selfie": "s"})
    assert d.outcome == "deny" and "KA-SAN-001" in d.techniques
    assert d.recommended_controls  # controls surfaced from the technique


def test_orchestrator_review_and_controls():
    d = Orchestrator.local().assess(
        subject={"name": "John Doe", "document": "d", "selfie": "s",
                 "synthetic_signals": True},
        txn={"amount": 9500, "reporting_threshold": 10000})
    assert d.outcome in ("review", "deny")
    assert "KA-IDF-001" in d.techniques and "KA-MLP-001" in d.techniques
    json.dumps(d.to_dict())


def test_recommend_providers():
    r = recommend_providers("KA-CRY-001")
    assert "chain_analytics" in r["capabilities"]
    assert any("Chainalysis" in v or "Elliptic" in v
               for v in r["providers_by_capability"].values())


def test_cli():
    assert main(["threats"]) == 0
    assert main(["threat", "KA-IDF-001", "--format", "json"]) == 0
    assert main(["threat", "NOPE"]) == 1
    assert main(["providers"]) == 0
    assert main(["provider", "sardine", "--format", "json"]) == 0
    assert main(["capability", "sanctions_screening"]) == 0
    assert main(["map", "KA-SAN-001"]) == 0
    assert main(["demo"]) == 0
