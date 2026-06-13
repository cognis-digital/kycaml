"""
Orchestrator — run identity verification + sanctions screening + transaction
monitoring through one call, aggregate a risk decision, and map every flag back to
the threat taxonomy and the controls/providers that address it.

This is the "streamlined hookup": you configure which adapter(s) to use (the local
mock, or real vendors once you wire in clients), hand it a customer/transaction, and
get one decision (clear / review / deny) with explained, technique-linked reasons.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

from . import threats, providers as providers_mod
from .adapters import get_adapter, Adapter


@dataclass
class Decision:
    outcome: str                 # clear | review | deny
    risk_score: float            # 0..1
    reasons: list = field(default_factory=list)     # human-readable
    techniques: list = field(default_factory=list)  # threat ids triggered
    recommended_controls: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)       # raw per-stage results

    def to_dict(self) -> dict:
        return asdict(self)


class Orchestrator:
    def __init__(self, idv: Adapter = None, aml: Adapter = None,
                 monitor: Adapter = None):
        # default everything to the local mock so it runs out of the box
        local = get_adapter("local")
        self.idv = idv or local
        self.aml = aml or local
        self.monitor = monitor or local

    @classmethod
    def local(cls) -> "Orchestrator":
        return cls()

    def assess(self, subject: dict = None, txn: dict = None) -> Decision:
        subject = subject or {}
        techniques, reasons, score = [], [], 0.0
        detail = {}

        if subject:
            v = self.idv.verify_identity(subject)
            detail["identity"] = v.to_dict()
            if not v.verified:
                reasons.append(f"identity verification weak (score {v.score})")
                score = max(score, 0.5)
            techniques += v.flags

            s = self.aml.screen_sanctions(subject)
            detail["screening"] = s.to_dict()
            if s.hit:
                reasons.append("sanctions/PEP screening hit: " +
                               ", ".join(m["name"] for m in s.matches))
                score = max(score, 0.9)
            techniques += s.flags

        if txn:
            m = self.monitor.monitor_transaction(txn)
            detail["monitoring"] = m.to_dict()
            if m.alert:
                reasons.append("transaction monitoring: " + ", ".join(m.rules_fired))
                score = max(score, 0.4 + m.score * 0.5)
            techniques += m.flags

        techniques = sorted(set(techniques))
        # gather recommended controls from the triggered techniques
        controls = []
        for tid in techniques:
            t = threats.get_technique(tid)
            if t:
                controls += t.controls
        controls = sorted(set(controls))

        if score >= 0.85:
            outcome = "deny"
        elif score >= 0.4 or techniques:
            outcome = "review"
        else:
            outcome = "clear"
        if not reasons:
            reasons.append("no risk signals detected")
        return Decision(outcome=outcome, risk_score=round(score, 2), reasons=reasons,
                        techniques=techniques, recommended_controls=controls,
                        detail=detail)


def recommend_providers(technique_id: str) -> dict:
    """For a threat technique, the capabilities that defend against it and the
    catalog providers that offer those capabilities."""
    t = threats.get_technique(technique_id)
    if not t:
        return {"error": f"unknown technique '{technique_id}'"}
    provs = {}
    for cap in t.capabilities:
        provs[cap] = [p.name for p in providers_mod.providers_with_capability(cap)]
    return {"technique": t.id, "name": t.name, "capabilities": t.capabilities,
            "controls": t.controls, "providers_by_capability": provs}
