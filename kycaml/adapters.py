"""
Provider-agnostic adapter layer — the "streamlined hookup".

One interface for every KYC/AML provider: `verify_identity`, `screen_sanctions`,
`monitor_transaction`. A `LocalMockAdapter` implements all of it deterministically
with no network (for development, demos, and tests). Real vendors are registered as
config-driven stubs that establish the integration seam but make NO outbound calls
until you supply credentials and a concrete client — so this library never silently
phones home, and never helps anyone bypass a real provider.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
import hashlib
import re


# ---- result types ---------------------------------------------------------
@dataclass
class VerificationResult:
    verified: bool
    score: float                  # 0..1 confidence
    checks: dict = field(default_factory=dict)
    flags: list = field(default_factory=list)   # threat technique ids
    provider: str = "local"

    def to_dict(self): return asdict(self)


@dataclass
class ScreeningResult:
    hit: bool
    matches: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    provider: str = "local"

    def to_dict(self): return asdict(self)


@dataclass
class MonitoringResult:
    alert: bool
    rules_fired: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    score: float = 0.0
    provider: str = "local"

    def to_dict(self): return asdict(self)


class NotConfigured(Exception):
    """A real-provider adapter was used without credentials/a client."""


class Adapter:
    """Base interface. Subclasses implement the methods their capabilities support."""
    key = "base"

    def verify_identity(self, subject: dict) -> VerificationResult:
        raise NotImplementedError

    def screen_sanctions(self, subject: dict) -> ScreeningResult:
        raise NotImplementedError

    def monitor_transaction(self, txn: dict) -> MonitoringResult:
        raise NotImplementedError


# ---- local, deterministic mock (no network) -------------------------------
# tiny illustrative watchlist (NOT a real sanctions list — for demo/tests only)
_MOCK_WATCHLIST = [
    {"name": "ivan petrov", "type": "sanctioned", "program": "DEMO-OFAC"},
    {"name": "acme shell holdings", "type": "sanctioned", "program": "DEMO-EU"},
    {"name": "maria gonzalez", "type": "pep", "program": "DEMO-PEP"},
]
_HIGH_RISK_JURISDICTIONS = {"KP", "IR", "SY", "DEMO-HR"}
_MIXER_TAG = "mixer"


def _norm(s) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip().lower())


class LocalMockAdapter(Adapter):
    """Deterministic offline behavior good enough to build + test against."""
    key = "local"

    def verify_identity(self, subject: dict) -> VerificationResult:
        checks, flags = {}, []
        has_doc = bool(subject.get("document"))
        has_selfie = bool(subject.get("selfie"))
        checks["document_present"] = has_doc
        checks["selfie_present"] = has_selfie
        # demo signals (opt-in via subject fields) mapped to threat techniques
        if subject.get("document_reused"):
            flags.append("KA-DOC-001")
        if has_doc and has_selfie and subject.get("selfie_match") is False:
            flags.append("KA-DOC-002")
        if subject.get("liveness_failed"):
            flags.append("KA-BIO-001")
        if subject.get("synthetic_signals"):
            flags.append("KA-IDF-001")
        score = 0.95 if (has_doc and has_selfie and not flags) else \
            (0.6 if (has_doc or has_selfie) else 0.2)
        if flags:
            score = min(score, 0.35)
        return VerificationResult(verified=score >= 0.7 and not flags,
                                  score=round(score, 2), checks=checks, flags=flags)

    def screen_sanctions(self, subject: dict) -> ScreeningResult:
        name = _norm(subject.get("name"))
        matches, flags = [], []
        for w in _MOCK_WATCHLIST:
            wn = w["name"]
            # exact or token-subset (fuzzy-lite) match
            if name == wn or (name and set(wn.split()) <= set(name.split())):
                matches.append(w)
        if matches:
            flags.append("KA-SAN-001")
        return ScreeningResult(hit=bool(matches), matches=matches, flags=flags)

    def monitor_transaction(self, txn: dict) -> MonitoringResult:
        rules, flags = [], []
        amount = float(txn.get("amount", 0) or 0)
        threshold = float(txn.get("reporting_threshold", 10000))
        # structuring: just under a reporting threshold
        if 0.8 * threshold <= amount < threshold:
            rules.append("structuring_near_threshold"); flags.append("KA-MLP-001")
        # velocity: many transfers in a short window
        if int(txn.get("count_24h", 0) or 0) >= 10:
            rules.append("high_velocity"); flags.append("KA-MLL-003")
        # rapid pass-through: in then out, low residual
        if txn.get("passthrough"):
            rules.append("rapid_passthrough"); flags.append("KA-MLL-003")
        # high-risk jurisdiction
        if str(txn.get("counterparty_country", "")).upper() in _HIGH_RISK_JURISDICTIONS:
            rules.append("high_risk_jurisdiction"); flags.append("KA-SAN-001")
        # crypto mixer exposure
        tags = [_norm(t) for t in (txn.get("crypto_exposure") or [])]
        if _MIXER_TAG in tags:
            rules.append("mixer_exposure"); flags.append("KA-CRY-001")
        score = min(1.0, 0.25 * len(rules))
        return MonitoringResult(alert=bool(rules), rules_fired=rules,
                                flags=sorted(set(flags)), score=round(score, 2))


class _RealStub(Adapter):
    """Seam for a real vendor: holds config, raises until a client is wired in."""
    def __init__(self, key, client=None, **config):
        self.key = key
        self._client = client
        self._config = config

    def _require(self):
        if self._client is None:
            raise NotConfigured(
                f"provider '{self.key}' needs a configured client/credentials; "
                f"this library makes no outbound calls on your behalf. Pass client=... "
                f"or use the 'local' adapter for offline development.")

    def verify_identity(self, subject): self._require()
    def screen_sanctions(self, subject): self._require()
    def monitor_transaction(self, txn): self._require()


def get_adapter(key: str = "local", **config) -> Adapter:
    """Return an adapter. 'local' = the deterministic mock; any other key returns a
    config-driven stub for that vendor (no network until you wire in a client)."""
    if (key or "local").lower() == "local":
        return LocalMockAdapter()
    return _RealStub(key, **config)
