"""
KYC/AML provider catalog.

A reference map of the identity-verification, sanctions/PEP screening, transaction-
monitoring, KYB, and crypto-analytics vendor ecosystem, tagged with the capabilities
(from threats.CAPABILITIES) each is publicly known to offer. Used to map a defensive
control need -> the providers that can satisfy it, and to drive the orchestrator.

Capabilities are based on each vendor's publicly described product scope; this is a
descriptive catalog (confirm current scope with each vendor), not an endorsement.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Provider:
    key: str
    name: str
    segment: str             # idv | aml | orchestration | crypto | kyb
    capabilities: list
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


PROVIDERS: list[Provider] = [
    Provider("jumio", "Jumio", "idv",
             ["document_verification", "liveness_detection", "biometric_match",
              "database_idv", "risk_scoring"],
             "Document + biometric identity verification."),
    Provider("onfido", "Onfido", "idv",
             ["document_verification", "liveness_detection", "biometric_match",
              "database_idv"],
             "Document + facial-biometric verification (Entrust)."),
    Provider("veriff", "Veriff", "idv",
             ["document_verification", "liveness_detection", "biometric_match",
              "device_intelligence"],
             "IDV with fraud/device signals."),
    Provider("sumsub", "Sumsub", "orchestration",
             ["document_verification", "liveness_detection", "sanctions_screening",
              "pep_screening", "transaction_monitoring", "kyb_business_verification",
              "case_management"],
             "Full KYC/KYB/AML orchestration platform."),
    Provider("persona", "Persona", "orchestration",
             ["document_verification", "liveness_detection", "database_idv",
              "device_intelligence", "case_management", "risk_scoring"],
             "Configurable IDV + workflow orchestration."),
    Provider("alloy", "Alloy", "orchestration",
             ["database_idv", "sanctions_screening", "transaction_monitoring",
              "kyb_business_verification", "case_management", "risk_scoring"],
             "Identity decisioning + AML orchestration layer."),
    Provider("socure", "Socure", "idv",
             ["database_idv", "email_phone_intelligence", "device_intelligence",
              "risk_scoring", "behavioral_biometrics"],
             "Predictive identity / fraud risk."),
    Provider("sardine", "Sardine", "aml",
             ["device_intelligence", "behavioral_biometrics", "transaction_monitoring",
              "risk_scoring", "chain_analytics"],
             "Fraud + AML with device/behavior signals; crypto-aware."),
    Provider("unit21", "Unit21", "aml",
             ["transaction_monitoring", "case_management", "risk_scoring"],
             "Transaction monitoring + case management."),
    Provider("hummingbird", "Hummingbird", "aml",
             ["case_management", "transaction_monitoring"],
             "AML investigations + SAR case management."),
    Provider("comply_advantage", "ComplyAdvantage", "aml",
             ["sanctions_screening", "pep_screening", "adverse_media",
              "transaction_monitoring"],
             "Sanctions/PEP/adverse-media screening + monitoring."),
    Provider("refinitiv_wc", "LSEG World-Check", "aml",
             ["sanctions_screening", "pep_screening", "adverse_media"],
             "Watchlist / PEP / adverse-media reference data."),
    Provider("trulioo", "Trulioo", "idv",
             ["database_idv", "document_verification", "kyb_business_verification",
              "email_phone_intelligence"],
             "Global identity + business verification."),
    Provider("middesk", "Middesk", "kyb",
             ["kyb_business_verification", "ubo_resolution"],
             "Business identity / KYB + UBO."),
    Provider("chainalysis", "Chainalysis", "crypto",
             ["chain_analytics", "sanctions_screening", "transaction_monitoring",
              "risk_scoring"],
             "Blockchain analytics + crypto sanctions/exposure."),
    Provider("elliptic", "Elliptic", "crypto",
             ["chain_analytics", "sanctions_screening", "risk_scoring"],
             "Crypto wallet/transaction risk + tracing."),
    Provider("trm", "TRM Labs", "crypto",
             ["chain_analytics", "transaction_monitoring", "risk_scoring"],
             "Crypto risk + investigations."),
    Provider("sentilink", "SentiLink", "idv",
             ["database_idv", "risk_scoring", "email_phone_intelligence"],
             "Synthetic / first-party fraud detection (US)."),
    Provider("prove", "Prove", "idv",
             ["email_phone_intelligence", "database_idv", "device_intelligence"],
             "Phone-centric identity / possession verification."),
    Provider("incode", "Incode", "idv",
             ["document_verification", "liveness_detection", "biometric_match"],
             "Biometric identity verification."),
]

_BY_KEY = {p.key: p for p in PROVIDERS}


def list_providers(segment: Optional[str] = None) -> list[Provider]:
    if segment:
        return [p for p in PROVIDERS if p.segment == segment]
    return list(PROVIDERS)


def get_provider(key: str) -> Optional[Provider]:
    return _BY_KEY.get((key or "").lower())


def providers_with_capability(capability: str) -> list[Provider]:
    return [p for p in PROVIDERS if capability in p.capabilities]
