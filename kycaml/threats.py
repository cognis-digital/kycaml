"""
KYC/AML threat taxonomy — DEFENDER-ORIENTED.

A structured catalog of the techniques fraudsters and money launderers use against
identity-verification (KYC) and anti-money-laundering (AML) programs, written so a
risk/compliance/engineering team can RECOGNIZE and DEFEND against them. Each entry
carries detection signals ("red flags"), recommended controls, and the provider
CAPABILITIES that address it — it is a defensive threat model (think MITRE ATT&CK,
or FATF typologies), NOT a how-to for committing financial crime.

See DISCLAIMER in the README: this content is for building and strengthening KYC/AML
controls and for fraud/AML investigations — not for evading them.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional

TOOL_NAME = "kycaml"
TOOL_VERSION = "0.1.0"

# capability tags a provider can offer (used to map threats -> defenses -> vendors)
CAPABILITIES = [
    "document_verification", "liveness_detection", "biometric_match",
    "database_idv", "sanctions_screening", "pep_screening", "adverse_media",
    "transaction_monitoring", "device_intelligence", "behavioral_biometrics",
    "email_phone_intelligence", "kyb_business_verification", "ubo_resolution",
    "chain_analytics", "case_management", "risk_scoring",
]

CATEGORIES = [
    "identity_fraud", "document_fraud", "biometric_spoofing", "onboarding_abuse",
    "account_takeover", "ml_placement", "ml_layering", "ml_integration",
    "sanctions_evasion", "crypto_laundering",
]


@dataclass
class Technique:
    id: str
    name: str
    category: str
    description: str          # what the threat IS (awareness), not how to do it
    red_flags: list           # detection signals a program should monitor
    controls: list            # defensive controls that mitigate it
    capabilities: list        # provider capability tags that address it

    def to_dict(self) -> dict:
        return asdict(self)


# FATF-/industry-typology-aligned. Defensive framing throughout.
TECHNIQUES: list[Technique] = [
    Technique("KA-IDF-001", "Synthetic identity", "identity_fraud",
        "A fabricated identity that blends real and made-up data (e.g. a valid-but-"
        "unused SSN paired with an invented name/DOB) to pass onboarding and build "
        "credit before 'busting out'. A leading first-party fraud vector.",
        ["Thin or contradictory credit file vs. claimed age",
         "SSN issued recently or inconsistent with DOB",
         "Many applications sharing PII fragments (same phone/SSN, different names)",
         "Authorized-user piggybacking to fabricate history"],
        ["Cross-record PII correlation across applicants",
         "SSN-issuance/date-of-birth consistency checks",
         "Velocity rules on shared identifiers", "Step-up verification on thin files"],
        ["database_idv", "email_phone_intelligence", "device_intelligence", "risk_scoring"]),
    Technique("KA-IDF-002", "Stolen / first-party identity theft", "identity_fraud",
        "Use of a real victim's genuine identity data to open or take over accounts.",
        ["Identity data appearing in known breach corpora",
         "Geolocation/device mismatch vs. the genuine holder",
         "Recently changed contact details before high-risk actions"],
        ["Knowledge-/possession-based step-up auth", "Breached-credential checks",
         "Device + behavioral binding to the genuine holder"],
        ["database_idv", "email_phone_intelligence", "device_intelligence", "behavioral_biometrics"]),
    Technique("KA-DOC-001", "Forged or altered identity document", "document_fraud",
        "Submission of a counterfeit, tampered, or templated ID document during KYC.",
        ["Font/MRZ/checksum inconsistencies", "Security-feature anomalies under analysis",
         "Reused document image hashes across applicants",
         "Metadata indicating editing software"],
        ["Automated document authentication (MRZ/checksum, security features)",
         "Image-hash reuse detection", "Issuing-authority database cross-check"],
        ["document_verification", "database_idv"]),
    Technique("KA-DOC-002", "Genuine document, wrong holder", "document_fraud",
        "A real, valid document presented by someone other than its rightful holder.",
        ["Document valid but face/liveness mismatch",
         "Same document across multiple applicants"],
        ["Document-to-selfie biometric match", "Liveness + presentation-attack detection"],
        ["document_verification", "biometric_match", "liveness_detection"]),
    Technique("KA-BIO-001", "Deepfake / injected media", "biometric_spoofing",
        "Synthetic or injected video/imagery used to defeat selfie/liveness checks "
        "(camera-injection, virtual cameras, AI face swaps).",
        ["Virtual-camera / emulator signals", "Frame-injection artifacts",
         "Liveness-challenge response anomalies", "Device-integrity failures"],
        ["Injection-attack detection", "Active + passive liveness",
         "Device-integrity/attestation checks"],
        ["liveness_detection", "biometric_match", "device_intelligence"]),
    Technique("KA-BIO-002", "Presentation attack", "biometric_spoofing",
        "Printed photo, replayed video, or mask used to spoof a face check.",
        ["Flat / 2D depth signals", "Screen moire / replay artifacts",
         "Challenge-response timing anomalies"],
        ["Presentation-attack detection (PAD)", "Randomized active-liveness challenges"],
        ["liveness_detection", "biometric_match"]),
    Technique("KA-ONB-001", "Money-mule onboarding", "onboarding_abuse",
        "Recruited or complicit individuals open genuine accounts to receive and move "
        "illicit funds on behalf of others.",
        ["Rapid post-onboarding inbound then outbound transfers",
         "Account dormant then suddenly high-velocity",
         "Shared devices/IPs across many 'independent' new accounts",
         "Onboarding clusters by time/geo/device"],
        ["Device + network clustering at onboarding", "Mule-pattern transaction rules",
         "Post-onboarding behavioral monitoring", "Cross-account network analysis"],
        ["device_intelligence", "transaction_monitoring", "behavioral_biometrics", "risk_scoring"]),
    Technique("KA-ATO-001", "Account takeover (ATO)", "account_takeover",
        "Compromise of an existing, verified account via credential stuffing, phishing, "
        "SIM-swap, or social engineering — bypassing onboarding KYC entirely.",
        ["New device + new geo + immediate high-risk action",
         "Contact-detail change followed by withdrawals",
         "SIM-swap indicators (recent port, carrier change)"],
        ["Step-up auth on risky sessions", "SIM-swap / phone-intelligence checks",
         "Behavioral-biometric continuity", "Change-of-detail cool-down + monitoring"],
        ["device_intelligence", "behavioral_biometrics", "email_phone_intelligence"]),
    Technique("KA-MLP-001", "Structuring / smurfing", "ml_placement",
        "Breaking large sums into many sub-threshold deposits/transfers (across people, "
        "accounts, or time) to avoid reporting thresholds. FATF placement typology.",
        ["Many transactions just under reporting thresholds",
         "Coordinated sub-threshold activity across linked parties",
         "Round-number clustering near limits"],
        ["Threshold-aware aggregation rules (not just per-transaction)",
         "Linked-party aggregation", "Structuring-pattern detection over time windows"],
        ["transaction_monitoring", "risk_scoring", "case_management"]),
    Technique("KA-MLP-002", "Cash-intensive front", "ml_placement",
        "Commingling illicit cash with legitimate revenue of a cash-heavy business.",
        ["Revenue inconsistent with business type/peers",
         "Deposits exceeding plausible legitimate volume"],
        ["Expected-activity profiling vs. peer baselines", "KYB + ongoing review"],
        ["transaction_monitoring", "kyb_business_verification", "risk_scoring"]),
    Technique("KA-MLL-001", "Shell-company layering", "ml_layering",
        "Moving funds through layers of shell entities and nominee owners to obscure "
        "origin. FATF layering typology.",
        ["Complex ownership with no economic rationale",
         "Nominee directors / mass-registration agents",
         "Circular or rapid pass-through flows between related entities"],
        ["UBO resolution + KYB", "Network/graph analysis of entity flows",
         "Source-of-funds / source-of-wealth evidence"],
        ["kyb_business_verification", "ubo_resolution", "transaction_monitoring", "case_management"]),
    Technique("KA-MLL-002", "Trade-based money laundering", "ml_layering",
        "Mis-invoicing trade (over/under-invoicing, phantom shipments) to move value "
        "across borders disguised as commerce.",
        ["Invoice values inconsistent with market/goods",
         "Goods/route inconsistent with parties' profiles",
         "Repeated amendments / circular trade"],
        ["Trade-document and price-benchmark review",
         "Counterparty and route risk screening"],
        ["transaction_monitoring", "kyb_business_verification", "adverse_media"]),
    Technique("KA-MLL-003", "Rapid movement / pass-through", "ml_layering",
        "Funds enter and leave quickly with little economic purpose, often fanning out.",
        ["High in/out velocity, low residual balance",
         "Fan-in/fan-out across many counterparties"],
        ["Velocity + flow-through rules", "Counterparty network analysis"],
        ["transaction_monitoring", "risk_scoring"]),
    Technique("KA-MLI-001", "Integration via high-value assets", "ml_integration",
        "Laundered funds re-enter the economy as real estate, luxury goods, or business "
        "investment with an apparently legitimate basis. FATF integration typology.",
        ["Asset purchases inconsistent with known income",
         "Use of intermediaries/trusts to hold assets"],
        ["Source-of-wealth corroboration", "Enhanced due diligence on large asset flows"],
        ["transaction_monitoring", "adverse_media", "case_management"]),
    Technique("KA-SAN-001", "Sanctions / PEP screening evasion", "sanctions_evasion",
        "Defeating watchlist screening via name variation, transliteration, nominee "
        "use, or jurisdiction hopping.",
        ["Near-miss name matches dismissed without review",
         "Transliteration/alias variants of listed parties",
         "Ownership links to sanctioned UBOs",
         "Routing through high-risk / evasion-hub jurisdictions"],
        ["Fuzzy + transliteration-aware screening", "UBO + ownership screening",
         "Jurisdiction risk scoring", "Documented match-disposition workflow"],
        ["sanctions_screening", "pep_screening", "ubo_resolution", "case_management"]),
    Technique("KA-CRY-001", "Crypto mixing / tumbling", "crypto_laundering",
        "Use of mixers/tumblers to break the on-chain link between source and "
        "destination of crypto funds.",
        ["Exposure to known mixer addresses",
         "Deposits sourced shortly after mixing"],
        ["Chain-analytics exposure scoring", "Source-of-funds for crypto deposits"],
        ["chain_analytics", "transaction_monitoring", "risk_scoring"]),
    Technique("KA-CRY-002", "Chain-hopping / nested services", "crypto_laundering",
        "Swapping across assets/chains or routing through nested exchanges to obscure "
        "provenance.",
        ["Rapid cross-asset/cross-chain swaps",
         "Counterparties identified as nested/high-risk VASPs"],
        ["Cross-chain tracing", "VASP counterparty risk + Travel Rule data"],
        ["chain_analytics", "transaction_monitoring"]),
    Technique("KA-CRY-003", "Peel chains", "crypto_laundering",
        "Iteratively peeling small amounts off a large balance across many hops to "
        "launder while hiding the principal.",
        ["Long sequences of single-input/two-output transfers",
         "Gradual dispersal to many endpoints"],
        ["Peel-chain pattern detection", "Hop-distance exposure scoring"],
        ["chain_analytics"]),
]

_BY_ID = {t.id: t for t in TECHNIQUES}


def list_techniques(category: Optional[str] = None) -> list[Technique]:
    if category:
        return [t for t in TECHNIQUES if t.category == category]
    return list(TECHNIQUES)


def get_technique(tid: str) -> Optional[Technique]:
    return _BY_ID.get((tid or "").upper())


def capabilities_for(tid: str) -> list:
    t = get_technique(tid)
    return list(t.capabilities) if t else []


def techniques_by_capability(capability: str) -> list[Technique]:
    return [t for t in TECHNIQUES if capability in t.capabilities]
