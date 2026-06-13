"""kycaml — a defensive KYC/AML toolkit: threat taxonomy, provider catalog, and a
streamlined provider-orchestration layer. For building and strengthening KYC/AML
controls — not for evading them. See the README disclaimer."""
from .threats import (
    TOOL_NAME, TOOL_VERSION, CAPABILITIES, CATEGORIES, Technique, TECHNIQUES,
    list_techniques, get_technique, capabilities_for, techniques_by_capability,
)
from .providers import (
    Provider, PROVIDERS, list_providers, get_provider, providers_with_capability,
)
from .adapters import (
    Adapter, LocalMockAdapter, get_adapter, NotConfigured,
    VerificationResult, ScreeningResult, MonitoringResult,
)
from .orchestrator import Orchestrator, Decision, recommend_providers

__all__ = [
    "TOOL_NAME", "TOOL_VERSION", "CAPABILITIES", "CATEGORIES", "Technique",
    "TECHNIQUES", "list_techniques", "get_technique", "capabilities_for",
    "techniques_by_capability", "Provider", "PROVIDERS", "list_providers",
    "get_provider", "providers_with_capability", "Adapter", "LocalMockAdapter",
    "get_adapter", "NotConfigured", "VerificationResult", "ScreeningResult",
    "MonitoringResult", "Orchestrator", "Decision", "recommend_providers",
]
