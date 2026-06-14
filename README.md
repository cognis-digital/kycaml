# kycaml

> A **defensive** KYC/AML toolkit: a defender-oriented threat taxonomy of how fraud
> and money laundering are attempted against identity (KYC) and anti-money-laundering
> (AML) programs, a catalog of the KYC/AML provider ecosystem, and a streamlined
> provider-orchestration layer that wires them up behind one interface.

[![Code License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-6b46c1.svg)](LICENSE)
[![tests](https://img.shields.io/badge/tests-14%20passing-2ea44f.svg)](tests/)

<!-- cognis:layman:start -->
## What is this?

Banks, fintechs, and crypto platforms are legally required to verify who their
customers are (KYC) and to watch for money laundering (AML). Doing that well means
two things: understanding the tricks criminals use to slip through, and plugging in
the right verification and screening vendors. `kycaml` helps with both. It ships a
plain catalog of the common attack techniques — synthetic identities, fake
documents, deepfake selfies, money mules, structuring, shell-company layering,
sanctions evasion, crypto mixing — each written for the *defender*: what to watch
for and which controls stop it. It also maps the major KYC/AML providers (Jumio,
Onfido, Persona, Alloy, Sardine, ComplyAdvantage, Chainalysis, and more) to the
capabilities they offer, and gives you one interface to run identity verification,
sanctions screening, and transaction monitoring together and get a single
clear / review / deny decision. A built-in local mock lets you develop and test the
whole flow offline, then swap in real vendors when you're ready.
<!-- cognis:layman:end -->

## Three parts

1. **Threat taxonomy** (`kycaml.threats`) — 17+ FATF-/industry-aligned techniques
   across identity fraud, document fraud, biometric spoofing, onboarding abuse,
   account takeover, the three money-laundering stages (placement / layering /
   integration), sanctions evasion, and crypto laundering. Each carries **red flags**
   (detection signals), **controls** (defensive mitigations), and the provider
   **capabilities** that address it.
2. **Provider catalog** (`kycaml.providers`) — 20 vendors across IDV, AML, KYB,
   crypto-analytics, and orchestration, tagged by capability so you can map a control
   need to the vendors that satisfy it.
3. **Streamlined hookup** (`kycaml.adapters` + `kycaml.orchestrator`) — one adapter
   interface (`verify_identity` / `screen_sanctions` / `monitor_transaction`), a
   deterministic **local mock** for offline dev/test, and config-driven stubs for
   real vendors (no outbound calls until you wire in a client). The `Orchestrator`
   runs the stages, aggregates a risk **Decision**, and links every flag back to the
   threat taxonomy and recommended controls.

## Usage

```sh
kycaml threats --category ml_layering          # browse the taxonomy
kycaml threat KA-IDF-001                        # signals + controls + capabilities
kycaml providers --segment crypto               # the vendor catalog
kycaml map KA-SAN-001                           # technique -> capabilities -> providers
kycaml demo                                      # a sample end-to-end assessment
kycaml assess --subject customer.json --txn payment.json
```

```python
from kycaml import Orchestrator
decision = Orchestrator.local().assess(
    subject={"name": "Jane Public", "document": "passport", "selfie": "img"},
    txn={"amount": 9500, "reporting_threshold": 10000, "count_24h": 12})
print(decision.outcome, decision.techniques, decision.recommended_controls)
```

Swap in a real provider by implementing an adapter and passing it to the
`Orchestrator` — the local mock and the real vendor share one interface.

## Topics / Domains

`kyc` · `aml` · `compliance` · `anti-fraud` · `regtech` · `sanctions-screening` ·
`transaction-monitoring` · `identity-verification` · part of the **Cognis Neural
Suite** (finance / compliance domain).

## Verification

```text
tests   : 14 passing (deterministic; local mock, no network)
runtime : pure Python standard library; no third-party deps
```

## Disclaimer — defensive use only

`kycaml` exists to help organizations **build and strengthen** KYC/AML programs:
understand the threat landscape in order to defend against it, choose and integrate
compliance providers, and orchestrate verification/screening/monitoring. The threat
taxonomy is **defender-oriented threat awareness** (detection signals and controls,
in the spirit of FATF typologies and MITRE ATT&CK) — it deliberately does **not**
contain operational instructions for committing identity fraud, money laundering, or
sanctions evasion, and the library makes **no** outbound calls to circumvent any real
provider. It is not legal or compliance advice; consult qualified counsel and meet
your jurisdiction's regulatory obligations. Bundled watchlist data is a tiny
illustrative mock, **not** a real sanctions list.

## Interoperability

`kycaml` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `kycaml`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Cognis Open Collaboration License (COCL) 1.0 — see [LICENSE](LICENSE).
