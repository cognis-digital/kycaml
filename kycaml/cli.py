"""kycaml — KYC/AML defense toolkit CLI.

  threats [--category C]        list the defender-oriented threat taxonomy
  threat <ID>                   show one technique (signals, controls, capabilities)
  providers [--segment S]       list the KYC/AML provider catalog
  provider <key>                show one provider
  capability <cap>              providers + techniques for a capability
  map <TECHNIQUE_ID>            technique -> defending capabilities -> providers
  assess --subject f.json [--txn t.json]   run the orchestrator (local mock)
  demo                          run a built-in demo assessment

--format table|json
"""
from __future__ import annotations
import argparse
import json
import sys

from . import threats, providers as P, orchestrator
from .threats import TOOL_NAME, TOOL_VERSION


def _out(obj, fmt="json"):
    print(json.dumps(obj, indent=2, default=str) if fmt == "json" or not isinstance(obj, str)
          else obj)


def cmd_threats(a):
    ts = threats.list_techniques(a.category)
    if a.format == "json":
        _out([t.to_dict() for t in ts]); return 0
    for t in ts:
        print(f"{t.id:12} [{t.category:18}] {t.name}")
    return 0


def cmd_threat(a):
    t = threats.get_technique(a.id)
    if not t:
        print(f"unknown technique '{a.id}'"); return 1
    _out(t.to_dict()); return 0


def cmd_providers(a):
    ps = P.list_providers(a.segment)
    if a.format == "json":
        _out([p.to_dict() for p in ps]); return 0
    for p in ps:
        print(f"{p.key:16} [{p.segment:13}] {p.name} — {', '.join(p.capabilities)}")
    return 0


def cmd_provider(a):
    p = P.get_provider(a.key)
    if not p:
        print(f"unknown provider '{a.key}'"); return 1
    _out(p.to_dict()); return 0


def cmd_capability(a):
    _out({"capability": a.cap,
          "providers": [p.name for p in P.providers_with_capability(a.cap)],
          "techniques": [t.id for t in threats.techniques_by_capability(a.cap)]})
    return 0


def cmd_map(a):
    _out(orchestrator.recommend_providers(a.id)); return 0


def cmd_assess(a):
    subject = json.load(open(a.subject)) if a.subject else {}
    txn = json.load(open(a.txn)) if a.txn else {}
    d = orchestrator.Orchestrator.local().assess(subject=subject, txn=txn)
    _out(d.to_dict() if a.format == "json" else
         f"OUTCOME: {d.outcome.upper()} (risk {d.risk_score})\n"
         f"reasons: {'; '.join(d.reasons)}\n"
         f"techniques: {', '.join(d.techniques) or 'none'}\n"
         f"controls: {'; '.join(d.recommended_controls) or 'none'}", a.format)
    return 0


def cmd_demo(a):
    subject = {"name": "Ivan Petrov", "document": "passport", "selfie": "img",
               "synthetic_signals": True}
    txn = {"amount": 9500, "reporting_threshold": 10000, "count_24h": 12,
           "counterparty_country": "DEMO-HR", "crypto_exposure": ["mixer"]}
    d = orchestrator.Orchestrator.local().assess(subject=subject, txn=txn)
    _out(d.to_dict()); return 0


def build_parser():
    p = argparse.ArgumentParser(prog=TOOL_NAME, description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    def add(name, fn):
        sp = sub.add_parser(name)
        sp.add_argument("--format", choices=["table", "json"], default="table")
        sp.set_defaults(func=fn)
        return sp

    sp = add("threats", cmd_threats); sp.add_argument("--category")
    sp = add("threat", cmd_threat); sp.add_argument("id")
    sp = add("providers", cmd_providers); sp.add_argument("--segment")
    sp = add("provider", cmd_provider); sp.add_argument("key")
    sp = add("capability", cmd_capability); sp.add_argument("cap")
    sp = add("map", cmd_map); sp.add_argument("id")
    sp = add("assess", cmd_assess); sp.add_argument("--subject"); sp.add_argument("--txn")
    add("demo", cmd_demo)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not getattr(args, "command", None):
        build_parser().print_help(); return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
