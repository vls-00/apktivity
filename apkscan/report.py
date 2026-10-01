"""CLI plumbing shared by the scanners: argparse, colours, findings, json."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from .apk import APK, api_label

HIGH, MEDIUM, LOW, INFO, OK = "HIGH", "MEDIUM", "LOW", "INFO", "OK"
SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3, OK: 4}

_COLORS = {HIGH: "\033[1;31m", MEDIUM: "\033[1;33m", LOW: "\033[1;36m", INFO: "\033[1;34m", OK: "\033[1;32m"}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"
RULE = "-" * 78


class Style:
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def sev(cls, s):
        return _COLORS.get(s, "") + s + _RESET if cls.enabled else s

    @classmethod
    def bold(cls, s):
        return _BOLD + s + _RESET if cls.enabled else s

    @classmethod
    def dim(cls, s):
        return _DIM + s + _RESET if cls.enabled else s


@dataclass
class Finding:
    severity: str
    component: str
    title: str
    reasons: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    commands: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def base_parser(description):
    kw = {"description": description, "formatter_class": argparse.RawDescriptionHelpFormatter}
    try:
        p = argparse.ArgumentParser(color=False, **kw)   # 3.14 colours --help by default
    except TypeError:
        p = argparse.ArgumentParser(**kw)
    p.add_argument("apk", help="path to the .apk file")
    p.add_argument("--json", action="store_true", help="machine readable JSON output")
    p.add_argument("--all", action="store_true", help="also list components that look safe")
    return p


def load_apk(args) -> APK:
    if args.json:
        Style.enabled = False
    try:
        apk = APK(args.apk)
    except Exception as e:
        sys.stderr.write("error: cannot read %s: %s\n" % (args.apk, e))
        sys.exit(2)
    return apk


def print_header(apk, tool, extra=None):
    m = apk.manifest
    print(Style.bold("== %s ==" % tool))
    print("  APK:        %s" % apk.path)
    print("  Package:    %s  (version %s / code %s)" % (m.package, m.version_name or "?", m.version_code or "?"))
    print("  minSdk:     %s" % api_label(m.min_sdk))
    print("  targetSdk:  %s" % api_label(m.target_sdk))
    if apk.resources_error:
        print(Style.dim("  note: resources.arsc could not be parsed (%s); references shown raw" % apk.resources_error))
    for line in extra or []:
        print("  " + line)
    print(Style.dim(RULE))
    print()


def print_findings(findings, show_all):
    shown = [f for f in findings if show_all or f.severity != OK]
    if not shown:
        print(Style.bold("No findings." if not findings else "No findings (use --all to list safe components)."))
        print()
        return
    shown.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.component))
    for f in shown:
        print("[%s] %s" % (Style.sev(f.severity), Style.bold(f.component)))
        print("    " + f.title)
        if f.details:
            print()
            scalars = [k for k, v in f.details.items() if not isinstance(v, list)]
            width = max(len(k) for k in scalars) + 1 if scalars else 0
            for k, v in f.details.items():
                if isinstance(v, list):
                    if v:
                        print("    %s:" % k)
                        for item in v:
                            print("      - %s" % item)
                else:
                    print("    %-*s %s" % (width, k + ":", v))
        if f.reasons:
            print()
            print("    " + Style.bold("Why"))
            for r in f.reasons:
                print("      * " + r)
        if f.commands:
            print()
            print("    " + Style.bold("Test"))
            for c in f.commands:
                print("      $ " + c)
        if f.mitigations:
            print()
            print("    " + Style.bold("Fix"))
            for r in f.mitigations:
                print("      - " + r)
        print()
        print(Style.dim(RULE))
        print()


def summary_line(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return "Summary: " + ", ".join("%s=%d" % (Style.sev(s), counts[s]) for s in (HIGH, MEDIUM, LOW, INFO, OK))


def emit_json(apk, tool, findings, extra=None):
    m = apk.manifest
    out = {
        "tool": tool,
        "apk": apk.path,
        "package": m.package,
        "version_name": m.version_name,
        "version_code": m.version_code,
        "min_sdk": m.min_sdk,
        "target_sdk": m.target_sdk,
        "findings": [f.to_dict() for f in findings],
    }
    if extra:
        out.update(extra)
    print(json.dumps(out, indent=2, default=str))


def exit_code(findings):
    """1 when there is at least one HIGH/MEDIUM finding, for CI."""
    return 1 if any(f.severity in (HIGH, MEDIUM) for f in findings) else 0
