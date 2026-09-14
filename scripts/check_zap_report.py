#!/usr/bin/env python3
"""Fail when a ZAP baseline report contains an alert at or above Medium.

  python3 scripts/check_zap_report.py report_json.json

The severity threshold lives here rather than in zap-baseline.py's exit code, which fails on any warning at
all and cannot express "Medium or higher". The two mechanisms have separate jobs: .github/zap-rules.tsv is the
reviewed list of rules ZAP should not raise at all, and this is the gate on whatever it still reports.
"""

import json
import sys
from pathlib import Path

# ZAP's riskcode: 0 informational, 1 low, 2 medium, 3 high.
RISK_NAMES = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}
BLOCKING_RISK = 2


def alerts(report: str) -> list[dict]:
    """Every alert in a traditional-json report, across every site it covers."""
    document = json.loads(report)
    return [alert for site in document.get("site") or [] for alert in site.get("alerts") or []]


def blocking(report: str, minimum: int = BLOCKING_RISK) -> list[str]:
    """Describes every alert at or above the threshold, most severe first."""
    found = []

    for alert in alerts(report):
        try:
            risk = int(alert.get("riskcode", 0))
        except (TypeError, ValueError):
            # An unparseable risk is treated as blocking: a report we cannot read is not a clean report.
            risk = 3

        if risk >= minimum:
            urls = ", ".join(sorted({instance.get("uri", "?") for instance in alert.get("instances") or []})[:3])
            found.append((risk, f"{RISK_NAMES.get(risk, risk)}: [{alert.get('pluginid', '?')}] {alert.get('alert', '?')} — {urls}"))

    return [description for _, description in sorted(found, key=lambda entry: -entry[0])]


def summarise(report: str) -> str:
    counts: dict[int, int] = {}
    for alert in alerts(report):
        risk = int(alert.get("riskcode", 0) or 0)
        counts[risk] = counts.get(risk, 0) + 1

    if not counts:
        return "no alerts at all"
    return ", ".join(f"{count} {RISK_NAMES.get(risk, risk)}" for risk, count in sorted(counts.items(), reverse=True))


def main(path: Path) -> None:
    if not path.is_file():
        # A missing report means the scan did not run, which must not read as a pass.
        print(f"FAIL  no ZAP report at {path}; did the scan run?", file=sys.stderr)
        sys.exit(1)

    report = path.read_text(encoding="utf-8")
    print(f"ZAP reported: {summarise(report)}")

    failures = blocking(report)
    for failure in failures:
        print(f"FAIL  {failure}", file=sys.stderr)

    if failures:
        print(
            "\nEach of these is either a real finding to fix or, if it is a deliberate design decision, an "
            "entry for .github/zap-rules.tsv naming the task and test that justify it.",
            file=sys.stderr)
        sys.exit(1)

    print(f"OK  nothing at {RISK_NAMES[BLOCKING_RISK]} or above")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "report_json.json"))
