#!/usr/bin/env python3
"""Report unit-test coverage per area and fail when security-critical code slips below its threshold.

Collect a report first:

  dotnet test OneShot.sln --collect:"XPlat Code Coverage" \\
      --settings coverlet.runsettings --results-directory artifacts/coverage

then run this script. Gated areas are the domain, endpoint, security and audit code — the parts a regression
would let through silently. Razor pages and the startup file are reported but not gated: they are exercised
by the browser suite (plan tasks 34, 42, 44), where line coverage of generated markup means little.
"""

import glob
import re
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path

GATED_AREAS = [
    "OneShot.Web.Api",
    "OneShot.Web.Audit",
    "OneShot.Web.Secrets",
    "OneShot.Web.Security",
]

MIN_LINE_PERCENT = 90.0
MIN_BRANCH_PERCENT = 85.0

CONDITION_RE = re.compile(r"\((\d+)/(\d+)\)")


@dataclass
class Area:
    """Coverage totals for one namespace."""

    name: str
    covered_lines: int = 0
    total_lines: int = 0
    covered_branches: int = 0
    total_branches: int = 0

    @property
    def line_percent(self) -> float:
        return 100.0 if self.total_lines == 0 else 100.0 * self.covered_lines / self.total_lines

    @property
    def branch_percent(self) -> float:
        return 100.0 if self.total_branches == 0 else 100.0 * self.covered_branches / self.total_branches


def parse(report: str) -> dict[str, Area]:
    """Group a cobertura report's classes into areas by namespace."""
    root = ElementTree.fromstring(report)
    areas: dict[str, Area] = {}

    for element in root.iter("class"):
        name = element.get("name") or ""
        namespace = name.rsplit(".", 1)[0] if "." in name else name
        area = areas.setdefault(namespace, Area(namespace))

        # Only the class's own <lines>: coverlet repeats every line under <methods>, and iterating
        # descendants would count each one twice.
        lines = element.find("lines")
        for line in lines.findall("line") if lines is not None else []:
            area.total_lines += 1
            if int(line.get("hits") or 0) > 0:
                area.covered_lines += 1

            condition = line.get("condition-coverage")
            if (line.get("branch") or "").lower() == "true" and condition and (match := CONDITION_RE.search(condition)):
                area.covered_branches += int(match.group(1))
                area.total_branches += int(match.group(2))

    return areas


def check(areas: dict[str, Area], gated: list[str], line: float, branch: float) -> list[str]:
    """Return a message for every gated area that is missing or below a threshold."""
    failures = []
    for name in gated:
        area = areas.get(name)
        if area is None:
            failures.append(f"{name}: no coverage data — was the area renamed or the report collected?")
            continue

        if area.line_percent < line:
            failures.append(f"{name}: line coverage {area.line_percent:.1f}% is below the required {line:.1f}%")
        if area.branch_percent < branch:
            failures.append(f"{name}: branch coverage {area.branch_percent:.1f}% is below the required {branch:.1f}%")

    return failures


def summarise(areas: dict[str, Area], gated: list[str]) -> list[str]:
    lines = []
    for name in sorted(areas, key=lambda area: (area not in gated, area)):
        area = areas[name]
        mark = " (gated)" if name in gated else ""
        lines.append(
            f"  {name:<28} lines {area.covered_lines:4d}/{area.total_lines:<4d} {area.line_percent:5.1f}%"
            f"   branches {area.covered_branches:4d}/{area.total_branches:<4d} {area.branch_percent:5.1f}%{mark}"
        )
    return lines


def newest_report(results: Path) -> Path | None:
    reports = glob.glob(str(results / "**" / "coverage.cobertura.xml"), recursive=True)
    return Path(max(reports, key=lambda path: Path(path).stat().st_mtime)) if reports else None


def main(results: Path = Path("artifacts/coverage")) -> None:
    report = newest_report(results)
    if report is None:
        print(f"FAIL  no coverage.cobertura.xml under {results}; run dotnet test --collect:\"XPlat Code Coverage\" first", file=sys.stderr)
        sys.exit(1)

    areas = parse(report.read_text(encoding="utf-8"))
    for line in summarise(areas, GATED_AREAS):
        print(line)

    failures = check(areas, GATED_AREAS, MIN_LINE_PERCENT, MIN_BRANCH_PERCENT)
    for failure in failures:
        print(f"FAIL  {failure}", file=sys.stderr)

    if failures:
        sys.exit(1)

    print(f"OK  every gated area is at or above {MIN_LINE_PERCENT:.0f}% lines and {MIN_BRANCH_PERCENT:.0f}% branches")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/coverage"))
