#!/usr/bin/env python3
"""Fail when a threat in docs/threat-model.md has no test citing it.

Security tests declare the threat they verify, so coverage can be checked mechanically:

  xUnit   [Trait("Threat", "T4")]   on a class or a [Fact]/[Theory]
  vitest  describe('[T9] ...')      on the top-level describe

A threat with no citing test is an unverified mitigation, and a citation of a threat that is not in the
register is a typo; both fail the build. See the Test Convention section of docs/threat-model.md.
"""

import re
import sys
from dataclasses import dataclass
from pathlib import Path

THREAT_RE = re.compile(r"\bT(\d+)\b")
TRAIT_RE = re.compile(r"""\[\s*Trait\s*\(\s*["']Threat["']\s*,\s*["']T(\d+)["']\s*\)\s*\]""")
DESCRIBE_RE = re.compile(r"""describe\s*\(\s*['"`]\s*\[T(\d+)\]""")

SEARCH_ROOTS = ("tests", "src")
SKIP_DIRECTORIES = {"bin", "obj", "node_modules", "test-results", "playwright-report"}


def declared_threats(text: str) -> set[str]:
    """Return every threat id the threat model mentions."""
    return {f"T{number}" for number in THREAT_RE.findall(text)}


def cited_in_csharp(text: str) -> set[str]:
    return {f"T{number}" for number in TRAIT_RE.findall(text)}


def cited_in_typescript(text: str) -> set[str]:
    return {f"T{number}" for number in DESCRIBE_RE.findall(text)}


@dataclass(frozen=True)
class Findings:
    """Everything wrong with the current coverage, lowest threat id first."""

    uncovered: list[str]
    """Declared, has no test, and has no documented exception."""

    unknown: list[str]
    """Cited by a test, or excepted, but absent from the threat model — usually a typo."""

    stale: list[str]
    """Excepted but now covered: the exception has served its purpose and must go."""

    @property
    def ok(self) -> bool:
        return not (self.uncovered or self.unknown or self.stale)


def pending_threats(text: str) -> dict[str, str]:
    """Read the documented coverage exceptions: threat id -> what will cover it."""
    section = re.search(r"^###?\s+Coverage Exceptions\s*$(.*?)(?=^##\s|\Z)", text, re.MULTILINE | re.DOTALL)
    if not section:
        return {}

    rows = re.findall(r"^\|\s*T(\d+)\s*\|\s*([^|]+?)\s*\|", section.group(1), re.MULTILINE)
    return {f"T{number}": covered_by for number, covered_by in rows}


def analyse(declared: set[str], citations: dict[str, set[str]], pending: dict[str, str]) -> Findings:
    return Findings(
        uncovered=sorted(declared - citations.keys() - pending.keys(), key=_number),
        unknown=sorted((citations.keys() | pending.keys()) - declared, key=_number),
        stale=sorted(pending.keys() & citations.keys(), key=_number),
    )


def collect(root: Path) -> dict[str, set[str]]:
    """Map each cited threat id to the files citing it."""
    citations: dict[str, set[str]] = {}
    for directory in SEARCH_ROOTS:
        for path in sorted((root / directory).rglob("*")):
            if path.suffix not in {".cs", ".ts"} or _skipped(path):
                continue
            text = path.read_text(encoding="utf-8")
            cited = cited_in_csharp(text) if path.suffix == ".cs" else cited_in_typescript(text)
            for threat in cited:
                citations.setdefault(threat, set()).add(str(path.relative_to(root)))
    return citations


def _skipped(path: Path) -> bool:
    return any(part in SKIP_DIRECTORIES for part in path.parts)


def _number(threat: str) -> int:
    return int(threat[1:])


def main(root: Path = Path(".")) -> None:
    model = root / "docs" / "threat-model.md"
    if not model.exists():
        print(f"FAIL  {model}: file not found", file=sys.stderr)
        sys.exit(1)

    text = model.read_text(encoding="utf-8")
    declared = declared_threats(text)
    if not declared:
        print(f"FAIL  {model}: no threat ids found", file=sys.stderr)
        sys.exit(1)

    pending = pending_threats(text)
    citations = collect(root)
    findings = analyse(declared, citations, pending)

    for threat in sorted(declared, key=_number):
        files = citations.get(threat, set())
        if files:
            status = f"{len(files):2d} file(s)"
        elif threat in pending:
            status = f"pending — {pending[threat]}"
        else:
            status = "NO TESTS"
        print(f"  {threat:>4}  {status}")

    for threat in findings.uncovered:
        print(f"FAIL  {threat} is in the threat model but no test cites it", file=sys.stderr)
    for threat in findings.unknown:
        where = ", ".join(sorted(citations.get(threat, {"the coverage exceptions"})))
        print(f"FAIL  {threat} is cited by {where} but is not in the threat model", file=sys.stderr)
    for threat in findings.stale:
        print(f"FAIL  {threat} now has tests; remove its row from the Coverage Exceptions table", file=sys.stderr)

    if not findings.ok:
        sys.exit(1)

    covered = len(declared) - len(pending)
    suffix = f", {len(pending)} pending" if pending else ""
    print(f"OK  {covered} of {len(declared)} threats covered{suffix}")


if __name__ == "__main__":
    main()
