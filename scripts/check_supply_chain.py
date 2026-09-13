#!/usr/bin/env python3
"""Fail if a dependency is vulnerable, unpinned, or not recorded in a lock file.

Runs the two vulnerability scanners and checks the shape of what is declared:

  python3 scripts/check_supply_chain.py

The parsing is separated from the shelling out so it can be tested without a network: see
scripts/test_check_supply_chain.py.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NODE_PROJECTS = [Path("src/OneShot.Web/Client"), Path("tests/e2e")]
DOTNET_PROJECTS = [Path("src/OneShot.Web"), Path("tests/OneShot.Tests")]

# Anything at or above this is a failure; npm's own --audit-level gates the exit code the same way.
BLOCKING_SEVERITIES = {"high", "critical"}

# An exact version: no ^, ~, >=, *, x, or range. A caret on a dev dependency still lets a build pull code
# nobody reviewed (T14).
EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


def dotnet_vulnerabilities(report: str) -> list[str]:
    """Names every vulnerable package in a `dotnet list package --vulnerable --format json` report."""
    document = json.loads(report)
    findings = []

    for project in document.get("projects") or []:
        name = Path(project.get("path", "?")).name
        for framework in project.get("frameworks") or []:
            for kind in ("topLevelPackages", "transitivePackages"):
                for package in framework.get(kind) or []:
                    for vulnerability in package.get("vulnerabilities") or []:
                        severity = vulnerability.get("severity", "unknown")
                        findings.append(f"{name}: {package.get('id')} {package.get('resolvedVersion')} — {severity}")

    return findings


def npm_vulnerabilities(report: str, project: str) -> list[str]:
    """Names every high or critical advisory in an `npm audit --json` report."""
    document = json.loads(report)
    findings = []

    for name, vulnerability in (document.get("vulnerabilities") or {}).items():
        severity = vulnerability.get("severity", "unknown")
        if severity in BLOCKING_SEVERITIES:
            findings.append(f"{project}: {name} — {severity}")

    return findings


def declared_dependencies(package_json: str, project: str, allow_runtime: bool) -> list[str]:
    """Checks that runtime dependencies are absent where they must be, and that versions are exact."""
    document = json.loads(package_json)
    findings = []

    runtime = document.get("dependencies") or {}
    if runtime and not allow_runtime:
        findings.append(f"{project}: ships runtime dependencies, which must stay empty: {sorted(runtime)}")

    for section in ("dependencies", "devDependencies"):
        for name, version in (document.get(section) or {}).items():
            if not EXACT_VERSION.match(version):
                findings.append(f"{project}: {name} is not pinned to an exact version ({version})")

    return findings


def missing_lock_files(root: Path) -> list[str]:
    """Every project must carry a committed lock file, or its resolved graph is not recorded anywhere."""
    findings = []

    for project in DOTNET_PROJECTS:
        if not (root / project / "packages.lock.json").is_file():
            findings.append(f"{project}: packages.lock.json is missing; run dotnet restore")

    for project in NODE_PROJECTS:
        if not (root / project / "package-lock.json").is_file():
            findings.append(f"{project}: package-lock.json is missing; run npm install")

    return findings


def run(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if not completed.stdout.strip():
        raise RuntimeError(f"{' '.join(command)} produced no output: {completed.stderr.strip()}")
    return completed.stdout


def main() -> None:
    findings = missing_lock_files(ROOT)

    findings += dotnet_vulnerabilities(
        run(["dotnet", "list", "OneShot.sln", "package", "--vulnerable", "--include-transitive", "--format", "json"], ROOT))

    for project in NODE_PROJECTS:
        directory = ROOT / project
        findings += npm_vulnerabilities(run(["npm", "audit", "--json"], directory), str(project))
        findings += declared_dependencies(
            (directory / "package.json").read_text(encoding="utf-8"),
            str(project),
            # Only the client is required to ship nothing at runtime; the e2e harness is never deployed.
            allow_runtime=project != NODE_PROJECTS[0])

    for finding in findings:
        print(f"FAIL  {finding}", file=sys.stderr)

    if findings:
        sys.exit(1)

    print("OK  no vulnerable packages, no unpinned versions, every project locked")


if __name__ == "__main__":
    main()
