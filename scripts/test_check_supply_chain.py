#!/usr/bin/env python3
"""Tests for check_supply_chain.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import json
import tempfile
import unittest
from pathlib import Path

from check_supply_chain import declared_dependencies, dotnet_vulnerabilities, missing_lock_files, npm_vulnerabilities

CLEAN_DOTNET = json.dumps({
    "version": 1,
    "projects": [{"path": "/repo/src/OneShot.Web/OneShot.Web.csproj"}],
})

VULNERABLE_DOTNET = json.dumps({
    "version": 1,
    "projects": [{
        "path": "/repo/tests/OneShot.Tests/OneShot.Tests.csproj",
        "frameworks": [{
            "framework": "net10.0",
            "topLevelPackages": [{
                "id": "Some.Package",
                "resolvedVersion": "1.0.0",
                "vulnerabilities": [{"severity": "High", "advisoryurl": "https://example.test/a"}],
            }],
            "transitivePackages": [{
                "id": "Buried.Dependency",
                "resolvedVersion": "2.3.4",
                "vulnerabilities": [{"severity": "Critical", "advisoryurl": "https://example.test/b"}],
            }],
        }],
    }],
})


class DotnetTests(unittest.TestCase):
    def test_a_clean_report_has_no_findings(self) -> None:
        self.assertEqual([], dotnet_vulnerabilities(CLEAN_DOTNET))

    def test_reports_both_top_level_and_transitive_packages(self) -> None:
        # A transitive advisory is the one nobody notices, so missing them would defeat the point.
        findings = dotnet_vulnerabilities(VULNERABLE_DOTNET)

        self.assertEqual(2, len(findings))
        self.assertTrue(any("Some.Package 1.0.0" in finding for finding in findings))
        self.assertTrue(any("Buried.Dependency 2.3.4" in finding for finding in findings))
        self.assertTrue(any("Critical" in finding for finding in findings))

    def test_names_the_project_the_finding_came_from(self) -> None:
        self.assertTrue(all("OneShot.Tests.csproj" in finding for finding in dotnet_vulnerabilities(VULNERABLE_DOTNET)))


class NpmTests(unittest.TestCase):
    def report(self, severities: list[str]) -> str:
        return json.dumps({"vulnerabilities": {f"pkg{i}": {"severity": s} for i, s in enumerate(severities)}})

    def test_a_clean_report_has_no_findings(self) -> None:
        self.assertEqual([], npm_vulnerabilities(json.dumps({"vulnerabilities": {}}), "client"))

    def test_high_and_critical_are_findings(self) -> None:
        self.assertEqual(2, len(npm_vulnerabilities(self.report(["high", "critical"]), "client")))

    def test_low_and_moderate_are_not(self) -> None:
        # The gate matches npm's own --audit-level=high, so it does not fail a build over advisories nobody
        # would act on today.
        self.assertEqual([], npm_vulnerabilities(self.report(["info", "low", "moderate"]), "client"))


class DependencyTests(unittest.TestCase):
    def test_the_client_may_ship_nothing_at_runtime(self) -> None:
        package = json.dumps({"dependencies": {"left-pad": "1.0.0"}, "devDependencies": {}})

        findings = declared_dependencies(package, "client", allow_runtime=False)

        self.assertEqual(1, len(findings))
        self.assertIn("runtime dependencies", findings[0])

    def test_the_e2e_harness_may_ship_runtime_dependencies(self) -> None:
        package = json.dumps({"dependencies": {"left-pad": "1.0.0"}, "devDependencies": {}})

        self.assertEqual([], declared_dependencies(package, "e2e", allow_runtime=True))

    def test_an_empty_runtime_map_is_fine(self) -> None:
        self.assertEqual([], declared_dependencies(json.dumps({"dependencies": {}}), "client", allow_runtime=False))

    def test_a_range_is_not_a_pin(self) -> None:
        for version in ["^1.0.0", "~1.0.0", ">=1.0.0", "1.x", "*", "latest", "1.0"]:
            package = json.dumps({"devDependencies": {"tool": version}})

            findings = declared_dependencies(package, "client", allow_runtime=False)

            self.assertEqual(1, len(findings), version)
            self.assertIn("not pinned", findings[0])

    def test_an_exact_version_is_a_pin(self) -> None:
        for version in ["1.0.0", "0.28.2", "1.56.1", "7.0.2-beta.1"]:
            package = json.dumps({"devDependencies": {"tool": version}})

            self.assertEqual([], declared_dependencies(package, "client", allow_runtime=False), version)


class LockFileTests(unittest.TestCase):
    def test_reports_every_project_without_a_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            findings = missing_lock_files(Path(directory))

        self.assertEqual(4, len(findings))
        self.assertTrue(any("packages.lock.json" in finding for finding in findings))
        self.assertTrue(any("package-lock.json" in finding for finding in findings))

    def test_the_repository_itself_has_every_lock_file(self) -> None:
        self.assertEqual([], missing_lock_files(Path(__file__).resolve().parent.parent))


if __name__ == "__main__":
    unittest.main()
