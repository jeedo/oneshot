#!/usr/bin/env python3
"""Tests for check_threat_coverage.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import unittest

from check_threat_coverage import (
    analyse,
    cited_in_csharp,
    cited_in_typescript,
    declared_threats,
    pending_threats,
)


class DeclaredThreatsTests(unittest.TestCase):
    def test_finds_every_distinct_id(self) -> None:
        text = "| T1 | ... |\n| T2 | ... |\nSee T10 and T2 again."

        self.assertEqual({"T1", "T2", "T10"}, declared_threats(text))

    def test_finds_ids_written_as_a_list_or_range(self) -> None:
        text = "The register (T1-T3) covers T7/T8 and (T9, T10)."

        self.assertEqual({"T1", "T3", "T7", "T8", "T9", "T10"}, declared_threats(text))

    def test_ignores_words_and_versions_that_merely_start_with_t(self) -> None:
        text = "TLS 1.2, Tls12 | Tls13, RFC 7807, ES2022, task 26, the T. 5 note"

        self.assertEqual(set(), declared_threats(text))


class CitationTests(unittest.TestCase):
    def test_reads_xunit_traits(self) -> None:
        text = '[Trait("Threat", "T4")]\n[Trait( "Threat" ,  "T11" )]\npublic sealed class X'

        self.assertEqual({"T4", "T11"}, cited_in_csharp(text))

    def test_ignores_other_traits_and_plain_mentions(self) -> None:
        text = '[Trait("Category", "T9")]\n// covers T3 in spirit\nvar s = "T5";'

        self.assertEqual(set(), cited_in_csharp(text))

    def test_reads_vitest_describe_tags_in_any_quote_style(self) -> None:
        text = "describe('[T9] client crypto', () => {});\ndescribe(\"[T1] flow\", () => {});\ndescribe(`[T8] load`, () => {});"

        self.assertEqual({"T9", "T1", "T8"}, cited_in_typescript(text))

    def test_ignores_untagged_describes_and_inner_text(self) -> None:
        text = "describe('client crypto [T9]', () => {});\nit('[T3] nested', () => {});"

        self.assertEqual(set(), cited_in_typescript(text))


EXCEPTIONS = """
## Test Convention

Every security test declares the threat it verifies. T3 is covered elsewhere.

### Coverage Exceptions

| Threat | Covered by | Why it has no test yet |
|--------|------------|------------------------|
| T15 | task 49 | Its mitigation does not exist yet. |
| T14 | task 43 | Needs the supply-chain job. |

## Analyzer Suppressions

| CA5398 | somewhere | T8 is the reason |
"""


class PendingThreatsTests(unittest.TestCase):
    def test_reads_only_the_coverage_exceptions_table(self) -> None:
        self.assertEqual({"T15": "task 49", "T14": "task 43"}, pending_threats(EXCEPTIONS))

    def test_is_empty_when_the_section_is_absent(self) -> None:
        self.assertEqual({}, pending_threats("## Test Convention\n\nNothing pending here. T1 T2\n"))


class AnalyseTests(unittest.TestCase):
    def test_reports_declared_threats_with_no_citation(self) -> None:
        findings = analyse({"T1", "T2", "T3"}, {"T1": {"a.cs"}, "T3": {"b.test.ts"}}, {})

        self.assertEqual(["T2"], findings.uncovered)
        self.assertEqual([], findings.unknown)

    def test_reports_citations_of_threats_that_do_not_exist(self) -> None:
        findings = analyse({"T1"}, {"T1": {"a.cs"}, "T99": {"typo.cs"}}, {})

        self.assertEqual([], findings.uncovered)
        self.assertEqual(["T99"], findings.unknown)

    def test_orders_findings_numerically_rather_than_alphabetically(self) -> None:
        findings = analyse({"T2", "T10", "T1"}, {}, {})

        self.assertEqual(["T1", "T2", "T10"], findings.uncovered)

    def test_passes_when_every_threat_is_cited(self) -> None:
        findings = analyse({"T1", "T2"}, {"T1": {"a.cs"}, "T2": {"b.cs"}}, {})

        self.assertTrue(findings.ok)

    def test_a_documented_pending_threat_is_not_a_failure(self) -> None:
        findings = analyse({"T1", "T2"}, {"T1": {"a.cs"}}, {"T2": "task 49"})

        self.assertTrue(findings.ok)
        self.assertEqual([], findings.uncovered)

    def test_a_pending_threat_that_gained_a_test_must_lose_its_exception(self) -> None:
        findings = analyse({"T1"}, {"T1": {"a.cs"}}, {"T1": "task 49"})

        self.assertFalse(findings.ok)
        self.assertEqual(["T1"], findings.stale)

    def test_an_exception_for_a_threat_that_does_not_exist_is_rejected(self) -> None:
        findings = analyse({"T1"}, {"T1": {"a.cs"}}, {"T99": "task 49"})

        self.assertFalse(findings.ok)
        self.assertEqual(["T99"], findings.unknown)


if __name__ == "__main__":
    unittest.main()
