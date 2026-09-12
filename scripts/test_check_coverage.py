#!/usr/bin/env python3
"""Tests for check_coverage.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import unittest

from check_coverage import Area, check, parse, summarise

REPORT = """<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0.8" branch-rate="0.75">
  <packages>
    <package name="OneShot.Web">
      <classes>
        <class name="OneShot.Web.Secrets.InMemorySecretStore" filename="src/OneShot.Web/Secrets/InMemorySecretStore.cs">
          <lines>
            <line number="1" hits="3" branch="false" />
            <line number="2" hits="0" branch="false" />
            <line number="3" hits="1" branch="true" condition-coverage="50% (1/2)" />
          </lines>
        </class>
        <class name="OneShot.Web.Api.SecretsApi" filename="src/OneShot.Web/Api/SecretsApi.cs">
          <methods>
            <method name="CreateAsync">
              <lines>
                <line number="1" hits="1" branch="False" />
                <line number="2" hits="1" branch="True" condition-coverage="100% (2/2)" />
              </lines>
            </method>
          </methods>
          <lines>
            <line number="1" hits="1" branch="False" />
            <line number="2" hits="1" branch="True" condition-coverage="100% (2/2)" />
          </lines>
        </class>
        <class name="OneShot.Web.Pages.Pages_Index" filename="src/OneShot.Web/Pages/Index.cshtml">
          <lines>
            <line number="1" hits="0" branch="false" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
"""


class ParseTests(unittest.TestCase):
    def test_groups_lines_and_branches_by_area(self) -> None:
        areas = parse(REPORT)

        self.assertEqual((2, 3), (areas["OneShot.Web.Secrets"].covered_lines, areas["OneShot.Web.Secrets"].total_lines))
        self.assertEqual((1, 2), (areas["OneShot.Web.Secrets"].covered_branches, areas["OneShot.Web.Secrets"].total_branches))
        self.assertEqual((2, 2), (areas["OneShot.Web.Api"].covered_lines, areas["OneShot.Web.Api"].total_lines))
        self.assertEqual((2, 2), (areas["OneShot.Web.Api"].covered_branches, areas["OneShot.Web.Api"].total_branches))

    def test_counts_each_line_once_even_though_methods_repeat_them(self) -> None:
        # coverlet lists every line twice: under the class and again under its method.
        api = parse(REPORT)["OneShot.Web.Api"]

        self.assertEqual((2, 2), (api.covered_lines, api.total_lines))
        self.assertEqual((2, 2), (api.covered_branches, api.total_branches))

    def test_recognises_the_capitalised_branch_flag_coverlet_writes(self) -> None:
        # A lowercase-only comparison silently yields 0/0 branches, which reads as 100% and gates nothing.
        self.assertGreater(parse(REPORT)["OneShot.Web.Api"].total_branches, 0)

    def test_reports_percentages(self) -> None:
        secrets = parse(REPORT)["OneShot.Web.Secrets"]

        self.assertAlmostEqual(66.67, secrets.line_percent, places=1)
        self.assertAlmostEqual(50.0, secrets.branch_percent, places=1)

    def test_an_area_with_no_branches_counts_as_fully_covered(self) -> None:
        area = Area("x", covered_lines=1, total_lines=1, covered_branches=0, total_branches=0)

        self.assertEqual(100.0, area.branch_percent)


class CheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.areas = parse(REPORT)

    def test_reports_an_area_below_the_line_threshold(self) -> None:
        failures = check(self.areas, ["OneShot.Web.Secrets"], line=90.0, branch=0.0)

        self.assertEqual(1, len(failures))
        self.assertIn("OneShot.Web.Secrets", failures[0])
        self.assertIn("line", failures[0])

    def test_reports_an_area_below_the_branch_threshold(self) -> None:
        failures = check(self.areas, ["OneShot.Web.Secrets"], line=0.0, branch=90.0)

        self.assertIn("branch", failures[0])

    def test_passes_when_every_gated_area_clears_both_thresholds(self) -> None:
        self.assertEqual([], check(self.areas, ["OneShot.Web.Api"], line=90.0, branch=90.0))

    def test_ungated_areas_are_never_a_failure(self) -> None:
        # Razor pages are exercised through the browser, not the unit suite.
        self.assertEqual([], check(self.areas, ["OneShot.Web.Api"], line=100.0, branch=100.0))

    def test_a_gated_area_missing_from_the_report_is_a_failure(self) -> None:
        failures = check(self.areas, ["OneShot.Web.Nope"], line=90.0, branch=90.0)

        self.assertEqual(1, len(failures))
        self.assertIn("no coverage data", failures[0])


class SummariseTests(unittest.TestCase):
    def test_orders_areas_by_name_and_marks_the_gated_ones(self) -> None:
        lines = summarise(parse(REPORT), ["OneShot.Web.Api"])

        self.assertEqual(3, len(lines))
        self.assertIn("OneShot.Web.Api", lines[0])
        self.assertIn("gated", lines[0])
        self.assertNotIn("gated", lines[1])


if __name__ == "__main__":
    unittest.main()
