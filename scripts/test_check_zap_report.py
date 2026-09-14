#!/usr/bin/env python3
"""Tests for check_zap_report.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import json
import unittest

from check_zap_report import blocking, summarise


def report(*alerts: tuple[int, str, str]) -> str:
    return json.dumps({
        "site": [{
            "@name": "http://127.0.0.1:5199",
            "alerts": [
                {
                    "pluginid": pluginid,
                    "alert": name,
                    "riskcode": str(risk),
                    "instances": [{"uri": "http://127.0.0.1:5199/"}],
                }
                for risk, pluginid, name in alerts
            ],
        }],
    })


class BlockingTests(unittest.TestCase):
    def test_a_clean_report_blocks_nothing(self) -> None:
        self.assertEqual([], blocking(report()))

    def test_informational_and_low_do_not_block(self) -> None:
        # The gate is Medium or higher: a Low that nobody would act on today must not stop a release.
        self.assertEqual([], blocking(report((0, "10109", "Modern Web Application"), (1, "10063", "Permissions Policy"))))

    def test_medium_blocks(self) -> None:
        failures = blocking(report((2, "10038", "CSP Header Not Set")))

        self.assertEqual(1, len(failures))
        self.assertIn("Medium", failures[0])
        self.assertIn("10038", failures[0])

    def test_high_blocks(self) -> None:
        self.assertEqual(1, len(blocking(report((3, "40012", "Reflected XSS")))))

    def test_the_most_severe_is_reported_first(self) -> None:
        failures = blocking(report((2, "1", "medium one"), (3, "2", "high one")))

        self.assertIn("High", failures[0])
        self.assertIn("Medium", failures[1])

    def test_an_unreadable_risk_is_treated_as_blocking(self) -> None:
        # A report we cannot parse is not a clean report, and must not be read as one.
        broken = json.dumps({"site": [{"alerts": [{"pluginid": "x", "alert": "odd", "riskcode": "not-a-number"}]}]})

        self.assertEqual(1, len(blocking(broken)))

    def test_alerts_are_collected_across_every_site(self) -> None:
        two_sites = json.dumps({
            "site": [
                {"alerts": [{"pluginid": "1", "alert": "a", "riskcode": "2", "instances": []}]},
                {"alerts": [{"pluginid": "2", "alert": "b", "riskcode": "2", "instances": []}]},
            ],
        })

        self.assertEqual(2, len(blocking(two_sites)))

    def test_a_report_with_no_sites_blocks_nothing(self) -> None:
        self.assertEqual([], blocking(json.dumps({})))


class SummaryTests(unittest.TestCase):
    def test_counts_each_severity(self) -> None:
        text = summarise(report((0, "1", "a"), (0, "2", "b"), (2, "3", "c")))

        self.assertIn("1 Medium", text)
        self.assertIn("2 Informational", text)

    def test_says_so_when_there_is_nothing(self) -> None:
        self.assertEqual("no alerts at all", summarise(report()))


if __name__ == "__main__":
    unittest.main()
