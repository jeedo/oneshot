#!/usr/bin/env python3
"""Tests for check_docs.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import tempfile
import unittest
from pathlib import Path

from check_docs import (
    REQUIRED_RUNBOOK_SECTIONS,
    REQUIRED_SECURITY_REVIEW_SECTIONS,
    check_runbook,
    check_sectioned_lines,
    check_security_review,
)


class CheckSectionedLinesTests(unittest.TestCase):
    def test_a_clean_document_has_no_findings(self) -> None:
        lines = [
            "## One",
            "content",
            "## Two",
            "more content",
        ]

        self.assertEqual([], check_sectioned_lines(lines, "doc.md", ["One", "Two"]))

    def test_reports_a_missing_section(self) -> None:
        lines = ["## One", "content"]

        errors = check_sectioned_lines(lines, "doc.md", ["One", "Two"])

        self.assertEqual(["doc.md: missing required section 'Two'"], errors)

    def test_reports_a_section_with_no_content(self) -> None:
        lines = ["## One", "## Two", "content"]

        errors = check_sectioned_lines(lines, "doc.md", ["One", "Two"])

        self.assertEqual(["doc.md: section 'One' is empty"], errors)

    def test_reports_every_tbd_marker_with_its_line_number(self) -> None:
        lines = ["## One", "TBD: fill this in", "content"]

        errors = check_sectioned_lines(lines, "doc.md", ["One"])

        self.assertEqual(["doc.md:2: unresolved TBD: 'TBD: fill this in'"], errors)

    def test_tbd_matching_is_case_insensitive_and_word_bounded(self) -> None:
        # "Tbd" should still match; "TBD9" or a word merely containing it should not.
        lines = ["## One", "content", "see Tbd here", "TBD9 is not a marker"]

        errors = check_sectioned_lines(lines, "doc.md", ["One"])

        self.assertEqual(["doc.md:3: unresolved TBD: 'see Tbd here'"], errors)


class CheckRunbookTests(unittest.TestCase):
    """The runbook is gated the same way deployment.md is: a section that quietly goes missing is a
    procedure nobody can follow during an incident, which is exactly when nobody will be reading a diff."""

    def _runbook(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runbook.md"
            path.write_text(text, encoding="utf-8")
            return check_runbook(path)

    def test_a_missing_runbook_is_an_error_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = check_runbook(Path(directory) / "runbook.md")

        self.assertEqual(1, len(errors))
        self.assertIn("file not found", errors[0])

    def test_every_required_section_with_content_passes(self) -> None:
        text = "".join(f"## {section}\ncontent\n" for section in REQUIRED_RUNBOOK_SECTIONS)

        self.assertEqual([], self._runbook(text))

    def test_a_dropped_section_is_reported(self) -> None:
        text = "".join(f"## {section}\ncontent\n" for section in REQUIRED_RUNBOOK_SECTIONS[:-1])

        errors = self._runbook(text)

        self.assertEqual([f"runbook.md: missing required section '{REQUIRED_RUNBOOK_SECTIONS[-1]}'"], errors)

    def test_a_heading_left_empty_is_reported(self) -> None:
        # A heading with nothing under it is the failure mode a "does the section exist" check would miss.
        text = f"## {REQUIRED_RUNBOOK_SECTIONS[0]}\n" + "".join(
            f"## {section}\ncontent\n" for section in REQUIRED_RUNBOOK_SECTIONS[1:])

        errors = self._runbook(text)

        self.assertEqual([f"runbook.md: section '{REQUIRED_RUNBOOK_SECTIONS[0]}' is empty"], errors)

    def test_the_gated_sections_are_the_ones_task_51_names(self) -> None:
        # Pinned so the gate cannot be weakened by deleting an entry along with the prose it guards.
        self.assertEqual(
            ["Restart Semantics", "Audit Log Retention", "PII and Windows Account Names", "Suspected Compromise"],
            REQUIRED_RUNBOOK_SECTIONS)


class CheckSecurityReviewTests(unittest.TestCase):
    """The review is the sign-off record for a release. A section silently missing from it means a release
    went out claiming a review that did not cover that ground."""

    def _review(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security-review.md"
            path.write_text(text, encoding="utf-8")
            return check_security_review(path)

    def test_a_missing_review_is_an_error_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = check_security_review(Path(directory) / "security-review.md")

        self.assertEqual(1, len(errors))
        self.assertIn("file not found", errors[0])

    def test_every_required_section_with_content_passes(self) -> None:
        text = "".join(f"## {section}\ncontent\n" for section in REQUIRED_SECURITY_REVIEW_SECTIONS)

        self.assertEqual([], self._review(text))

    def test_a_dropped_section_is_reported(self) -> None:
        text = "".join(f"## {section}\ncontent\n" for section in REQUIRED_SECURITY_REVIEW_SECTIONS[:-1])

        errors = self._review(text)

        self.assertEqual(
            [f"security-review.md: missing required section '{REQUIRED_SECURITY_REVIEW_SECTIONS[-1]}'"], errors)

    def test_a_findings_heading_left_empty_is_reported(self) -> None:
        # "Findings" with nothing under it is the one a reviewer in a hurry is most likely to leave behind.
        text = "".join(
            f"## {section}\n" if section == "Findings" else f"## {section}\ncontent\n"
            for section in REQUIRED_SECURITY_REVIEW_SECTIONS)

        self.assertEqual(["security-review.md: section 'Findings' is empty"], self._review(text))

    def test_the_gated_sections_are_the_ones_task_52_names(self) -> None:
        self.assertEqual(
            ["Scope and Method", "ASVS 4.0 Level 2", "Threat Register", "Security CI Results", "Findings",
             "Sign-off"],
            REQUIRED_SECURITY_REVIEW_SECTIONS)


if __name__ == "__main__":
    unittest.main()
