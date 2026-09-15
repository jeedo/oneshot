#!/usr/bin/env python3
"""Tests for check_docs.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

import unittest

from check_docs import check_sectioned_lines


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


if __name__ == "__main__":
    unittest.main()
