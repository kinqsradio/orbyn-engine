#!/usr/bin/env python3
"""Tests for the title check that CI runs on every pull request and issue."""

import unittest

from check_title import MAX_TITLE_CHARS, check


class AcceptedTitles(unittest.TestCase):
    def test_the_forms_the_repository_uses_pass(self):
        for title in [
            "feat(web): resize the preview page from its device toolbar",
            "fix(core): keep the composer focused after a send",
            "docs: require conventional titles for pull requests and issues",
            "chore(deps): bump the cargo-minor-and-patch group with 4 updates",
            "ci: run the web checks on the oldest supported node",
            "refactor(service): move the render routes beside previews",
            "revert(web): drop the gallery counter",
            "feat(core)!: rename the render route",
            "fix(web): web/src/generated stays in the same commit",
            "feat(web): support 3d previews",
            "fix(web): 3d previews keep their size",
        ]:
            with self.subTest(title=title):
                self.assertEqual(check(title, "pr"), [], title)

    def test_an_issue_may_ask_a_question(self):
        self.assertEqual(check("question: does the preview keep its token?", "issue"), [])

    def test_whitespace_around_the_title_is_ignored(self):
        self.assertEqual(check("  fix(web): trim the title  ", "pr"), [])


class RefusedTitles(unittest.TestCase):
    def test_an_uppercase_summary_is_refused(self):
        for kind in ("pr", "issue"):
            for title in (
                "fix: Keep focus",
                "feat(web)!: Rename the preview",
                "docs: Éviter les doublons",
            ):
                with self.subTest(kind=kind, title=title):
                    self.assertTrue(check(title, kind), title)

    def test_a_sentence_case_title_is_refused(self):
        problems = check("Resize the preview page from its device toolbar", "pr")
        self.assertTrue(any("type(scope): summary" in problem for problem in problems), problems)

    def test_an_unknown_kind_names_the_ones_that_work(self):
        problems = check("feature(web): add a gallery", "pr")
        self.assertTrue(any("`feature` is not a kind" in problem for problem in problems), problems)

    def test_a_trailing_full_stop_is_refused(self):
        problems = check("fix(web): keep the focus.", "pr")
        self.assertTrue(any("full stop" in problem for problem in problems), problems)

    def test_a_kind_without_a_summary_is_refused(self):
        problems = check("fix(web):", "pr")
        self.assertTrue(problems)

    def test_the_length_cap_is_exact(self):
        fits = "fix(web): " + "a" * (MAX_TITLE_CHARS - len("fix(web): "))
        self.assertEqual(check(fits, "pr"), [])
        self.assertTrue(check(fits + "a", "pr"))

    def test_attribution_is_refused(self):
        self.assertTrue(check("fix(web): keep focus co-authored-by: someone", "pr"))
        self.assertTrue(check("feat(web): a gallery written by claude", "pr"))
        self.assertTrue(check("fix(web): repair the panel with codex", "pr"))

    def test_a_subject_may_still_be_an_engine_or_a_model(self):
        # Naming what the change is about is not attribution.
        self.assertEqual(check("feat(web): show the claude usage limit", "pr"), [])
        self.assertEqual(check("fix(codex): wait for tools before the first turn", "pr"), [])

    def test_a_question_is_not_a_pull_request_kind(self):
        problems = check("question: why is this here", "pr")
        self.assertTrue(any("not a kind" in problem for problem in problems), problems)

    def test_an_empty_title_is_refused(self):
        self.assertEqual(check("   ", "pr"), ["The title is empty."])


if __name__ == "__main__":
    unittest.main()
