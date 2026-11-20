#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/pr_ok.py (OPS-004; ADR-1073). Run: python3 scripts/test_pr_ok.py"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pr_ok", HERE / "pr_ok.py")
assert SPEC and SPEC.loader
pr_ok = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_ok)


def needs(**results: str) -> str:
    return json.dumps({job: {"result": r, "outputs": {}} for job, r in results.items()})


class Verdict(unittest.TestCase):
    def test_ops_004_all_success(self):
        code, _ = pr_ok.verdict(needs(changes="success", fmt="success", site="success"))
        self.assertEqual(code, 0)

    def test_ops_004_success_and_skipped(self):
        code, _ = pr_ok.verdict(needs(changes="success", fmt="skipped", ui="skipped", site="success"))
        self.assertEqual(code, 0)

    def test_ops_004_one_failure_is_named(self):
        code, lines = pr_ok.verdict(needs(changes="success", fmt="success", clippy="failure"))
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 1)
        self.assertIn("clippy", lines[0])
        self.assertNotIn("fmt", lines[0])

    def test_ops_004_one_cancelled(self):
        code, lines = pr_ok.verdict(needs(changes="success", test="cancelled"))
        self.assertEqual(code, 1)
        self.assertIn("test", lines[0])

    def test_ops_004_unknown_result_fails(self):
        code, lines = pr_ok.verdict(needs(changes="success", fmt="neutral"))
        self.assertEqual(code, 1)
        self.assertIn("neutral", lines[0])

    def test_ops_004_every_offender_is_named(self):
        code, lines = pr_ok.verdict(needs(fmt="failure", deny="cancelled", site="success", ui="weird"))
        self.assertEqual(code, 1)
        self.assertEqual(len(lines), 3)

    def test_ops_004_changes_failed_everything_else_skipped(self):
        results = {
            "changes": "failure", "fmt": "skipped", "clippy": "skipped", "test": "skipped",
            "deny": "skipped", "ui": "skipped", "native-lite": "skipped",
            "site": "success", "privacy": "success",
        }
        code, lines = pr_ok.verdict(needs(**results))
        self.assertEqual(code, 1)
        self.assertIn("changes", lines[0])

    def test_ops_004_empty_object_is_an_error(self):
        code, _ = pr_ok.verdict("{}")
        self.assertEqual(code, 2)

    def test_ops_004_empty_and_blank_input_is_an_error(self):
        for text in ["", "  \n"]:
            code, _ = pr_ok.verdict(text)
            self.assertEqual(code, 2, repr(text))

    def test_ops_004_malformed_json_is_an_error(self):
        for text in ["{not json", '{"fmt": {"result": "success"}', "null", "[]", '"success"']:
            code, _ = pr_ok.verdict(text)
            self.assertEqual(code, 2, text)

    def test_ops_004_entry_without_a_result_is_an_error(self):
        for text in ['{"fmt": {}}', '{"fmt": "success"}', '{"fmt": {"result": null}}', '{"fmt": {"result": 1}}']:
            code, _ = pr_ok.verdict(text)
            self.assertEqual(code, 2, text)


class Cli(unittest.TestCase):
    def run_cli(self, env_text: str | None, stdin: str = "") -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != "NEEDS_JSON"}
        if env_text is not None:
            env["NEEDS_JSON"] = env_text
        return subprocess.run(
            [sys.executable, str(HERE / "pr_ok.py")], input=stdin, env=env, capture_output=True, text=True
        )

    def test_ops_004_cli_reads_the_environment(self):
        self.assertEqual(self.run_cli(needs(fmt="success")).returncode, 0)
        self.assertEqual(self.run_cli(needs(fmt="failure")).returncode, 1)

    def test_ops_004_cli_reads_stdin_without_the_variable(self):
        self.assertEqual(self.run_cli(None, needs(fmt="success")).returncode, 0)
        self.assertEqual(self.run_cli(None, needs(fmt="cancelled")).returncode, 1)
        self.assertEqual(self.run_cli(None, "").returncode, 2)

    def test_ops_004_cli_empty_variable_is_an_error(self):
        self.assertEqual(self.run_cli("").returncode, 2)


if __name__ == "__main__":
    unittest.main()
