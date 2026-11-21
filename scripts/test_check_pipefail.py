#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/check-pipefail.py (OPS-004). Run: python3 scripts/test_check_pipefail.py"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_pipefail", HERE / "check-pipefail.py")
assert SPEC and SPEC.loader
pipefail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipefail)


class Lines(unittest.TestCase):
    def test_ops_004_piped_echo_and_printf_are_hits(self):
        self.assertEqual(pipefail.hits('echo "$x" | grep -q y\n'), [1])
        self.assertEqual(pipefail.hits("printf '%s\\n' \"$x\" | grep -qF y\n"), [1])
        self.assertEqual(pipefail.hits('echo "$x" | grep -Eq "^[0-9]+$"\n'), [1])

    def test_ops_004_here_string_and_other_pipes_pass(self):
        self.assertEqual(pipefail.hits('grep -q y <<<"$x"\n'), [])
        self.assertEqual(pipefail.hits('curl -s http://x | grep -q y\n'), [])
        self.assertEqual(pipefail.hits('echo "$x" | head -c 300\n'), [])

    def test_ops_004_comment_lines_are_skipped(self):
        self.assertEqual(pipefail.hits('# echo "$x" | grep -q y\n'), [])
        self.assertEqual(pipefail.hits('    # echo "$x" | grep -q y\n'), [])
        self.assertEqual(pipefail.hits('x=1 # echo "$x" | grep -q y\n'), [1])


class Repo(unittest.TestCase):
    """End to end in a throwaway git repository: only tracked files under deploy/ and .github/."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git("init", "-q")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, env=self.env, capture_output=True)

    def write(self, rel, text, track=True):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        if track:
            self.git("add", rel)

    def run_check(self):
        return subprocess.run([sys.executable, str(HERE / "check-pipefail.py"), "--root", str(self.root)],
                              cwd=self.root, capture_output=True, text=True, env=self.env)

    def test_ops_004_clean_tree_passes(self):
        self.write("deploy/ok.sh", '#!/usr/bin/env bash\nset -euo pipefail\ngrep -q y <<<"$x" || exit 1\n')
        self.write(".github/workflows/main.yml", "jobs:\n  t:\n    steps:\n      - run: echo hi\n")
        res = self.run_check()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("check-pipefail: ok", res.stdout)

    def test_ops_004_piped_echo_fails_and_names_path_and_line(self):
        self.write("deploy/bad.sh", '#!/usr/bin/env bash\nset -euo pipefail\necho "$x" | grep -q y || exit 1\n')
        res = self.run_check()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("deploy/bad.sh:3", res.stdout)

    def test_ops_004_comment_with_the_same_text_passes(self):
        self.write("deploy/commented.sh", '# echo "$x" | grep -q y  (the old form, kept as a note)\n')
        self.assertEqual(self.run_check().returncode, 0)

    def test_ops_004_here_string_form_passes(self):
        self.write("deploy/here.sh", 'grep -q y <<<"$x"\n')
        self.assertEqual(self.run_check().returncode, 0)

    def test_ops_004_printf_is_caught_in_workflows(self):
        self.write(".github/workflows/x.yml", "      - run: printf '%s\\n' \"$x\" | grep -qF y\n")
        res = self.run_check()
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn(".github/workflows/x.yml:1", res.stdout)

    def test_ops_004_other_trees_and_untracked_files_are_not_checked(self):
        self.write("scripts/tool.sh", 'echo "$x" | grep -q y\n')
        self.write("deploy/untracked.sh", 'echo "$x" | grep -q y\n', track=False)
        self.assertEqual(self.run_check().returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
