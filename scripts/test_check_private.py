#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/check-private.py (DOC-006). Run: python3 scripts/test_check_private.py

Every pattern here is synthetic; none is a real identifier.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_private", HERE / "check-private.py")
assert SPEC and SPEC.loader
cp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cp)

DENYLIST = "# synthetic patterns\n\nzebra-wombat\nregex:(?i)\\bquokka\\d+\\b\nregex:10\\.99\\.(?!0\\.)\\d+\\.\\d+\n"


def run(argv: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cp.main(argv, env)
    return code, out.getvalue(), err.getvalue()


class Parse(unittest.TestCase):
    def test_doc_006_comments_and_blanks_are_skipped(self):
        self.assertEqual(len(cp.parse_denylist(DENYLIST)), 3)

    def test_doc_006_literal_is_exact_and_case_sensitive(self):
        [p] = cp.parse_denylist("a.b(c)\n")
        self.assertTrue(p.search("see a.b(c) here"))
        self.assertFalse(p.search("see axb(c) here"))
        self.assertFalse(p.search("see A.B(C) here"))

    def test_doc_006_regex_lines_keep_their_flags_and_lookarounds(self):
        _, quokka, net = cp.parse_denylist(DENYLIST)
        self.assertTrue(quokka.search("the QUOKKA42 host"))
        self.assertFalse(quokka.search("quokkas"))
        self.assertTrue(net.search("at 10.99.7.1"))
        self.assertFalse(net.search("at 10.99.0.1"))

    def test_doc_006_bad_regex_error_names_the_index_not_the_pattern(self):
        with self.assertRaises(cp.DenylistError) as ctx:
            cp.parse_denylist("fine\nregex:secret-(unclosed\n")
        self.assertIn("#2", str(ctx.exception))
        self.assertNotIn("secret", str(ctx.exception))

    def test_doc_006_escaped_spelling_is_found(self):
        pats = cp.parse_denylist(DENYLIST)
        escaped = "expect(url).toMatch(/host=10" + "\\\\." + "99" + "\\\\." + "4" + "\\\\." + "5/)"
        self.assertEqual(cp.scan_text(escaped, pats), [(1, 3)])
        self.assertEqual(cp.scan_text('"zebra\\\\-wombat"', pats), [(1, 1)])
        self.assertEqual(cp.spellings("no escapes here"), ["no escapes here"])

    def test_doc_006_text_patterns_number_after_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp, "deny.txt")
            f.write_text("one\ntwo\n", encoding="utf-8")
            pats = cp.load_patterns({cp.ENV_FILE: str(f), cp.ENV_TEXT: "three\n"})
        assert pats is not None
        self.assertEqual([p.pattern for p in pats], ["one", "two", "three"])

    def test_doc_006_nothing_set_means_none(self):
        self.assertIsNone(cp.load_patterns({}))
        self.assertIsNone(cp.load_patterns({cp.ENV_FILE: " ", cp.ENV_TEXT: "\n"}))

    def test_doc_006_only_comments_is_an_error(self):
        with self.assertRaises(cp.DenylistError):
            cp.load_patterns({cp.ENV_TEXT: "# nothing\n"})


class Scan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.write("clean.md", "nothing to see\n")
        self.write("dirty.md", "line one\nhost zebra-wombat here\nand Quokka7 too\n")
        self.write("untracked.md", "zebra-wombat but not tracked\n")
        self.write("blob.bin", "zebra-wombat", binary=True)
        subprocess.run(["git", "-C", str(self.root), "add", "clean.md", "dirty.md", "blob.bin"], check=True)
        # Built and generated output that git ignores is still scanned.
        self.write("site/_site/index.html", "<p>10.99.3.4</p>\n")
        self.write("docs/api/gen.json", '{"x": "zebra-wombat"}\n')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel: str, text: str, binary: bool = False):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(b"\0\0" + text.encode())
        else:
            path.write_text(text, encoding="utf-8")

    def test_doc_006_files_to_scan(self):
        files = cp.files_to_scan(self.root, [])
        self.assertIn("dirty.md", files)
        self.assertIn("site/_site/index.html", files)
        self.assertIn("docs/api/gen.json", files)
        self.assertNotIn("untracked.md", files)

    def test_doc_006_report_names_file_line_and_index_only(self):
        code, out, err = run(["--root", str(self.root)], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 1)
        lines = out.splitlines()
        self.assertEqual(
            sorted(lines),
            sorted([
                "dirty.md:2: pattern #1",
                "dirty.md:3: pattern #2",
                "docs/api/gen.json:1: pattern #1",
                "site/_site/index.html:1: pattern #3",
            ]),
        )
        for needle in ("zebra", "wombat", "quokka", "Quokka", "10.99", "10\\.99"):
            self.assertNotIn(needle, out + err)

    def test_doc_006_extra_dir(self):
        self.write("build/out.txt", "zebra-wombat\n")
        code, out, _ = run(["--root", str(self.root), "--extra", "build"], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 1)
        self.assertIn("build/out.txt:1: pattern #1", out)

    def test_doc_006_clean_tree_passes(self):
        code, out, _ = run(["--root", str(self.root)], {cp.ENV_TEXT: "absent-token\n"})
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_doc_006_skips_without_a_denylist(self):
        code, out, _ = run(["--root", str(self.root)], {})
        self.assertEqual(code, 0)
        self.assertIn("skipped", out)

    def test_doc_006_required_without_a_denylist_fails(self):
        code, _, err = run(["--root", str(self.root), "--require"], {})
        self.assertEqual(code, 2)
        self.assertIn("required", err)
        code, _, _ = run(["--root", str(self.root)], {cp.ENV_REQUIRED: "true"})
        self.assertEqual(code, 2)
        code, _, _ = run(["--root", str(self.root)], {cp.ENV_REQUIRED: "false"})
        self.assertEqual(code, 0)

    def test_doc_006_required_with_a_denylist_scans(self):
        code, out, _ = run(["--root", str(self.root), "--require"], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 1)
        self.assertIn("dirty.md:2: pattern #1", out)

    def test_doc_006_extra_outside_root_is_an_error_without_a_pattern(self):
        with tempfile.TemporaryDirectory() as other:
            Path(other, "x.txt").write_text("zebra-wombat\n", encoding="utf-8")
            code, out, err = run(["--root", str(self.root), "--extra", other], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 2)
        self.assertIn("inside --root", err)
        for needle in ("zebra", "wombat", "quokka", "Traceback"):
            self.assertNotIn(needle, out + err)

    def test_doc_006_unreadable_file_is_an_error_without_the_path(self):
        missing = str(self.root / "no-such-denylist.txt")
        code, _, err = run(["--root", str(self.root)], {cp.ENV_FILE: missing})
        self.assertEqual(code, 2)
        self.assertNotIn("no-such-denylist", err)


if __name__ == "__main__":
    unittest.main()
