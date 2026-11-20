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


LEAKS = ("zebra", "wombat", "quokka", "Quokka", "10.99", "10\\.99")


class History(unittest.TestCase):
    """--history (DOC-006): a temporary repository whose history is built by each test."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name, "repo")
        self.root.mkdir()
        self.git("init", "-q", "-b", "main")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args: str, cwd: Path | None = None) -> str:
        cmd = ["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid",
               "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "core.autocrlf=false",
               *args]
        return subprocess.run(
            cmd, cwd=cwd or self.root, check=True, capture_output=True, text=True, encoding="utf-8"
        ).stdout.strip()

    def commit(self, files: dict[str, str | None], message: str = "work") -> str:
        """Writes (or, for None, removes) files, commits, and returns the 12-hex commit."""
        for rel, text in files.items():
            path = self.root / rel
            if text is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")[:12]

    def history(self, text: str = DENYLIST, *extra: str) -> tuple[int, str, str]:
        return run(["--root", str(self.root), "--history", *extra], {cp.ENV_TEXT: text})

    def assert_safe(self, out: str, err: str):
        for needle in LEAKS + ("Traceback",):
            self.assertNotIn(needle, out + err)

    def test_doc_006_history_finds_text_removed_by_a_later_commit(self):
        old = self.commit({"notes.txt": "fine\nhost zebra-wombat here\n"})
        self.commit({"notes.txt": "fine\n"})
        code, out, err = self.history()
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"commit {old} notes.txt: pattern #1"])
        self.assertIn("1 history hit(s)", err)
        self.assert_safe(out, err)
        # The tree scan does not see it: the text is gone from the working tree.
        code, out, _ = run(["--root", str(self.root)], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 0)

    def test_doc_006_history_clean_exits_zero(self):
        self.commit({"a.txt": "one\n"}, "first")
        self.commit({"a.txt": "two\n"}, "second")
        code, out, err = self.history()
        self.assertEqual(code, 0)
        self.assertIn("2 commit(s) clean", out)
        self.assertEqual(err, "")

    def test_doc_006_history_skips_without_a_list_and_requires_on_demand(self):
        self.commit({"a.txt": "one\n"})
        code, out, _ = run(["--root", str(self.root), "--history"], {})
        self.assertEqual((code, "skipped" in out), (0, True))
        code, _, err = run(["--root", str(self.root), "--history", "--require"], {})
        self.assertEqual((code, "required" in err), (2, True))

    def test_doc_006_history_extra_is_a_bad_argument(self):
        self.commit({"a.txt": "one\n"})
        with self.assertRaises(SystemExit) as ctx:
            run(["--root", str(self.root), "--history", "--extra", "x"], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(ctx.exception.code, 2)

    def test_doc_006_history_commit_message_only(self):
        sha = self.commit({"a.txt": "harmless\n"}, "subject mentions zebra-wombat\n\nbody line")
        code, out, err = self.history()
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"commit {sha} message: pattern #1"])
        self.assert_safe(out, err)

    def test_doc_006_history_message_body_is_scanned(self):
        sha = self.commit({"a.txt": "harmless\n"}, "plain subject\n\nsee Quokka9 for details")
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {sha} message: pattern #2"]))
        self.assert_safe(out, err)

    def test_doc_006_history_branch_name_only(self):
        sha = self.commit({"a.txt": "harmless\n"})
        self.git("branch", "feature/zebra-wombat-work")
        code, out, err = self.history()
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"ref -> {sha}: pattern #1"])
        self.assert_safe(out, err)

    def test_doc_006_history_tag_name_only(self):
        sha = self.commit({"a.txt": "harmless\n"})
        self.git("tag", "release-zebra-wombat")
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"ref -> {sha}: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_annotated_tag_reports_its_commit(self):
        sha = self.commit({"a.txt": "harmless\n"})
        self.git("tag", "-a", "-m", "release", "v-zebra-wombat")
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"ref -> {sha}: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_remote_tracking_ref_name(self):
        sha = self.commit({"a.txt": "harmless\n"})
        self.git("update-ref", "refs/remotes/origin/zebra-wombat", "HEAD")
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"ref -> {sha}: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_side_branch_that_is_not_head(self):
        self.commit({"a.txt": "base\n"})
        self.git("switch", "-q", "-c", "side")
        side = self.commit({"b.txt": "Quokka12 on the side\n"})
        self.git("switch", "-q", "main")
        self.commit({"a.txt": "main moves on\n"})
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {side} b.txt: pattern #2"]))
        self.assert_safe(out, err)

    def test_doc_006_history_detached_head_is_scanned(self):
        self.commit({"a.txt": "base\n"})
        self.git("switch", "-q", "--detach")
        sha = self.commit({"b.txt": "zebra-wombat\n"})
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {sha} b.txt: pattern #1"]))

    def test_doc_006_history_regex_pattern_and_lookahead(self):
        a = self.commit({"net.txt": "at 10.99.7.1\nat 10.99.0.1\n"})
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {a} net.txt: pattern #3"]))
        self.assert_safe(out, err)

    def test_doc_006_history_backslash_escaped_spelling(self):
        sha = self.commit({"esc.txt": 'name = "zebra\\-wombat"\n'})
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {sha} esc.txt: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_one_line_per_commit_path_and_pattern(self):
        sha = self.commit({"a.txt": "zebra-wombat\nzebra-wombat again\nQuokka3\n"})
        code, out, _ = self.history()
        self.assertEqual(
            out.splitlines(), [f"commit {sha} a.txt: pattern #1", f"commit {sha} a.txt: pattern #2"]
        )

    def test_doc_006_history_matching_path_is_withheld(self):
        sha = self.commit({"docs/zebra-wombat.txt": "clean content\n"})
        code, out, err = self.history()
        self.assertEqual(code, 1)
        self.assertEqual(out.splitlines(), [f"commit {sha} <path withheld>: pattern #1"])
        self.assert_safe(out, err)

    def test_doc_006_history_matching_path_with_matching_content_is_one_withheld_line(self):
        sha = self.commit({"zebra-wombat.txt": "zebra-wombat inside\n"})
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {sha} <path withheld>: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_deleted_path_is_still_found(self):
        added = self.commit({"old/quokka5.cfg": ""}, "add")
        self.commit({"old/quokka5.cfg": None}, "remove")
        code, out, err = self.history()
        self.assertEqual(code, 1)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn(f"commit {added} <path withheld>: pattern #2", lines)
        self.assert_safe(out, err)

    def test_doc_006_history_path_with_spaces_and_non_ascii_is_reported_whole(self):
        sha = self.commit({"sp ace/ünï.txt": "zebra-wombat\n"})
        code, out, _ = self.history()
        self.assertEqual(out.splitlines(), [f"commit {sha} sp ace/ünï.txt: pattern #1"])

    def test_doc_006_unquote_path(self):
        self.assertEqual(cp.unquote_path('"a\\tb\\303\\251\\"\\\\"'), 'a\tbé"\\')
        self.assertEqual(cp.unquote_path("plain"), "plain")
        self.assertEqual(cp.diff_path("+++ b/dir/file.txt"), "dir/file.txt")
        self.assertEqual(cp.diff_path("+++ b/with space.txt\t"), "with space.txt")
        self.assertIsNone(cp.diff_path("+++ /dev/null"))

    def test_doc_006_history_added_line_imitating_the_marker_does_not_confuse_the_parser(self):
        fake = "0" * 40
        text = (
            f"{cp.MARKER}{fake}\n"
            f"{cp.MARKER}deadbeef{fake}\n"
            "+++ b/innocent.txt\n"
            "diff --git a/x b/x\n"
            "@@ -1 +1 @@\n"
            "zebra-wombat\n"
        )
        sha = self.commit({"plant.txt": text})
        later = self.commit({"later.txt": "Quokka4\n"})
        code, out, err = self.history()
        self.assertEqual(code, 1)
        self.assertEqual(
            sorted(out.splitlines()),
            sorted([f"commit {sha} plant.txt: pattern #1", f"commit {later} later.txt: pattern #2"]),
        )
        self.assertNotIn("000000000000", out)
        self.assertNotIn("innocent", out)
        self.assert_safe(out, err)

    def test_doc_006_history_marker_lookalike_alone_is_clean(self):
        self.commit({"plant.txt": f"{cp.MARKER}{'0' * 40}\n+++ b/other.txt\n"})
        code, out, _ = self.history()
        self.assertEqual(code, 0)

    def test_doc_006_history_binary_changes_are_skipped(self):
        self.commit({"keep.txt": "ok\n"})
        (self.root / "blob.bin").write_bytes(b"\0\0zebra-wombat\0")
        self.git("add", "blob.bin")
        self.git("commit", "-q", "-m", "binary")
        code, out, err = self.history()
        self.assertEqual(code, 0)

    def test_doc_006_history_merge_resolution_text_is_seen(self):
        self.commit({"f.txt": "base\n"})
        self.git("switch", "-q", "-c", "side")
        self.commit({"f.txt": "side change\n"})
        self.git("switch", "-q", "main")
        self.commit({"f.txt": "main change\n"})
        merge = subprocess.run(
            ["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid", "merge", "side"],
            cwd=self.root, capture_output=True, text=True,
        )
        self.assertNotEqual(merge.returncode, 0)  # a conflict, resolved by hand below
        (self.root / "f.txt").write_text("resolved with zebra-wombat\n", encoding="utf-8", newline="\n")
        self.git("add", "f.txt")
        self.git("commit", "-q", "-m", "merge side")
        resolved = self.head()
        code, out, err = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {resolved} f.txt: pattern #1"]))
        self.assert_safe(out, err)

    def test_doc_006_history_clean_merge_does_not_repeat_the_side_lines(self):
        self.commit({"f.txt": "one\ntwo\nthree\n"})
        self.git("switch", "-q", "-c", "side")
        side = self.commit({"g.txt": "Quokka8\n"})
        self.git("switch", "-q", "main")
        self.commit({"f.txt": "one\ntwo\nthree\nfour\n"})
        self.git("merge", "-q", "--no-ff", "-m", "merge side", "side")
        code, out, _ = self.history()
        self.assertEqual(out.splitlines(), [f"commit {side} g.txt: pattern #2"])

    def test_doc_006_history_shallow_clone_fails(self):
        self.commit({"a.txt": "one\n"})
        self.commit({"a.txt": "zebra-wombat\n"})
        self.commit({"a.txt": "three\n"})
        shallow = Path(self.tmp.name, "shallow")
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1", self.root.as_uri(), str(shallow)],
            check=True, capture_output=True,
        )
        code, out, err = run(["--root", str(shallow), "--history"], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 2)
        self.assertIn("shallow", err)
        self.assertEqual(out, "")
        self.assert_safe(out, err)

    def test_doc_006_history_git_failure_is_an_error_not_a_pass(self):
        not_a_repo = Path(self.tmp.name, "plain")
        not_a_repo.mkdir()
        code, out, err = run(["--root", str(not_a_repo), "--history"], {cp.ENV_TEXT: DENYLIST})
        self.assertEqual(code, 2)
        self.assertNotIn("clean", out)
        self.assert_safe(out, err)

    def test_doc_006_history_corrupt_object_is_an_error_without_git_output(self):
        self.commit({"a.txt": "zebra-wombat\n"})
        blob = self.git("rev-parse", "HEAD:a.txt")
        obj = self.root / ".git" / "objects" / blob[:2] / blob[2:]
        obj.chmod(0o600)
        obj.write_bytes(b"garbage")
        code, out, err = self.history()
        self.assertEqual(code, 2)
        self.assertNotIn("clean", out)
        self.assert_safe(out, err)

    def test_doc_006_history_streams_in_chunks(self):
        # Records and lines that straddle the 64 KiB read size are reassembled intact.
        sha = self.commit({"big.txt": ("x" * 200 + "\n") * 2000 + "zebra-wombat\n"})
        code, out, _ = self.history()
        self.assertEqual((code, out.splitlines()), (1, [f"commit {sha} big.txt: pattern #1"]))


if __name__ == "__main__":
    unittest.main()
