#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/pr_changes.py (OPS-004; ADR-1073). Run: python3 scripts/test_pr_changes.py"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("pr_changes", HERE / "pr_changes.py")
assert SPEC and SPEC.loader
pr_changes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_changes)

ALL = {"code": True, "ui": True, "native": True}
NONE = {"code": False, "ui": False, "native": False}


def nul(*paths: str) -> bytes:
    return b"".join(p.encode("utf-8") + b"\0" for p in paths)


class Classify(unittest.TestCase):
    def test_ops_004_docs(self):
        for p in (
            "spec/10-roadmap-and-tasks.md",
            "site/build.py",
            "scripts/ci_bench.py",
            "docs/design/cmdb.md",
            "docs/running.md",
            "docs/legal/terms.md",
            "docs/review/README.md",
            "docs/images/map-day.jpg",
            ".github/CODEOWNERS",
            ".github/workflows/ci.yml",
            ".github/dependabot.yml",
            "README.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "LICENSE-UPSTREAM-MIT",
            "NOTICE",
        ):
            self.assertEqual(pr_changes.classify(p), "DOCS", p)

    def test_ops_004_ui(self):
        for p in ("ui/src/App.svelte", "ui/package.json", ".spectral.yaml", "docs/help/topics.json"):
            self.assertEqual(pr_changes.classify(p), "UI", p)

    def test_ops_004_native(self):
        for p in ("deploy/compose/e2e.sh", "deploy/systemd/guided-e2e.sh", "deploy/grafana/build.py"):
            self.assertEqual(pr_changes.classify(p), "NATIVE", p)

    def test_ops_004_the_files_the_crates_read_are_code(self):
        for p in (
            "presets/devices.toml",
            "presets/oui.bin",
            "presets/categories/ads.txt",
            "brand/tokens.json",
            "docs/config-schema.json",
            "docs/recovery.md",
            "docs/examples/wrendns.toml",
            "ui/src/lib/alert-conditions.ts",
            "docs/api/openapi.json",
            "docs/api/mcp-tools.json",
            ".cargo/config.toml",
            "clippy.toml",
            "rustfmt.toml",
            "deploy/release/wrendns-release.pub",
            "deploy/systemd/install.sh",
            "crates/wrendns/src/main.rs",
            "bench/lists/x.txt",
            "Cargo.lock",
            "Makefile",
            ".github/workflows/pr.yml",
            ".github/scripts/apt-install.sh",
            "scripts/pr_changes.py",
            "scripts/pr_ok.py",
        ):
            self.assertEqual(pr_changes.classify(p), "CODE", p)

    def test_ops_004_unknown_paths_run_everything(self):
        for p in ("NEW-TOP-LEVEL-FILE", "newdir/file.md", "docs/new-dir/file.md", "docs/x.txt", "ct.yaml"):
            self.assertEqual(pr_changes.classify(p), "CODE", p)
        self.assertEqual(pr_changes.decide(["NEW-TOP-LEVEL-FILE"]), ALL)

    def test_ops_004_odd_characters(self):
        for p in ("docs/design/a b.md", "docs/design/café.md", 'docs/design/say "hi".md'):
            self.assertEqual(pr_changes.classify(p), "DOCS", p)
            self.assertEqual(pr_changes.decide([p]), NONE)
        self.assertEqual(pr_changes.classify('crates/a b/café "x".rs'), "CODE")
        # A path still wrapped in quotes (what core.quotePath would print) is unknown: CODE.
        self.assertEqual(pr_changes.classify('"docs/design/a.md"'), "CODE")


class Decide(unittest.TestCase):
    def test_ops_004_docs_only_is_all_false(self):
        self.assertEqual(pr_changes.decide(["README.md", "spec/11-decisions.md", "site/x.html"]), NONE)

    def test_ops_004_ui_only(self):
        self.assertEqual(
            pr_changes.decide(["ui/src/x.ts", "README.md"]), {"code": False, "ui": True, "native": False}
        )

    def test_ops_004_deploy_only(self):
        self.assertEqual(
            pr_changes.decide(["deploy/compose/compose.yaml"]), {"code": False, "ui": False, "native": True}
        )

    def test_ops_004_ui_and_deploy(self):
        self.assertEqual(
            pr_changes.decide(["ui/a.ts", "deploy/b.sh"]), {"code": False, "ui": True, "native": True}
        )

    def test_ops_004_code_runs_everything(self):
        self.assertEqual(pr_changes.decide(["README.md", "crates/a/src/lib.rs"]), ALL)

    def test_ops_004_empty_is_an_error(self):
        with self.assertRaises(ValueError):
            pr_changes.decide([])
        with self.assertRaises(ValueError):
            pr_changes.decide(["", ""])


def run(args: list[str], stdin: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(HERE / "pr_changes.py"), *args], input=stdin, capture_output=True
    )


class Cli(unittest.TestCase):
    def test_ops_004_output_lines(self):
        r = run([], nul("ui/a.ts", 'docs/design/café "x".md'))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode(), "code=false\nui=true\nnative=false\n")

    def test_ops_004_all(self):
        r = run(["--all"], b"")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode(), "code=true\nui=true\nnative=true\n")

    def test_ops_004_empty_input_fails(self):
        for data in (b"", b"\0", b"\0\0"):
            r = run([], data)
            self.assertEqual(r.returncode, 1, data)
            self.assertEqual(r.stdout, b"")

    def test_ops_004_bad_arguments(self):
        self.assertEqual(run(["--nope"], nul("README.md")).returncode, 2)

    def test_ops_004_main_in_process(self):
        self.assertEqual(pr_changes.main([], io.BytesIO(b"")), 1)

    def test_ops_004_non_utf8_path_is_docs_by_prefix(self):
        r = run([], b"docs/design/\xff.md\0")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode(), "code=false\nui=false\nnative=false\n")


if __name__ == "__main__":
    unittest.main()
