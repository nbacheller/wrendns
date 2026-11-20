#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which parts of a pull request changed (the `changes` job of .github/workflows/pr.yml; OPS-004,
NFR-005; ADR-1073).

Reads the changed paths from stdin, separated by NUL (the workflow pipes
`git -c core.quotePath=false diff -z --name-only --no-renames "$BASE_SHA" HEAD`), and prints three
lines for $GITHUB_OUTPUT: `code=true|false`, `ui=true|false`, `native=true|false`. `--all` prints all
three as true without reading anything (workflow_dispatch).

Every path is exactly one of:

  DOCS    affects no job (the explicit list below, each entry checked: see DOCS_RULES)
  UI      read by the ui job only
  NATIVE  read by the native-lite job only
  CODE    everything else

UNKNOWN PATHS RUN EVERYTHING. CODE is the default for any path no explicit rule matches, so a new
directory or file the lists do not know runs every job. `code` is true when any path is CODE; `ui` is
true when `code` is true or any path is UI; `native` is true when `code` is true or any path is NATIVE.

  exit 0  the three lines were printed
  exit 1  the input holds no path (an empty diff is an error, never "nothing changed")
  exit 2  bad arguments
"""

from __future__ import annotations

import re
import sys

# Paths the crates read at build or test time (include_str!, include_bytes!, env!("CARGO_MANIFEST_DIR")
# joins) and other files the heavy jobs read. They sit inside a directory that is otherwise UI,
# NATIVE or DOCS, so they are matched first and are CODE. (Found by searching crates/, ui/, deploy/,
# the Makefile, deny.toml and the Dockerfile for include_str!, include_bytes!, include!, build.rs and
# relative-path reads.)
CODE_RULES = (
    "ui/src/lib/alert-conditions.ts",  # wrendns-config tests/config.rs include_str!
    "deploy/release/wrendns-release.pub",  # wrendns selfupdate_tests.rs reads it
    "deploy/systemd/install.sh",  # wrendns selfupdate_tests.rs reads it
    "docs/api/",  # openapi.json include_str! in wrendns-api; mcp-tools.json read by its tests
    "docs/config-schema.json",  # wrendns-config guarded.rs include_str!, tests/config.rs
    "docs/recovery.md",  # wrendns-config guarded.rs include_str!
    "docs/examples/",  # wrendns-config tests/config.rs include_str! of wrendns.toml
    "scripts/pr_changes.py",  # the classification itself: a change to it changes what is tested
    "scripts/pr_ok.py",  # the pr-ok verdict, likewise
)

# Read only by the ui job: ui/ (its build and tests), the OpenAPI lint ruleset, and the help
# glossary that the UI imports (ui/src/lib/help.ts, ui/scripts/check-help.mjs; no crate reads it).
UI_RULES = ("ui/", ".spectral.yaml", "docs/help/")

# Read only by the native-lite job (the Compose bundle, the installer and the systemd unit).
NATIVE_RULES = ("deploy/",)

# DOCS: a short explicit list. Nothing in crates/, bench/, fuzz/, ui/, deploy/, the Makefile,
# deny.toml or the Dockerfile reads these at build or test time (the search above found only the
# CODE and UI paths). The site, privacy and trace checks do read spec/, site/ and docs/, but they run
# on every pull request.
DOCS_RULES = (
    "spec/",
    "site/",
    "scripts/",  # except the two CODE_RULES entries, which are matched first
    "docs/design/",
    "docs/legal/",
    "docs/review/",
    "docs/images/",
    ".github/",  # except NOT_DOCS
)
# Markdown directly in docs/ (docs/recovery.md is a CODE rule, matched first) and at the root, and
# the licence files at the root.
DOCS_PATTERNS = (
    re.compile(r"docs/[^/]+\.md"),
    re.compile(r"[^/]+\.md"),
    re.compile(r"LICENSE[^/]*"),
    re.compile(r"NOTICE"),
)
# Inside .github/, but run or read by a job: not DOCS (so CODE).
NOT_DOCS = (".github/workflows/pr.yml", ".github/scripts/")


def _under(path: str, rules: tuple[str, ...]) -> bool:
    return any(path == r or (r.endswith("/") and path.startswith(r)) for r in rules)


def classify(path: str) -> str:
    """Return "DOCS", "UI", "NATIVE" or "CODE" for one repository path. The default is CODE."""
    if _under(path, CODE_RULES):
        return "CODE"
    if _under(path, UI_RULES):
        return "UI"
    if _under(path, NATIVE_RULES):
        return "NATIVE"
    if not _under(path, NOT_DOCS) and (
        _under(path, DOCS_RULES) or any(p.fullmatch(path) for p in DOCS_PATTERNS)
    ):
        return "DOCS"
    return "CODE"


def decide(paths: list[str]) -> dict[str, bool]:
    """The three outputs for a non-empty list of paths. Raises ValueError on an empty list."""
    paths = [p for p in paths if p]
    if not paths:
        raise ValueError("no changed paths: an empty diff is an error, not 'nothing changed'")
    classes = {classify(p) for p in paths}
    code = "CODE" in classes
    return {
        "code": code,
        "ui": code or "UI" in classes,
        "native": code or "NATIVE" in classes,
    }


def render(outputs: dict[str, bool]) -> str:
    return "".join(f"{k}={'true' if outputs[k] else 'false'}\n" for k in ("code", "ui", "native"))


def emit(outputs: dict[str, bool]) -> None:
    # Bytes with a plain LF: $GITHUB_OUTPUT wants LF lines, whatever the platform's text mode.
    sys.stdout.buffer.write(render(outputs).encode("ascii"))
    sys.stdout.buffer.flush()


def main(argv: list[str], stdin) -> int:
    if argv == ["--all"]:
        emit({"code": True, "ui": True, "native": True})
        return 0
    if argv:
        print("usage: pr_changes.py [--all]  (NUL-separated paths on stdin)", file=sys.stderr)
        return 2
    paths = [p.decode("utf-8", "surrogateescape") for p in stdin.read().split(b"\0")]
    try:
        outputs = decide(paths)
    except ValueError as e:
        print(f"::error title=changes::{e}", file=sys.stderr)
        return 1
    emit(outputs)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], sys.stdin.buffer))
