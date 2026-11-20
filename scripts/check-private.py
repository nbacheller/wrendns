#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fails when a tracked or built file matches a maintainer's private denylist (DOC-006).

Maintainers keep a private list of identifiers that must never appear in the repository, the
built site or the generated docs (personal names, home addresses and networks, device names,
private hostnames and so on). The list is not in the repository, and this script contains none
of its entries: it reads them at run time from

    WRENDNS_PRIVACY_DENYLIST       a path to the denylist file
    WRENDNS_PRIVACY_DENYLIST_TEXT  the denylist itself (how CI passes a secret)

Both may be set; their patterns are combined (the file's first). With neither set, the check
is skipped with a notice and exits 0, so contributors without the list are not blocked, unless
`--require` is given or WRENDNS_PRIVACY_REQUIRED is `true`: then a missing list fails (exit 2).
CI requires it on the maintainers' own repository and before every site deploy.

Denylist format, one pattern per line:

    some literal text          matched exactly (case-sensitive)
    regex:PATTERN              a Python regular expression (put (?i) in it for case-insensitive)
    # a comment                ignored, as are blank lines

What is scanned: every file `git ls-files` lists, plus the built site in site/_site when it
exists, plus every JSON file under docs/ (the generated API, MCP, config and help files), even
before it is committed. Binary files are skipped. Each line is matched as written and, when it has
backslash escapes, once more with them removed, so an identifier written inside a regular
expression or an escaped string (each dot written as backslash-dot) is still found.

A hit is reported as `path:line: pattern #N`, where N is the 1-based position of the pattern
among the loaded patterns (comments and blank lines are not counted). The pattern and the
matched text are never printed, so the report can sit in a public CI log.

Usage: python3 scripts/check-private.py [--root DIR] [--extra DIR ...] [--require]
(exit 1 on any hit, 2 on a missing or unusable list when required, or a bad argument)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ENV_FILE = "WRENDNS_PRIVACY_DENYLIST"
ENV_TEXT = "WRENDNS_PRIVACY_DENYLIST_TEXT"
ENV_REQUIRED = "WRENDNS_PRIVACY_REQUIRED"
REGEX_PREFIX = "regex:"
# Built or generated output that is scanned even though git does not track it.
EXTRA_TREES = ("site/_site",)
EXTRA_GLOBS = (("docs", "**/*.json"),)
# How much of a file is sniffed for a NUL byte to decide it is binary.
SNIFF = 8192


class DenylistError(Exception):
    """A denylist that cannot be used. The message never contains a pattern."""


def parse_denylist(text: str, start: int = 1) -> list[re.Pattern[str]]:
    """Compiles one pattern per non-blank, non-comment line. `start` numbers the first one."""
    patterns: list[re.Pattern[str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        index = start + len(patterns)
        if line.startswith(REGEX_PREFIX):
            source = line[len(REGEX_PREFIX):]
            if not source:
                raise DenylistError(f"pattern #{index} is an empty regex")
            try:
                patterns.append(re.compile(source))
            except re.error:
                # The re.error text quotes the pattern, so it is not passed on.
                raise DenylistError(f"pattern #{index} is not a valid regular expression") from None
        else:
            patterns.append(re.compile(re.escape(line)))
    return patterns


def load_patterns(env: dict[str, str]) -> list[re.Pattern[str]] | None:
    """The combined patterns from the environment, or None when neither variable is set."""
    path = env.get(ENV_FILE, "").strip()
    text = env.get(ENV_TEXT, "")
    if not path and not text.strip():
        return None
    patterns: list[re.Pattern[str]] = []
    if path:
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            raise DenylistError(f"{ENV_FILE} names a file that cannot be read") from None
        patterns += parse_denylist(content)
    if text.strip():
        patterns += parse_denylist(text, start=len(patterns) + 1)
    if not patterns:
        raise DenylistError("the denylist has no patterns")
    return patterns


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]


def extra_files(root: Path, extra_dirs: list[str]) -> list[str]:
    found: list[str] = []
    root = root.resolve()
    for tree in list(EXTRA_TREES) + extra_dirs:
        base = (root / tree).resolve()
        if not base.is_relative_to(root):
            raise DenylistError("an --extra directory must be inside --root")
        if base.is_dir():
            found += [p.relative_to(root).as_posix() for p in base.rglob("*") if p.is_file()]
    for directory, pattern in EXTRA_GLOBS:
        base = root / directory
        if base.is_dir():
            found += [p.relative_to(root).as_posix() for p in base.glob(pattern) if p.is_file()]
    return found


def files_to_scan(root: Path, extra_dirs: list[str]) -> list[str]:
    return sorted(set(tracked_files(root)) | set(extra_files(root, extra_dirs)))


def read_text(path: Path) -> str | None:
    """The file's text, or None for a binary, missing or unreadable file."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:SNIFF]:
        return None
    return data.decode("utf-8", errors="replace")


# One or more backslashes before punctuation, as in a regular expression or an escaped string.
ESCAPED = re.compile(r"\\+([^\w\s\\])")


def spellings(line: str) -> list[str]:
    """The line as written, plus the line with escapes removed when it has any, so an
    identifier written inside a regex or a JSON string is still found."""
    plain = ESCAPED.sub(r"\1", line)
    return [line] if plain == line else [line, plain]


def scan_text(text: str, patterns: list[re.Pattern[str]]) -> list[tuple[int, int]]:
    """(line number, pattern number) for every pattern that matches a line, both 1-based."""
    hits: list[tuple[int, int]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        forms = spellings(line)
        for index, pattern in enumerate(patterns, 1):
            if any(pattern.search(form) for form in forms):
                hits.append((lineno, index))
    return hits


def scan(root: Path, files: list[str], patterns: list[re.Pattern[str]]) -> list[str]:
    report: list[str] = []
    for rel in files:
        text = read_text(root / rel)
        if text is None:
            continue
        for lineno, index in scan_text(text, patterns):
            report.append(f"{rel}:{lineno}: pattern #{index}")
    return report


def main(argv: list[str] | None = None, env: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None, help="repository root (default: the git top level)")
    parser.add_argument(
        "--extra", action="append", default=[], help="another directory to scan (repeatable)"
    )
    parser.add_argument(
        "--require",
        action="store_true",
        help=f"fail when no denylist is set (also: {ENV_REQUIRED}=true)",
    )
    args = parser.parse_args(argv)
    env = dict(os.environ) if env is None else env

    try:
        patterns = load_patterns(env)
    except DenylistError as err:
        print(f"check-private: {err}", file=sys.stderr)
        return 2
    required = args.require or env.get(ENV_REQUIRED, "").strip().lower() == "true"
    if patterns is None and required:
        message = f"check-private: required, but neither {ENV_FILE} nor {ENV_TEXT} is set"
        print(f"::error::{message}" if env.get("GITHUB_ACTIONS") == "true" else message, file=sys.stderr)
        return 2
    if patterns is None:
        message = f"check-private: skipped, neither {ENV_FILE} nor {ENV_TEXT} is set"
        # A GitHub Actions notice, so a run without the secret says so on the summary page.
        print(f"::notice::{message}" if env.get("GITHUB_ACTIONS") == "true" else message)
        return 0

    if args.root:
        root = Path(args.root).resolve()
    else:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], check=True, capture_output=True, text=True
        ).stdout.strip()
        root = Path(top)

    try:
        files = files_to_scan(root, args.extra)
    except DenylistError as err:
        print(f"check-private: {err}", file=sys.stderr)
        return 2
    report = scan(root, files, patterns)
    if report:
        print("\n".join(report))
        print(
            f"check-private: {len(report)} hit(s) in {len({r.rsplit(':', 2)[0] for r in report})}"
            f" file(s) against {len(patterns)} pattern(s); generalize them (see CONTRIBUTING.md)",
            file=sys.stderr,
        )
        return 1
    print(f"check-private: {len(files)} file(s) clean against {len(patterns)} pattern(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
