#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""No `echo` or `printf` piped into `grep -q` in deploy/ and .github/ (OPS-004).

Under `set -o pipefail`, `producer | grep -q PATTERN` fails falsely when the producer writes more
than the pipe buffer (about 64 KiB): grep exits at its first match, the writer takes EPIPE, and the
pipeline fails although the pattern matched. A here-string has no pipe to break:

    grep -q PATTERN <<<"$X"          (not: echo "$X" | grep -q PATTERN)

The check reads the tracked files under deploy/ and .github/ and reports `path:line` for each
non-comment line where `echo` or `printf` comes before a pipe into `grep -q` (or `-qF`, `-qE`...).
A line whose first non-blank character is `#` is a comment and is skipped. Large-output producers
piped into `grep -q` are not caught here; they are reviewed by hand.

Usage: python3 scripts/check-pipefail.py [--root DIR]   (exit 1 lists the lines to fix)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PREFIXES = ("deploy/", ".github/")
# An echo or printf, then a pipe into grep with a -q flag (any flag group that contains q).
PIPED_GREP = re.compile(r"(echo|printf)[^|]*\|\s*grep -[a-zA-Z]*q")


def scanned(path: str) -> bool:
    return path.startswith(PREFIXES)


def hits(text: str) -> list[int]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if PIPED_GREP.search(line):
            found.append(number)
    return found


def git(root: Path, *args: str) -> list[str]:
    out = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout
    return [line for line in out.splitlines() if line]


def scan(root: Path) -> list[tuple[str, int, str]]:
    bad = []
    for path in git(root, "ls-files"):
        if not scanned(path):
            continue
        file = root / path
        if not file.is_file():
            continue
        lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
        for number in hits("\n".join(lines)):
            bad.append((path, number, lines[number - 1].strip()))
    return bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=None, help="the repository (default: the git top level)")
    args = ap.parse_args(argv)
    root = args.root or Path(git(Path.cwd(), "rev-parse", "--show-toplevel")[0])
    bad = scan(root)
    if bad:
        print(f"check-pipefail: {len(bad)} line(s) pipe echo or printf into grep -q (use a here-string):")
        for path, number, text in bad:
            print(f"  {path}:{number}: {text}")
        return 1
    checked = sum(1 for path in git(root, "ls-files") if scanned(path))
    print(f"check-pipefail: ok ({checked} tracked file(s) under deploy/ and .github/ checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
