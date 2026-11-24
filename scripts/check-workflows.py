#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The workflow rules of ADR-1080 (T39.11), checked on .github/workflows/*.yml (OPS-004, NFR-005).

1. Pinned actions: every `uses:` that is not a local `./` path is pinned to a full 40-hex commit SHA
   and names its version in a comment on the same line (`uses: owner/name@<sha> # v1.2.3`), so a
   moved tag cannot change what runs with a secret.
2. Checkouts: every `actions/checkout` step sets `persist-credentials` itself. `false` is the rule;
   `true` is for a job that pushes or reads the remote with the checkout's credentials, and the
   workflow says why in a comment next to it.
3. Permissions: every job sets its own `permissions:` (a reusable-workflow caller too), so no job
   gets more than it names.
4. No untrusted expression in a script: a `${{ }}` inside a `run:` or a github-script `script:` body
   may use only the contexts in SAFE_CONTEXTS (runner facts and the run's own numbers). Anything
   else (an event field, an input, a matrix value, a step or job output, a secret) goes through
   `env:` and a quoted shell variable.

The reader is line based (no YAML library), so it runs on any runner and in the tests.

Usage: python3 scripts/check-workflows.py [--root DIR]   (exit 1 lists `path:line: rule: text`)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
USES = re.compile(r"^(\s*)(- )?uses:\s*(\S+)(\s*#\s*(\S.*))?\s*$")
KEY_BLOCK = re.compile(r"^(\s*)(?:- )?(run|script):\s*(\|[-+]?|>[-+]?)?\s*(.*)$")
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)
STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")
DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_*-]+)+")

# Contexts whose value no outside party chooses: the runner's own facts and this run's numbers.
SAFE_CONTEXTS = {
    "runner.environment", "runner.os", "runner.arch", "runner.temp", "runner.name",
    "github.sha", "github.run_id", "github.run_number", "github.run_attempt",
    "github.workflow", "github.job", "github.workspace", "github.repository", "github.server_url",
}


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def is_blank_or_comment(line: str) -> bool:
    s = line.strip()
    return s == "" or s.startswith("#")


def unsafe_contexts(expression: str) -> list[str]:
    """The dotted contexts in one `${{ }}` body that are not in SAFE_CONTEXTS."""
    bare = STRING_LITERAL.sub("''", expression)
    return [c for c in DOTTED.findall(bare) if c not in SAFE_CONTEXTS]


def step_bounds(lines: list[str], i: int, key_indent: int) -> tuple[int, int]:
    """First and one-past-last line of the step whose `uses:` is at line i."""
    start = i
    if not re.match(r"^\s*- ", lines[i]):
        j = i - 1
        while j >= 0 and not (indent_of(lines[j]) == key_indent - 2 and lines[j].lstrip().startswith("- ")):
            j -= 1
        start = max(j, 0)
    end = i + 1
    while end < len(lines) and (is_blank_or_comment(lines[end]) or indent_of(lines[end]) >= key_indent):
        end += 1
    return start, end


def check_text(text: str) -> list[tuple[int, str, str]]:
    """(line number, rule, the line) for each problem in one workflow's text."""
    lines = text.split("\n")
    bad: list[tuple[int, str, str]] = []

    def flag(n: int, rule: str) -> None:
        bad.append((n + 1, rule, lines[n].strip()))

    in_jobs = False
    job_start: int | None = None
    job_has_permissions = False

    def close_job() -> None:
        if job_start is not None and not job_has_permissions:
            flag(job_start, "permissions: the job sets no `permissions:` of its own")

    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
        elif in_jobs and re.match(r"^\S", line) and not line.startswith("#"):
            close_job()
            job_start, in_jobs = None, False
        if in_jobs:
            if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
                close_job()
                job_start, job_has_permissions = i, False
            elif job_start is not None and re.match(r"^    permissions:", line):
                job_has_permissions = True

        m = USES.match(line)
        if m:
            indent, dash, ref, _, version = m.groups()
            key_indent = len(indent) + (2 if dash else 0)
            if not ref.startswith("./"):
                if not SHA_PIN.match(ref):
                    flag(i, "pin: not pinned to a full 40-hex commit SHA")
                elif not version:
                    flag(i, "pin: no version comment after the SHA")
            if ref.startswith("actions/checkout@"):
                a, b = step_bounds(lines, i, key_indent)
                if not any(re.search(r"persist-credentials\s*:", ln) for ln in lines[a:b]):
                    flag(i, "checkout: `persist-credentials` is not set")

        b = KEY_BLOCK.match(line)
        if b:
            indent, _, style, inline = b.groups()
            body = [inline] if inline and not style else []
            if style:
                j = i + 1
                while j < len(lines) and (lines[j].strip() == "" or indent_of(lines[j]) > len(indent) + (2 if line.lstrip().startswith("- ") else 0)):
                    body.append(lines[j])
                    j += 1
            for chunk in body:
                if chunk.lstrip().startswith("#"):
                    continue
                for e in EXPR.finditer(chunk):
                    bad_ctx = unsafe_contexts(e.group(1))
                    if bad_ctx:
                        flag(i, "injection: `${{ %s }}` in a script body (use env: and a quoted variable)" % ", ".join(bad_ctx))
                        break
        i += 1
    close_job()
    return bad


def scan(root: Path) -> list[tuple[str, int, str, str]]:
    found = []
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        for n, rule, text in check_text(path.read_text(encoding="utf-8")):
            found.append((path.relative_to(root).as_posix(), n, rule, text))
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                    help="the repository (default: this script's repository)")
    args = ap.parse_args(argv)
    found = scan(args.root)
    if found:
        print(f"check-workflows: {len(found)} problem(s) in .github/workflows:")
        for path, n, rule, text in found:
            print(f"  {path}:{n}: {rule}: {text}")
        return 1
    count = len(list((args.root / ".github" / "workflows").glob("*.yml")))
    print(f"check-workflows: ok ({count} workflow file(s): pins, checkouts, job permissions, script bodies)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
