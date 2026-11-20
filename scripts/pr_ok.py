#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The verdict of the `pr-ok` job in .github/workflows/pr.yml (OPS-004, NFR-005; ADR-1073).

Reads the JSON of `toJSON(needs)` from the environment variable NEEDS_JSON (or from stdin when it
is not set): an object mapping each needed job to {"result": "...", "outputs": {...}}.

  exit 0  every needed job's result is `success` or `skipped`
  exit 1  some job's result is `failure`, `cancelled` or anything else; each one is named
  exit 2  the input is empty, malformed, not an object, or has an entry with no string result
          (never a pass: a verdict that cannot be read is not a green one)

A job skipped because its dependency failed is covered because that dependency is itself needed
by `pr-ok` and fails the verdict on its own.

Usage: NEEDS_JSON='{"fmt":{"result":"success"}}' python3 scripts/pr_ok.py
"""

from __future__ import annotations

import json
import os
import sys

PASSING = ("success", "skipped")


def verdict(text: str) -> tuple[int, list[str]]:
    """Return (exit code, message lines) for the JSON text of `needs`."""
    if not text.strip():
        return 2, ["pr-ok: no input: NEEDS_JSON is empty, so there is nothing to judge"]
    try:
        needs = json.loads(text)
    except json.JSONDecodeError as err:
        return 2, [f"pr-ok: the input is not valid JSON: {err}"]
    if not isinstance(needs, dict) or not needs:
        return 2, ["pr-ok: the input must be a non-empty JSON object of needed jobs"]
    bad: list[str] = []
    malformed: list[str] = []
    for job, entry in sorted(needs.items()):
        result = entry.get("result") if isinstance(entry, dict) else None
        if not isinstance(result, str):
            malformed.append(f"pr-ok: job {job} has no result")
        elif result not in PASSING:
            bad.append(f"pr-ok: job {job} finished with result {result}")
    if malformed:
        return 2, malformed + bad
    if bad:
        return 1, bad
    return 0, [f"pr-ok: {len(needs)} needed jobs, all success or skipped"]


def main() -> int:
    text = os.environ["NEEDS_JSON"] if "NEEDS_JSON" in os.environ else sys.stdin.read()
    code, lines = verdict(text)
    for line in lines:
        print(line, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
