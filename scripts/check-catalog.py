#!/usr/bin/env python3
"""Live check of the content-category catalog (REQ: FLT-901, ADR-995 section 3).

Run by the weekly `catalog-check` workflow, never by cargo test: the cargo tests read only the
metadata recorded in presets/categories/*.toml. This script asks GitHub, for each source's
repository, three things: the licence is the SPDX id the catalog records, the last push is within
90 days, and the repository is not archived. It also fetches the first bytes of each source and
compares the entry count in the file's own header with the catalog's (a drift over 50 % is
reported, so a list that was rewritten is noticed). It prints a Markdown report and exits 1 when
anything is stale, so the workflow can open an issue.

Usage: scripts/check-catalog.py [--api-base URL] [--no-headers]
The GitHub token, when there is one, is read from GH_TOKEN or GITHUB_TOKEN.
"""
import argparse
import datetime
import json
import os
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_AGE_DAYS = 90


def load_sources():
    out = []
    for f in sorted((ROOT / "presets" / "categories").glob("*.toml")):
        data = tomllib.loads(f.read_text(encoding="utf-8"))
        out.extend(data.get("source", []))
    return out


def repo_of(source):
    """owner/name for a source's homepage (a GitHub repository URL)."""
    m = re.match(r"https://github\.com/([^/]+/[^/]+?)/?$", source["homepage"])
    return m.group(1) if m else None


def get(url, token, limit=None):
    req = urllib.request.Request(url, headers={"User-Agent": "wrendns-catalog-check"})
    if token and "api.github.com" in url:
        req.add_header("Authorization", f"Bearer {token}")
    if limit:
        req.add_header("Range", f"bytes=0-{limit}")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(limit) if limit else r.read()


def header_entries(text):
    m = re.search(r"Number of (?:entries|unique domains)\s*:\s*([\d,]+)", text)
    return int(m.group(1).replace(",", "")) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", default="https://api.github.com")
    ap.add_argument("--no-headers", action="store_true")
    args = ap.parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    now = datetime.datetime.now(datetime.timezone.utc)
    problems, notes = [], []
    repos = {}
    for s in load_sources():
        repo = repo_of(s)
        if repo and repo not in repos:
            try:
                repos[repo] = json.loads(get(f"{args.api_base}/repos/{repo}", token))
            except Exception as e:  # network or rate limit: report, do not guess
                repos[repo] = {"error": str(e)}
        info = repos.get(repo, {})
        if "error" in info:
            problems.append(f"{s['id']}: cannot read {repo}: {info['error']}")
            continue
        spdx = (info.get("license") or {}).get("spdx_id")
        if spdx != s["licence"]:
            problems.append(f"{s['id']}: licence is {spdx}, the catalog records {s['licence']}")
        if info.get("archived"):
            problems.append(f"{s['id']}: {repo} is archived")
        pushed = datetime.datetime.fromisoformat(info["pushed_at"].replace("Z", "+00:00"))
        age = (now - pushed).days
        if age > MAX_AGE_DAYS:
            problems.append(f"{s['id']}: last push {age} days ago (limit {MAX_AGE_DAYS})")
        if not args.no_headers and s.get("resolve") is None:
            try:
                head = get(s["url"], None, limit=3000).decode("utf-8", "replace")
                n = header_entries(head)
                if n and abs(n - s["entries"]) * 2 > s["entries"]:
                    notes.append(f"{s['id']}: header says {n} entries, the catalog has {s['entries']}")
            except Exception as e:
                problems.append(f"{s['id']}: cannot fetch {s['url']}: {e}")
    print("# Content-category catalog check\n")
    if problems:
        print("## Needs attention\n")
        for p in problems:
            print(f"- {p}")
    if notes:
        print("\n## Counts that drifted\n")
        for n in notes:
            print(f"- {n}")
    if not problems and not notes:
        print("Every source is licensed as recorded, pushed within 90 days and not archived.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
