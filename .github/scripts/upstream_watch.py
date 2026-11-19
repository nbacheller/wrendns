#!/usr/bin/env python3
"""REQ: OPS-004, DOC-006. Daily watch on paimonsoror/telltaledns for the fork.

Reads the ledger spec/upstream.md from the checkout, then: lists upstream commits since the
last sync and flags any that touch a fork deviation, the numbering files or the image gate;
runs a trial merge in a scratch worktree (nothing is committed); lists upstream issues
changed in the last week against the triaged block. The report goes into one fork issue
titled "Upstream watch" (created by the github-actions bot). A comment is added only when
the report's hash changes; the comment is posted before the body is edited.

Standard library only; calls git and gh. Run from the repo root (or anywhere in it).
--dry-run prints the report and the intended issue action and writes nothing to GitHub.
It fetches upstream into the local object store and uses a temporary worktree.
"""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = "spec/upstream.md"
UPSTREAM = "paimonsoror/telltaledns"
UPSTREAM_URL = "https://github.com/paimonsoror/telltaledns"
FORK = "nbacheller/wrendns"
WATCH_TITLE = "Upstream watch"
WATCH_AUTHORS = {"github-actions", "github-actions[bot]", "app/github-actions"}
WINDOW_DAYS = 7
MAX_ROWS = 100          # table rows per section; the rest are counted, not listed
MAX_TITLE = 200         # upstream titles and subjects are cut to this many characters
MAX_BODY = 50000        # GitHub rejects issue bodies over 65,536 characters
MARKER_RE = re.compile(r"<!-- watch-hash: ([0-9a-f]{64}) -->")
# Characters that Markdown would render as markup (mentions, links, images, HTML, issue refs).
MD_SPECIAL = re.compile(r"([\\`*_\[\]<>@|#!~&])")

# Always flagged: task and ADR numbers (spec/10, spec/11) and the image gate (ADR-916).
ALWAYS_FLAG = [
    ("numbering", ["spec/10-roadmap-and-tasks.md", "spec/11-decisions.md"]),
    ("image-gate", ["Cargo.toml", "Cargo.lock", "Dockerfile"]),
]


def run(args, cwd=None, check=True):
    """Run a command and return its stdout."""
    res = subprocess.run(args, cwd=cwd or ROOT, capture_output=True, text=True,
                         encoding="utf-8", errors="replace")
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {res.stderr.strip()}")
    return res.stdout


def glob_regex(glob):
    """Turn a repo glob into a regex: ** crosses directories, * and ? do not."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif glob[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile("^" + out + "$")


def ledger_block(text, tag):
    """The non-empty lines of the fenced block tagged `tag`."""
    m = re.search(r"^```" + tag + r"\n(.*?)^```", text, re.S | re.M)
    if not m:
        raise SystemExit(f"{LEDGER}: no ```{tag} block")
    return [line for line in m.group(1).splitlines() if line.strip()]


def read_ledger():
    text = (ROOT / LEDGER).read_text(encoding="utf-8")
    synced = re.search(r"^upstream-synced: ([0-9a-f]{7,40})$", text, re.M)
    if not synced:
        raise SystemExit(f"{LEDGER}: no 'upstream-synced:' line")
    rules = []
    for line in ledger_block(text, "deviations"):
        name, globs = line.split("\t")
        rules.append((name, [glob_regex(g.strip()) for g in globs.split(",") if g.strip()]))
    triaged = {}
    for line in ledger_block(text, "triaged"):
        number, updated = line.split("\t")
        triaged[int(number)] = updated
    return synced.group(1), rules, triaged


def is_ancestor(old, new):
    """True when `old` is an ancestor of `new`. An unknown sha or a git error counts as no."""
    res = subprocess.run(["git", "merge-base", "--is-ancestor", old, new], cwd=ROOT,
                         capture_output=True, text=True)
    return res.returncode == 0


def new_commits(synced, head):
    """Upstream commits in synced..head, oldest first, each with its changed files."""
    out = run(["git", "log", "--reverse", "--format=%H%x09%h%x09%s", f"{synced}..{head}"])
    commits = []
    for line in out.splitlines():
        if not line.strip():
            continue
        full, short, subject = line.split("\t", 2)
        # -z: NUL-separated, so paths with spaces or non-ASCII characters come through unquoted.
        raw = run(["git", "show", "-z", "--format=", "--name-only", "--first-parent", full])
        files = [f.lstrip("\n") for f in raw.split("\0") if f.strip()]
        commits.append((short, subject, files))
    return commits


def flags_for(files, rules):
    hits = set()
    for name, regexes in rules:
        if any(r.match(f) for f in files for r in regexes):
            hits.add(name)
    return sorted(hits)


def trial_merge(head, upstream_sha):
    """Merge upstream into a scratch worktree without committing; return the conflicted paths.

    A merge that stops with conflicts exits 1 and lists the unmerged paths. A merge that fails
    with no unmerged paths (unrelated histories, a bad object) is an error, not "no conflicts".
    """
    tmp = Path(tempfile.mkdtemp(prefix="upstream-watch-"))
    scratch = tmp / "tree"
    try:
        run(["git", "worktree", "add", "--detach", str(scratch), head])
        res = subprocess.run(["git", "-c", "user.email=watch@localhost", "-c", "user.name=watch",
                              "merge", "--no-commit", "--no-ff", upstream_sha],
                             cwd=scratch, capture_output=True, text=True,
                             encoding="utf-8", errors="replace")
        conflicts = run(["git", "diff", "--name-only", "--diff-filter=U"], cwd=scratch).split()
        if res.returncode != 0 and not conflicts:
            raise RuntimeError(f"trial merge failed: {res.stderr.strip() or res.stdout.strip()}")
        return conflicts
    finally:
        if scratch.exists():
            subprocess.run(["git", "merge", "--abort"], cwd=scratch, capture_output=True)
            run(["git", "worktree", "remove", "--force", str(scratch)], check=False)
        shutil.rmtree(tmp, ignore_errors=True)


def recent_issues(triaged, now):
    """Upstream issues updated in the window that are new or whose updated_at changed."""
    since = (now - datetime.timedelta(days=WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = run(["gh", "api", "--paginate", f"repos/{UPSTREAM}/issues", "-X", "GET",
               "-f", "state=all", "-f", "per_page=100", "-f", f"since={since}",
               "--jq", ".[] | select(.pull_request|not) | {number, updated_at, state, title}"])
    rows = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        it = json.loads(line)
        old = triaged.get(it["number"])
        if old is None:
            rows.append((it, "new"))
        elif old != it["updated_at"]:
            rows.append((it, f"changed (was {old})"))
    return rows


def cell(text, limit=MAX_TITLE):
    """Upstream text as plain table text: one line, cut to `limit`, with Markdown markup escaped."""
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[:limit - 3] + "..."
    return MD_SPECIAL.sub(r"\\\1", text)


def capped(rows, lines):
    """Append at most MAX_ROWS table rows, then a plain line counting the rest (ends the table)."""
    lines += rows[:MAX_ROWS]
    if len(rows) > MAX_ROWS:
        lines += ["", f"+{len(rows) - MAX_ROWS} more, not listed."]
    return lines


def build_report(synced, upstream_sha, commits, conflicts, issue_rows, note):
    flagged = [c for c in commits if c[3]]
    summary = (f"**{len(commits)} new commits, {len(flagged)} flagged, {len(conflicts)} conflicts, "
               f"{len(issue_rows)} new/changed issues** "
               f"(synced {synced}, upstream main {upstream_sha[:7]})")
    lines = [summary, ""]
    if note:
        lines += [f"> **Warning:** {cell(note, limit=1000)}", ""]
    lines += ["### Upstream commits", ""]
    if commits:
        rows = [f"| `{short}` | {cell(subject)} | {', '.join(flags) or '-'} |"
                for short, subject, _, flags in commits]
        lines += ["| commit | subject | flags |", "|---|---|---|"]
        lines = capped(rows, lines)
    else:
        lines.append("No new upstream commits.")
    lines += ["", "### Trial merge", ""]
    lines += [f"- conflict: {cell(path)}" for path in conflicts[:MAX_ROWS]] or ["No conflicts."]
    if len(conflicts) > MAX_ROWS:
        lines.append(f"- +{len(conflicts) - MAX_ROWS} more, not listed")
    lines += ["", "### Upstream issues", ""]
    if issue_rows:
        rows = []
        for it, change in issue_rows:
            link = f"[#{it['number']}]({UPSTREAM_URL}/issues/{it['number']})"
            rows.append(f"| {link} | {cell(it['title'])} | {cell(it['state'])} | {cell(change)} |")
        lines += ["| # | title | state | change |", "|---|---|---|---|"]
        lines = capped(rows, lines)
    else:
        lines.append("No new or changed issues in the last 7 days.")
    return summary, "\n".join(lines)


def find_watch_issue():
    """The fork's watch issue: this title, opened by the bot. Plain list, not search (the search
    index lags, which let a second run create a duplicate); any author other than the bot is ignored."""
    out = run(["gh", "issue", "list", "-R", FORK, "--state", "all", "--limit", "1000",
               "--json", "number,title,body,state,author"])
    matches = [it for it in json.loads(out)
               if it["title"] == WATCH_TITLE
               and ((it.get("author") or {}).get("login") in WATCH_AUTHORS)]
    return min(matches, key=lambda it: it["number"]) if matches else None


def make_body(digest, report, today):
    """The hash marker is the first line, so a marker-looking text later in the body cannot win."""
    body = report
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY] + "\n\n_Report cut short to fit the issue size limit; see the workflow log._"
    return (f"<!-- watch-hash: {digest} -->\n{body}\n\n"
            f"_Last checked {today} by the upstream watch workflow; ledger: spec/upstream.md._\n")


def write_issue(report, summary, dry_run):
    digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    body = make_body(digest, report, today)
    existing = find_watch_issue()
    prev = None
    if existing:
        m = MARKER_RE.search(existing.get("body") or "")
        prev = m.group(1) if m else None
    changed = prev != digest
    if existing is None:
        action = f"create issue '{WATCH_TITLE}' in {FORK} (label upstream)"
    elif changed:
        reopen = ", reopen it" if existing["state"] != "OPEN" else ""
        action = f"comment on issue #{existing['number']} (report changed), then update its body{reopen}"
    else:
        action = f"update issue #{existing['number']} body only (no change; no comment)"
    if dry_run:
        return action
    run(["gh", "label", "create", "upstream", "-R", FORK, "--force",
         "--color", "0E8A16", "--description", "Upstream watch and sync"])
    if existing is None:
        run(["gh", "issue", "create", "-R", FORK, "--title", WATCH_TITLE,
             "--label", "upstream", "--body", body])
        return action
    number = str(existing["number"])
    if changed:
        # Comment first: if the comment fails, the old hash stays and the next run notifies again.
        run(["gh", "issue", "comment", number, "-R", FORK,
             "--body", f"Upstream watch changed: {summary}"])
        if existing["state"] != "OPEN":
            run(["gh", "issue", "reopen", number, "-R", FORK])
    run(["gh", "issue", "edit", number, "-R", FORK, "--body", body])
    return action


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--dry-run", action="store_true",
                    help="print the report and the intended issue action; write nothing to GitHub")
    args = ap.parse_args()

    synced, deviations, triaged = read_ledger()
    run(["git", "fetch", UPSTREAM_URL, "main"])
    upstream_sha = run(["git", "rev-parse", "FETCH_HEAD"]).strip()
    head = run(["git", "rev-parse", "HEAD"]).strip()

    note = None
    commits = []
    if is_ancestor(synced, upstream_sha):
        rules = [(name, [glob_regex(p) for p in paths]) for name, paths in ALWAYS_FLAG] + deviations
        commits = [(short, subject, files, flags_for(files, rules))
                   for short, subject, files in new_commits(synced, upstream_sha)]
    else:
        note = (f"ledger sha {synced} is not an ancestor of upstream main (history rewritten?). "
                "The commit list is empty; check the upstream history by hand, then update upstream-synced.")
    conflicts = trial_merge(head, upstream_sha) if (commits or note) else []
    issue_rows = recent_issues(triaged, datetime.datetime.now(datetime.timezone.utc))

    summary, report = build_report(synced, upstream_sha, commits, conflicts, issue_rows, note)
    action = write_issue(report, summary, args.dry_run)
    print(report)
    print()
    print(("Intended issue action (dry run): " if args.dry_run else "Issue action taken: ") + action)


if __name__ == "__main__":
    main()
