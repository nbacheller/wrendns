#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CI timing: cold and warm wall time and hosted minutes per run (OPS-004, NFR-001; ADR-1073, T39.12).

Every speed number of the CI milestone (M39) is measured with this tool, so that the numbers
compare. It reads workflow runs through the `gh` CLI (which must be installed and signed in) and
prints, for one workflow on one branch, or for a list of run ids:

  cold         the wall time of the first run (an empty cache), from the run's start to its last update
  warm median  the median wall time of the next three runs (a warm cache); fewer runs give a
               median of what there is, and the tool says how many
  hosted min   per run, the minutes billed on GitHub-hosted runners: each job on a hosted runner is
               rounded up to a whole minute, jobs on self-hosted runners are not counted

Only completed runs are used, oldest first. The repository is `gh`'s current repository, or the
one named by --repo.

Usage:
  python3 scripts/ci_bench.py pr --branch speed/ci-pr-tier
  python3 scripts/ci_bench.py --run-id 111 --run-id 222 --run-id 333 --run-id 444 --repo OWNER/NAME
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
from datetime import datetime

WARM_RUNS = 3


def parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def wall_seconds(run: dict) -> float | None:
    """Seconds from the start of a run to its last update, or None while it is not complete."""
    start, end = run.get("run_started_at"), run.get("updated_at")
    if not start or not end or run.get("status") not in (None, "completed"):
        return None
    return (parse_ts(end) - parse_ts(start)).total_seconds()


def job_seconds(job: dict) -> float | None:
    start, end = job.get("started_at"), job.get("completed_at")
    if not start or not end:
        return None
    return max(0.0, (parse_ts(end) - parse_ts(start)).total_seconds())


def is_hosted(job: dict) -> bool:
    """A job ran on a GitHub-hosted runner when its labels do not include `self-hosted`."""
    return "self-hosted" not in (job.get("labels") or [])


def hosted_minutes(jobs: list[dict]) -> int:
    """Billed minutes: each completed job on a hosted runner, rounded up to a whole minute."""
    total = 0
    for job in jobs:
        secs = job_seconds(job)
        if secs is None or job.get("conclusion") == "skipped" or not is_hosted(job):
            continue
        total += max(1, math.ceil(secs / 60))
    return total


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def summarize(runs: list[dict]) -> dict:
    """Cold, warm median and hosted minutes for runs given oldest first.

    Each item is {"id": ..., "run": <run record>, "jobs": [<job records>]}.
    """
    walls = [(r["id"], wall_seconds(r["run"]), hosted_minutes(r["jobs"])) for r in runs]
    walls = [w for w in walls if w[1] is not None]
    warm = [w[1] for w in walls[1 : 1 + WARM_RUNS]]
    return {
        "runs": [{"id": i, "wall": w, "hosted_minutes": m} for i, w, m in walls],
        "cold": walls[0][1] if walls else None,
        "warm_median": median(warm),
        "warm_count": len(warm),
    }


def fmt(secs: float | None) -> str:
    if secs is None:
        return "-"
    secs = int(round(secs))
    return f"{secs // 60}m{secs % 60:02d}s"


def report(summary: dict) -> str:
    lines = ["run id          wall      hosted min"]
    for r in summary["runs"]:
        lines.append(f"{r['id']!s:<15} {fmt(r['wall']):<9} {r['hosted_minutes']}")
    lines.append("")
    lines.append(f"cold wall time        {fmt(summary['cold'])}")
    lines.append(f"warm wall median      {fmt(summary['warm_median'])}  (of {summary['warm_count']} warm runs)")
    if summary["warm_count"] < WARM_RUNS:
        lines.append(f"note: {WARM_RUNS} warm runs are asked for; fewer were found")
    return "\n".join(lines)


def gh_json(*args: str):
    done = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"gh {' '.join(args[:2])} failed: {done.stderr.strip()}")
    return json.loads(done.stdout)


def current_repo() -> str:
    return gh_json("repo", "view", "--json", "nameWithOwner")["nameWithOwner"]


def fetch_run(repo: str, run_id: int | str) -> dict:
    run = gh_json("api", f"repos/{repo}/actions/runs/{run_id}")
    jobs = gh_json("api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]
    return {"id": run["id"], "run": run, "jobs": jobs}


def list_run_ids(repo: str, workflow: str, branch: str | None, limit: int) -> list[int]:
    path = f"repos/{repo}/actions/workflows/{workflow}.yml/runs?status=completed&per_page={limit}"
    if branch:
        path += f"&branch={branch}"
    runs = gh_json("api", path)["workflow_runs"]
    return [r["id"] for r in sorted(runs, key=lambda r: r["created_at"])]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cold and warm CI wall time and hosted minutes per run.")
    ap.add_argument("workflow", nargs="?", help="workflow name, as in .github/workflows/NAME.yml (e.g. pr)")
    ap.add_argument("--branch", help="only runs on this branch")
    ap.add_argument("--run-id", action="append", default=[], help="a run id; repeat, oldest first (instead of a workflow)")
    ap.add_argument("--repo", help="OWNER/NAME; default: gh's current repository")
    ap.add_argument("--limit", type=int, default=1 + WARM_RUNS, help="newest completed runs to read (default %(default)s)")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args(argv)
    if not args.workflow and not args.run_id:
        ap.error("give a workflow name or at least one --run-id")
    repo = args.repo or current_repo()
    ids: list = args.run_id or list_run_ids(repo, args.workflow, args.branch, args.limit)
    if not ids:
        sys.exit("no completed runs found")
    summary = summarize([fetch_run(repo, i) for i in ids])
    print(json.dumps(summary, indent=1) if args.json else report(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
