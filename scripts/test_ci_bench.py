#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/ci_bench.py (OPS-004; T39.12), on canned records, with no network.
Run: python3 scripts/test_ci_bench.py"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ci_bench", HERE / "ci_bench.py")
assert SPEC and SPEC.loader
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def run(start: str, end: str, status: str = "completed") -> dict:
    return {"run_started_at": f"2026-11-20T{start}Z", "updated_at": f"2026-11-20T{end}Z", "status": status}


def job(start: str, end: str, labels=None, conclusion="success") -> dict:
    return {
        "started_at": f"2026-11-20T{start}Z",
        "completed_at": f"2026-11-20T{end}Z",
        "labels": labels if labels is not None else ["ubuntu-latest"],
        "conclusion": conclusion,
    }


class Arithmetic(unittest.TestCase):
    def test_ops_004_wall_seconds(self):
        self.assertEqual(bench.wall_seconds(run("10:00:00", "10:12:30")), 750.0)
        self.assertIsNone(bench.wall_seconds(run("10:00:00", "10:12:30", status="in_progress")))
        self.assertIsNone(bench.wall_seconds({"updated_at": "2026-11-20T10:00:00Z"}))

    def test_ops_004_median(self):
        self.assertEqual(bench.median([5.0, 1.0, 3.0]), 3.0)
        self.assertEqual(bench.median([4.0, 2.0]), 3.0)
        self.assertIsNone(bench.median([]))

    def test_ops_004_hosted_minutes_round_each_job_up(self):
        jobs = [job("10:00:00", "10:00:10"), job("10:00:00", "10:02:01"), job("10:00:00", "10:01:00")]
        self.assertEqual(bench.hosted_minutes(jobs), 1 + 3 + 1)

    def test_ops_004_hosted_minutes_skip_self_hosted_and_skipped(self):
        jobs = [
            job("10:00:00", "10:10:00", labels=["self-hosted", "linux"]),
            job("10:00:00", "10:05:00", conclusion="skipped"),
            {"started_at": None, "completed_at": None, "labels": ["ubuntu-latest"]},
            job("10:00:00", "10:04:00"),
        ]
        self.assertEqual(bench.hosted_minutes(jobs), 4)

    def test_ops_004_format(self):
        self.assertEqual(bench.fmt(None), "-")
        self.assertEqual(bench.fmt(750), "12m30s")
        self.assertEqual(bench.fmt(59.6), "1m00s")


class Summary(unittest.TestCase):
    def item(self, rid: int, start: str, end: str, jobs=None) -> dict:
        return {"id": rid, "run": run(start, end), "jobs": jobs or [job("10:00:00", "10:03:00")]}

    def test_ops_004_cold_and_warm_median_of_three(self):
        runs = [
            self.item(1, "10:00:00", "10:30:00"),
            self.item(2, "11:00:00", "11:10:00"),
            self.item(3, "12:00:00", "12:20:00"),
            self.item(4, "13:00:00", "13:12:00"),
            self.item(5, "14:00:00", "14:01:00"),
        ]
        s = bench.summarize(runs)
        self.assertEqual(s["cold"], 1800.0)
        self.assertEqual(s["warm_median"], 720.0)
        self.assertEqual(s["warm_count"], 3)
        self.assertEqual([r["hosted_minutes"] for r in s["runs"]], [3] * 5)

    def test_ops_004_one_run_has_no_warm_median(self):
        s = bench.summarize([self.item(1, "10:00:00", "10:30:00")])
        self.assertEqual(s["cold"], 1800.0)
        self.assertIsNone(s["warm_median"])
        self.assertEqual(s["warm_count"], 0)

    def test_ops_004_incomplete_runs_are_ignored(self):
        incomplete = {"id": 9, "run": run("09:00:00", "09:10:00", status="in_progress"), "jobs": []}
        s = bench.summarize([incomplete, self.item(1, "10:00:00", "10:30:00")])
        self.assertEqual(s["cold"], 1800.0)
        self.assertEqual(len(s["runs"]), 1)

    def test_ops_004_no_runs(self):
        s = bench.summarize([])
        self.assertIsNone(s["cold"])
        self.assertIsNone(s["warm_median"])

    def test_ops_004_report_lists_cold_warm_and_minutes(self):
        s = bench.summarize([self.item(1, "10:00:00", "10:30:00"), self.item(2, "11:00:00", "11:10:00")])
        text = bench.report(s)
        self.assertIn("cold wall time        30m00s", text)
        self.assertIn("10m00s", text)
        self.assertIn("fewer were found", text)


if __name__ == "__main__":
    unittest.main()
