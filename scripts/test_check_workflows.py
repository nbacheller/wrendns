#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/check-workflows.py (OPS-004, NFR-005; ADR-1080). Run: python3 scripts/test_check_workflows.py"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check_workflows", HERE / "check-workflows.py")
assert SPEC and SPEC.loader
cw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cw)

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def job(steps: str, perms: str = "    permissions:\n      contents: read\n") -> str:
    return "name: t\non: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + perms + "    steps:\n" + steps


def rules(text: str) -> list[str]:
    return [r.split(":")[0] for _, r, _ in cw.check_text(text)]


class Pins(unittest.TestCase):
    def test_ops_004_a_full_sha_with_a_version_comment_passes(self):
        t = job(f"      - uses: actions/setup-node@{SHA} # v7.1.0\n")
        self.assertEqual(rules(t), [])

    def test_ops_004_a_tag_or_branch_is_flagged(self):
        for ref in ("actions/setup-node@v7", "dtolnay/rust-toolchain@1.99.0", "x/y@" + SHA[:39], "x/y@main"):
            self.assertEqual(rules(job(f"      - uses: {ref}\n")), ["pin"], ref)

    def test_ops_004_a_sha_without_a_version_comment_is_flagged(self):
        self.assertEqual(rules(job(f"      - uses: actions/setup-node@{SHA}\n")), ["pin"])

    def test_ops_004_local_actions_and_reusable_workflows_are_not_pinned(self):
        t = "name: t\non: push\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/_x.yml\n    permissions:\n      contents: read\n"
        self.assertEqual(rules(t), [])

    def test_ops_004_a_uses_after_a_name_key_is_read_too(self):
        t = job("      - name: n\n        uses: x/y@v1\n")
        self.assertEqual(rules(t), ["pin"])


class Checkout(unittest.TestCase):
    def test_nfr_005_checkout_must_set_persist_credentials(self):
        t = job(f"      - uses: actions/checkout@{SHA} # v7.0.1\n      - run: echo hi\n")
        self.assertEqual(rules(t), ["checkout"])

    def test_nfr_005_block_and_flow_forms_count(self):
        block = job(f"      - uses: actions/checkout@{SHA} # v7.0.1\n        with:\n          persist-credentials: false\n")
        flow = job(f"      - uses: actions/checkout@{SHA} # v7.0.1\n        with: {{ persist-credentials: false, fetch-depth: 0 }}\n")
        self.assertEqual(rules(block), [])
        self.assertEqual(rules(flow), [])

    def test_nfr_005_the_key_of_the_next_step_does_not_count(self):
        t = job(
            f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
            f"      - uses: actions/upload-artifact@{SHA} # v7\n        with:\n          persist-credentials: false\n"
        )
        self.assertEqual(rules(t), ["checkout"])


class Permissions(unittest.TestCase):
    def test_nfr_005_a_job_without_permissions_is_flagged(self):
        self.assertEqual(rules(job("      - run: echo hi\n", perms="")), ["permissions"])

    def test_nfr_005_an_empty_permissions_block_counts(self):
        self.assertEqual(rules(job("      - run: echo hi\n", perms="    permissions: {}\n")), [])

    def test_nfr_005_each_job_is_checked_on_its_own(self):
        t = job("      - run: echo hi\n") + "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        self.assertEqual(rules(t), ["permissions"])


class Injection(unittest.TestCase):
    def test_nfr_005_event_input_matrix_and_output_expressions_in_run_are_flagged(self):
        for expr in ("github.event.pull_request.title", "inputs.seconds || 1800", "matrix.target", "steps.v.outputs.x",
                     "github.head_ref", "github.actor", "needs.a.outputs.b", "secrets.TOKEN"):
            t = job(f"      - run: echo ${{{{ {expr} }}}}\n")
            self.assertEqual(rules(t), ["injection"], expr)

    def test_nfr_005_block_scripts_are_read(self):
        t = job("      - run: |\n          echo ok\n          echo ${{ github.event.comment.body }}\n")
        self.assertEqual(rules(t), ["injection"])
        t = job("      - uses: x/y@" + SHA + " # v1\n        with:\n          script: |\n            core.info('${{ github.actor }}')\n")
        self.assertEqual(rules(t), ["injection"])

    def test_nfr_005_the_runners_own_facts_pass(self):
        t = job("      - run: npx playwright install ${{ runner.environment == 'github-hosted' && '--with-deps' || '' }} --only-shell chromium\n")
        self.assertEqual(rules(t), [])
        self.assertEqual(rules(job("      - run: echo ${{ github.run_number }} ${{ github.sha }}\n")), [])

    def test_nfr_005_expressions_in_env_with_and_if_are_not_script_bodies(self):
        t = job("      - if: github.event_name == 'push'\n        env:\n          X: ${{ github.event.pull_request.title }}\n        run: echo \"$X\"\n")
        self.assertEqual(rules(t), [])

    def test_nfr_005_a_string_literal_does_not_count_as_a_context(self):
        t = job("      - run: echo ${{ runner.os == 'github.event.x' }}\n")
        self.assertEqual(rules(t), [])


class Repo(unittest.TestCase):
    def test_ops_004_the_repositorys_own_workflows_pass(self):
        found = cw.scan(HERE.parent)
        self.assertEqual(found, [], "\n".join(f"{p}:{n}: {r}: {t}" for p, n, r, t in found))

    def test_ops_004_scan_reads_every_workflow_file(self):
        with tempfile.TemporaryDirectory() as d:
            wf = Path(d, ".github", "workflows")
            wf.mkdir(parents=True)
            (wf / "ok.yml").write_text(job(f"      - uses: actions/setup-node@{SHA} # v7\n"), encoding="utf-8")
            (wf / "bad.yml").write_text(job("      - uses: actions/setup-node@v7\n"), encoding="utf-8")
            found = cw.scan(Path(d))
            self.assertEqual([(p, r.split(":")[0]) for p, _, r, _ in found], [(".github/workflows/bad.yml", "pin")])
            self.assertEqual(cw.main(["--root", d]), 1)
            (wf / "bad.yml").unlink()
            self.assertEqual(cw.main(["--root", d]), 0)


if __name__ == "__main__":
    unittest.main()
