# Contributing to WrenDNS

Thank you for helping. Bug reports, fixes, docs, tests and ideas are all welcome.

- **A question?** Ask in [Discussions](https://github.com/nbacheller/wrendns/discussions).
- **A bug?** Open an [issue](https://github.com/nbacheller/wrendns/issues/new/choose) with a support package (the form says how).
- **A security problem?** Don't open an issue: follow [SECURITY.md](SECURITY.md).
- **Code or docs?** Open a pull request, as below. You will be asked to sign the [Contributor Licence Agreement](#contributor-licence-agreement) once.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## How the project works: spec first

WrenDNS is built from a specification, and the spec is the source of truth. Before you change behaviour, read:

1. [`AGENTS.md`](AGENTS.md): the ground rules (they apply to people as much as to coding agents).
2. [`spec/00-overview.md`](spec/00-overview.md), then [`spec/01-requirements.md`](spec/01-requirements.md) (the numbered requirements) and [`spec/11-decisions.md`](spec/11-decisions.md) (the decisions, ADRs).
3. The section of the spec for your area, and the task in [`spec/10-roadmap-and-tasks.md`](spec/10-roadmap-and-tasks.md).

What that means for a pull request:

- **Trace it.** Name the requirement IDs you implement in a comment where the code does it (`// REQ: FLT-003`), in test names (`flt_003_...`) and in the commit message (`feat(filter): FST snapshot compiler [FLT-003]`).
- **A gap in the spec** is not filled silently: propose an ADR in `spec/11-decisions.md` with status `Proposed`, or ask in the pull request.
- **Performance is a feature.** No allocation, locking or I/O on the DNS hot path without a benchmark (`make bench-smoke`). DNS never depends on telemetry, storage, the API or the cluster.
- **Clean room.** Never copy code from Pi-hole, Technitium, AdGuard Home or any other copyleft project. Their public docs, RFCs and data formats are fine. New Rust dependencies must pass `cargo deny` (permissive licences, plus MPL-2.0 per file; no GPL, LGPL or AGPL; see [LICENSING.md](LICENSING.md)), and new UI (npm) dependencies must have a permissive licence too.
- **Safety.** `unsafe` only in `wrendns-net`, with a `// SAFETY:` note; no `unwrap()` or `expect()` on runtime paths.
- **Every feature gets a UI control**, and every API operation is ready for agents (and an MCP tool where it fits, `spec/13`).
- **Docs.** User-visible behaviour is documented in `docs/` and on the site (`site/`).
- **New source files** start with an SPDX line, for example `// SPDX-License-Identifier: AGPL-3.0-or-later` (CI checks it with `scripts/check-spdx.py`). Files under `integrations/home-assistant/` are Apache-2.0 instead. A file taken from another project keeps its own licence line and goes under a `vendor/` or `third_party/` directory, which the check skips; say where it came from in the pull request.

- **No private details.** Examples use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example` domains and generic names ("a smart TV", "node-a"), never a real network, household, person or machine. Maintainers keep a private denylist of identifiers that must not appear in the repository; CI checks every tracked file, the built site and the generated docs against it (`scripts/check-private.py`, which reads the list from a repository secret and reports only `file:line` and the pattern's number). Without the list the check skips, so contributors don't need it. If it flags your pull request, a maintainer will say which line to generalize. Maintainers also run it with `--history` (separately from the tree scan) to check every commit's added lines, messages and paths, every ref name, the message and name of every annotated tag (through tags of tags), and the content of any ref that points at a blob or a tree.

Before you push, run the checks CI runs:

```sh
make check                         # cargo fmt --check, clippy -D warnings, tests, cargo deny
python3 site/build.py --check      # the site builds and its links resolve
python3 spec/trace.py --check      # requirements and tests stay traced
python3 scripts/check-spdx.py      # SPDX headers on new files
python3 scripts/check-pipefail.py  # no echo or printf piped into grep -q in deploy/ and .github/
python3 scripts/check-private.py   # maintainers: with WRENDNS_PRIVACY_DENYLIST set to the private list (CI requires it)
cd ui && npm ci && npm run check   # the UI type-checks (and npm run test:e2e for Playwright)
```

Keep commits small and coherent, with messages in the style of the history (`fix(api): ... [API-004]`).

## Continuous integration

Every pull request runs the fast tier (`.github/workflows/pr.yml`). A `changes` job lists the paths the pull request touched and `scripts/pr_changes.py` sorts each one. A pull request that changes only documentation (`spec/`, `site/`, `scripts/`, `docs/design/`, the Markdown in `docs/` and at the root that no code reads, the licence files, and `.github/` apart from `pr.yml` and `.github/scripts/`) skips the heavy jobs; one that changes only `ui/` (or the help glossary and Spectral rules) runs the UI job, and one that changes only `deploy/` runs the native-lite job. Any other path, including one the script does not know, runs everything: formatting, clippy, the amd64 tests, cargo-deny, the UI job and native-lite. The site job and the privacy check always run.

`pr-ok` is the one check to watch: it passes when every other job passed or was skipped, and it fails when any of them failed or was cancelled. Its log names each job that failed, and the run's job list shows where.

After a merge, the full tier (`.github/workflows/ci.yml`) runs on main: the arm64 tests, the end-to-end suites, the Helm and native cluster checks. The image workflow builds the images on main. To run it on a pull request, ask a maintainer to add the `ci:full` label; it runs again for each push while the label stays.

The privacy check needs a secret that pull requests from forks do not get, so it fails on them by design. That failure is not a problem with your change: a maintainer runs the check on a branch of the repository and reports the result.

## Dependency updates

Dependabot opens the dependency update pull requests: the root Cargo workspace is checked weekly, and the fuzz workspace, the two npm projects, the GitHub Actions and the image's base images are checked monthly. Minor and patch updates are grouped into one pull request for each entry that groups them (the root and fuzz Cargo workspaces, the two npm projects and the GitHub Actions), and every major update is its own pull request; the base images are not grouped. A release must be 5 days old before Dependabot offers it, and security updates do not wait for the schedule or that cooldown. Dependabot does not rebase its pull requests automatically, so a maintainer comments `@dependabot rebase` to refresh one. Merge each update with a squash, and put the requirement tag in the commit message, as the header of `.github/dependabot.yml` says.

## Contributor Licence Agreement

WrenDNS is licensed under the AGPL-3.0-or-later, and MySummitKeep, LLC also offers it under a commercial licence ([LICENSING.md](LICENSING.md)). To keep both possible, every outside contribution comes with this agreement. **You keep the copyright in your contribution**; you give MySummitKeep, LLC a licence to use it, including the right to license it to others under other terms.

### WrenDNS Individual Contributor Licence Agreement (version 1.0)

By signing, You accept and agree to the following terms for Your present and future Contributions submitted to MySummitKeep, LLC ("the Company"), a Florida limited liability company, for the WrenDNS project. Except for the licences granted here, You keep all right, title and interest in Your Contributions.

1. **Definitions.** "You" means the individual who signs this agreement. "Contribution" means any original work of authorship, including any changes or additions to an existing work, that You intentionally submit to the Company for inclusion in WrenDNS, through a pull request, a patch, an issue or any other form of communication with the project. A Contribution is "submitted" when it is sent to the Company or its representatives, including on the project's GitHub repository, mailing addresses or issue tracker, except communication You mark clearly as "Not a Contribution".

2. **Copyright licence.** You grant the Company, and recipients of software distributed by the Company, a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable licence to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense and distribute Your Contributions and such derivative works, **under any licence terms, including the GNU Affero General Public License, other open-source licences, and proprietary or commercial licences**.

3. **Patent licence.** You grant the Company, and recipients of software distributed by the Company, a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated in this section) patent licence to make, have made, use, offer to sell, sell, import and otherwise transfer the work, where the licence applies only to those patent claims licensable by You that are necessarily infringed by Your Contribution alone or by the combination of Your Contribution with the work to which it was submitted. If any entity starts patent litigation against You or any other entity (including a cross-claim or counterclaim in a lawsuit) alleging that Your Contribution, or the work to which You contributed, infringes a patent, then any patent licences granted to that entity under this agreement for that Contribution or work end on the date that litigation is filed.

4. **Relicensing.** You agree that the Company may license WrenDNS, including Your Contributions, under the AGPL and under other licences of its choice, including commercial ones, now and in the future. The Company agrees that each Contribution it accepts will also be available under the AGPL-3.0-or-later (or a later version of the GNU Affero General Public License) for as long as the Company distributes it under an open-source licence.

5. **Your right to grant.** You represent that You are legally entitled to grant the above licences. If Your employer has rights to intellectual property that You create, including Your Contributions, You represent that You have received permission to make Contributions on behalf of that employer, that Your employer has waived such rights for Your Contributions, or that Your employer has signed a separate agreement with the Company.

6. **Original work.** You represent that each of Your Contributions is Your original creation. Where You submit work that is not Your original creation (for example, code under another licence), You submit it separately from any Contribution, identify its source, its licence and any restrictions You know of, and mark it clearly as third-party work. You do not submit code copied from copyleft projects (AGENTS.md, rule 6).

7. **Tools.** If You used tools, including AI coding assistants, to prepare a Contribution, You represent that You reviewed the result, that You have the right to submit it under this agreement, and that it does not knowingly reproduce third-party code under incompatible terms.

8. **No obligation, no warranty.** The Company is not obliged to use or include any Contribution. Unless required by applicable law or agreed in writing, You provide Your Contributions on an "AS IS" basis, without warranties or conditions of any kind, and You are not expected to provide support for them.

9. **Notice of changes.** You agree to tell the Company if You become aware of any facts or circumstances that would make these representations inaccurate in any respect.

10. **Law.** This agreement is governed by the laws of the State of Florida, USA, without regard to its conflict-of-law rules.

### How to sign

When you open your first pull request, the **cla** check comments on it with a link to this agreement. To sign, add a comment to the pull request with exactly this sentence:

```text
I have read the CLA Document and I hereby sign the CLA
```

The check records your GitHub login, the pull request and the time in `signatures/cla.json` on the `cla-signatures` branch, and turns green. You sign once; later pull requests pass on their own. If the check doesn't update, comment `recheck`. If you are contributing for your employer and they need a corporate agreement, write to [support@wrendns.com](mailto:support@wrendns.com) first.

Questions about the agreement go to [support@wrendns.com](mailto:support@wrendns.com). It is reviewed by counsel before the first commercial sale (ADR-1033), and a changed version applies only to contributions made after you sign it.
