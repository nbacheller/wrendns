# Going public

The runbook for making WrenDNS public: one ordered checklist from today (the repository `nbacheller/wrendns` is private) to "public, v1.0.0 released, verified". It is written for the owner and for an agent that helps. Decision records: ADR-1080 (the public repository's policy, with the owner's decision of 2026-11-24), ADR-1076 (self-hosted runners), ADR-1028 (the rename window), ADR-1033 (licensing) and ADR-097 (releases). Task: T39.13.

## The route, and the owner's decisions of 2026-11-24

The repository that goes public is **the current repository**. Nothing is re-created, rewritten or force-pushed. The owner's decisions (binding):

- **E1, history as it is.** `nbacheller/wrendns` goes public with its history unchanged. The commit author addresses already in the history are accepted as they are. Commits from 2026-11-24 on use the owner's GitHub noreply address.
- **E2, order.** The repository goes public first. v1.0.0 is then cut through the release workflow within the hour. The provenance and SBOM attestation steps of `image.yml` run only when `github.event.repository.private == false`, and the release's `verify` job (`deploy/release/verify.sh`) reads GitHub and ghcr anonymously.
- **E3, old runs.** All existing Actions runs, with their logs and artifacts, and all caches are deleted just before the flip, on the owner's go-ahead. Only runs started after the flip are public.
- **E4, build box.** The eight self-hosted runners are stopped before the flip. After the flip, the owner first sets approval for fork pull request workflows from all outside collaborators, and verifies it with test fork pull requests. Only then are the runners started. There is no runner hook.
- **E5, fork pull requests.** The required privacy check fails closed on forks. To accept a contribution, a maintainer pushes the contributor's commits, with their authorship kept, to a branch in the repository, where all checks run, merges that, and closes the fork pull request with a link. No required check is bypassed.
- **E6, ruleset.** There is no bypass for the GitHub Actions app. After a release, the version bump on `main` goes through `deploy/release/bump.sh` and a normal pull request.
- **E7, TelltaleDNS-era leftovers.** Keep what the documented migration path needs. Nothing is removed without the owner's yes on a list. The TelltaleDNS-era releases are the only ones from before the switch to the AGPL, so they are kept: the `permissive-final` release and tag, and the `telltale` image and chart packages. They stay private through the flip and become public after a scan, as a separate step after v1.0.0 (Q2, step 24a).

The owner's answers of 2026-11-24 to the questions at the end of this page (each is binding; the step that acts keeps its own **owner's yes** at the time). Q3, Q6 and Q10 were answered on 2026-11-25; those answers are beside the questions at the end of this page.

- **Q1, packages `wrendns` and `charts/wrendns`.** Both are deleted just before the flip (step 13) and re-created by the first image run after it (step 19). Nothing is made public with the old versions.
- **Q2, packages `telltale` and `charts/telltale`.** They become public after their versions are scanned against the denylist, as a separate step after v1.0.0 (step 24a). A version that fails the scan is deleted, with the owner's yes. Until then they stay private, so `LICENSING.md` says they "are made public as an archive ... once checked", which is true on the day of the flip.
- **Q4 and Q5, the ruleset.** Required checks `privacy`, `site` and `pr-ok`. No separate "require a pull request" rule. The repository admin role may bypass for pull requests only. No bypass for the GitHub Actions app (E6). Step 22.
- **Q7, tags.** `fork-base` and `upstream-sync-last` are deleted (step 9, owner's yes at the time).
- **Q8, `telltale-*` release files.** They stop being published before v1.0.0: `deploy/release/legacy-assets.sh` and what uses it are removed (task in "Tasks to do before the flip"). The migration path stays.
- **Q9, branches.** Merged work branches are deleted on GitHub before the final scan (step 9, before step 14). Dependabot's branches are left.
- **Q11, commits that no ref reaches.** The owner's local clones are scanned for them with the privacy check (option 1), and the remainder is accepted as a known small risk, in writing (option 3). Steps 9 and 14.

## How to read it

- Every step names **who** does it, **how** (the exact command, or the Settings path), how to **verify** it, and how to **undo** it, or says plainly that it cannot be undone.
- **Owner's yes** marks a step that needs the owner's explicit yes at the time it is done. Every step that makes something public, deletes runs, caches, packages, releases, branches or tags, changes a ruleset, a secret, a variable or a package setting, cuts a release, or touches the build box has one. An agent never does such a step on its own. It may run the read-only checks and report.
- **To confirm at step N** marks a fact that no file in this repository states. Do not guess it. Find it out at step N and write the answer into this page.
- Every workflow, job, input, secret, variable and file name comes from the files in this repository. Labels in the GitHub interface are quoted as GitHub shows them and can drift.
- Placeholders: `<outside>` is a directory outside every working copy. `<list>` is the path of the private denylist file, kept outside every repository. `<checkout>` is a fresh clone of `main` at the frozen head (step 10), not a development worktree.
- **Never** copy a private value into a command line that is logged, an issue, a commit, a chat or this page. A privacy hit prints a path or a commit and `pattern #N`, never the value.
- GitHub API budget: 5,000 calls an hour, shared with other sessions. Do not use `gh run watch`. Poll at most every 5 minutes. Step 15 is the only step that needs many calls.

## What the repository already answers

- **Fork approval cannot be set while private.** `gh api repos/nbacheller/wrendns/actions/permissions/fork-pr-contributor-approval` answers 422, "Fork PR approval is not allowed for private repositories" (read 2026-11-24). It is step 18, straight after the flip.
- **The `runs-on` guard is not a barrier against a fork.** For a `pull_request` event GitHub runs the workflow file from the pull request's merge commit, so a fork can edit any job's `runs-on`, including the guard `github.event.pull_request.head.repo.full_name == github.repository` in `pr.yml` and `main.yml`. What keeps a fork off the box is the approval gate (step 18) and, until it is tested, stopped runners (E4). **Stopped is not unregistered:** the runners stay registered (step 11 expects `offline` eight times), and a job aimed at registered but offline runners waits in the queue instead of failing. Until step 18 the repository has GitHub's default fork-approval policy, and a run that already started is not held back by a later change of the setting. So a fork pull request opened between step 17 and step 18 can leave a queued job for the self-hosted labels, which a runner would pick up the moment it starts. Steps 18 and 26 therefore list such runs and cancel them (the command is in step 18). Removing the runner variables (step 12) does not close this: with them unset, `runs-on` in `pr.yml` and `main.yml` evaluates to `ubuntu-latest` (`pr.yml` lines 82 and 101; `main.yml` lines 159, 179, 316, 369, 516 and 661), because `vars.WRENDNS_PR_RUNNER` and `vars.WRENDNS_RUNNER` are empty strings and so fall through to `'"ubuntu-latest"'`. But a fork edits `runs-on` itself and writes the labels in, whatever the variables hold. The variables only keep the repository's own jobs off the stopped box.
- **The release workflow no longer pushes to `main`.** The ruleset `main` (id 27699911) holds only the rules `deletion` and `non_fast_forward`, with one bypass actor, the repository admin role, mode `always` (read 2026-11-24). The old "Move main" step ran `git push origin HEAD:main`, which passes today and would be refused once step 22 requires checks, ending every release run red. The task in "Tasks to do before the flip" removes that push: the step ends with a notice to run `deploy/release/bump.sh` and open a pull request (step 25).
- **What switches itself on at the flip.** The attestation steps in `image.yml`, the `dependency-review` job in `pr.yml` and the `codeql` workflow all test `private == false`. Nothing needs editing for them.
- **The privacy check requires the list only here.** `WRENDNS_PRIVACY_REQUIRED` is `github.repository == 'nbacheller/wrendns'` in `pr.yml` (and the same test, plus a same-repository head, in `main.yml`). A fork pull request runs in this repository, gets no secret, and fails closed (ADR-1080 point 2). The Dependabot secret `PRIVACY_DENYLIST` exists (read 2026-11-24).
- **`check-private.py --history` works on a bare mirror, by reading the code.** With `--root` it runs only `git -C <root>` with `log`, `for-each-ref`, `cat-file`, `ls-tree` and `rev-parse --is-shallow-repository`, and needs no work tree. Step 7 runs it on one, which proves it. Its tree mode is different: it runs `git ls-files` in `--root`, and it refuses an `--extra` directory outside `--root` ("an --extra directory must be inside --root"). Step 8 therefore scans files in a throwaway `git init` directory.
- **What `check-private.py` does not scan** (its docstring): author, committer and tagger names and emails; git notes and reflogs; binary files; anything outside git. Identities are accepted under E1. Built files are step 8. GitHub-side content is steps 4 and 14.
- **Every non-local `uses:` is pinned to a 40-hex SHA.** `scripts/check-workflows.py` enforces it. The repository's `sha_pinning_required` setting is `false` (audit, 2026-11-24).
- **Secrets, the release key and the site deploy do not move.** The repository is the same, so `MINISIGN_SECRET_KEY`, `PRIVACY_DENYLIST` and `AZURE_STATIC_WEB_APPS_API_TOKEN` stay as they are, installed nodes keep trusting the same key, and `site.yml` keeps deploying with its token.
- **Packages are linked to the archive.** The image `wrendns` and the chart `charts/wrendns` are private and linked to `nbacheller/wrendns-archive`, with 333 and 27 versions, the oldest from 2026-11-19 (read 2026-11-24). `telltale` and `charts/telltale` are private and linked there too. The `Dockerfile` sets `org.opencontainers.image.source` to `https://github.com/nbacheller/wrendns`, and `Chart.yaml` lists that address under `sources`. See decision Q1.
- **Already public and cannot be withdrawn:** the keyless cosign signatures of every edge build are in the public Sigstore transparency log, naming `nbacheller/wrendns` and `image.yml`. They hold no private value.
- **Commit identities (E1).** Accepted as they are. To see what the history exposes, count it in the step 14 mirror without printing a value: `git -C <outside>/wrendns-final.git log --all --format='%ae%n%ce' | sort -u | grep -vc '@users.noreply.github.com$'` prints the number of distinct addresses that are not GitHub noreply addresses (5 across origin's branches and tags on 2026-11-24). Drop `-c` to see them on your own screen only.

## The gap in the history scan

`check-private.py --history` reads `git log --all`, so it sees only commits that some ref reaches. A commit that no ref points at can still be fetched from a public repository by anyone who knows its hash (short hashes in the web interface too) until GitHub garbage-collects it. Nothing lists such commits from outside, and a mirror clone does not hold them, so no step here can scan them from GitHub's side. The owner's own clones and reflogs may hold some. The owner's decision on it is Q11 (above, and step 14): scan the owner's clones, accept the remainder.

## The order in one line each

Part A, prepare. The repository stays private.

1. Land the tasks before the flip.
2. Get the owner's answers to the open questions.
3. Read what GitHub holds today (read only).
4. Review issue and pull request text, by number. **Owner's yes** for each edit or deletion.
5. Set the version to 1.0.0 and write the notes, through a pull request.
6. A release rehearsal that publishes nothing.
7. First full privacy pass: tree, history with every pull request ref, secret scan.
8. Scan what the builds published: release assets, SBOMs, debug files.
9. Delete the leftover branches, and the tags on the owner's list. **Owner's yes.**

Part B, the window. From step 10 to the tag in step 24, nothing lands on `main` or the tags (step 10 says what is expected besides).

10. Freeze every ref.
11. Stop the eight runners (E4). **Owner's yes** (build box).
12. Remove the runner variables (Q3). **Owner's yes** (variables).
13. Packages: carry out the owner's answer to Q1. **Owner's yes** (packages).
14. Final re-scan and review. *This is the condition for the yes at step 17.*
15. Delete all Actions runs and caches (E3). **Owner's yes.**
16. Last look, minutes before the flip.
17. Make the repository public. **Owner's yes. It cannot be undone.**

Part C, after the flip:

18. Require approval for fork pull requests, first. **Owner's yes.**
19. Start the first runs after the flip. **Owner's yes** (publishes edge).
20. The test fork pull requests A and B. **Owner's yes** to approve test A's run.
21. The settings that exist only once public. **Owner's yes.**
22. The ruleset (ADR-1080 with E5 and E6). **Owner's yes** (ruleset).
23. Packages: link and visibility. **Owner's yes** (packages).
24. Cut v1.0.0 and verify it (E2). **Owner's yes** (release).
    - 24a. Scan and publish the `telltale` packages (Q2), after v1.0.0. **Owner's yes** (packages).
25. Start 1.1.0 through a pull request (E6).
26. Start the runners, then test C. **Owner's yes** (build box, variables, approving test C's run).
27. The site switch. **Owner's yes** (pushes and merges what makes the site's links live).
28. The social preview. **Owner's yes.**
29. Anonymous checks from the outside.
30. The Software Heritage save. **Owner's yes.**
31. The CLA context in the ruleset. **Owner's yes** (ruleset).

Part D, standing procedures:

32. Accepting a contribution (E5).
33. If something private is found after the flip.

## Part A: prepare

### 1. Land the tasks before the flip

- **Who:** an agent or the owner, each in a normal pull request. Commits use the owner's noreply address.
- **How:** do every item in "Tasks to do before the flip" at the end of this page. The `release.yml` task matters most: without it every release run ends red (step 24). Each task is marked when done.
- **Verify:** each pull request is merged and CI on `main` is green.
- **Undo:** revert the pull request.

### 2. Get the owner's answers to the open questions

- **Who:** the owner, asked through the question tool, all questions together.
- **How:** "Open questions for the owner" at the end of this page, each with a recommendation. Write each answer into this page beside its question. The owner answered all but Q3, Q6 and Q10 on 2026-11-24 (see "The route", above) and those three on 2026-11-25 (at the end of this page). Q10's answer sets how step 4 is done; the item-by-item marks are still to come.
- **Verify:** every question has a written answer before step 9.
- **Undo:** an answer can be changed until the step that acts on it.

### 3. Read what GitHub holds today

- **Who:** an agent or the owner. Read only, about 14 calls. Save the answers outside every repository: they hold names and settings, not secret values.
- **How:**
  - `gh api repos/nbacheller/wrendns --jq '{description,homepage,has_issues,has_wiki,has_projects,has_discussions,allow_merge_commit,allow_squash_merge,allow_rebase_merge,delete_branch_on_merge}'` and `gh api repos/nbacheller/wrendns/topics`.
  - `gh api repos/nbacheller/wrendns/actions/permissions` (`enabled`, `allowed_actions`, `sha_pinning_required`), `.../actions/permissions/selected-actions` (GitHub-owned and verified creators plus 10 patterns on 2026-11-24) and `.../actions/permissions/workflow` (`read`, cannot approve pull request reviews, on 2026-11-24).
  - `gh api repos/nbacheller/wrendns/rulesets/27699911`.
  - `gh secret list -R nbacheller/wrendns`, `gh secret list --app dependabot -R nbacheller/wrendns` and `gh variable list -R nbacheller/wrendns`: names only. On 2026-11-24 the secrets were `AZURE_STATIC_WEB_APPS_API_TOKEN`, `MINISIGN_SECRET_KEY` and `PRIVACY_DENYLIST`, the Dependabot secret `PRIVACY_DENYLIST`, and the variables `WRENDNS_RUNNER` and `WRENDNS_PR_RUNNER`, both `["self-hosted","wrendns"]`.
  - `gh api repos/nbacheller/wrendns/collaborators --jq '.[].login'`, `gh api repos/nbacheller/wrendns/invitations --jq length` and `gh api repos/nbacheller/wrendns/forks --jq length` (0 on 2026-11-24).
  - The owner, in the web interface: GitHub, Settings, Applications, Installed GitHub Apps, and each app's repository access. An app with access sees the repository's content whether it is public or not, so check each one is still wanted.
  - `gh api user/packages/container/wrendns --jq '.repository.full_name, .visibility'`, the same for `charts%2Fwrendns`, `telltale` and `charts%2Ftelltale`. Version counts: `gh api 'user/packages/container/wrendns/versions?per_page=100' --paginate --jq '.[].id' | wc -l`, and the same for `charts%2Fwrendns`.
- **Verify:** each answer is saved. Anything new against the 2026-11-24 values above goes to the owner.
- **Undo:** nothing to undo.

### 4. Review issue and pull request text, by number

Issues, pull requests, comments and their edit history all become public. Every item was written by `nbacheller`, `dependabot[bot]` or `github-actions[bot]`, and the audit found no email address, private address, user path, token or phone number in them. These need a human look:

- **Domains not on the scanner's allow-list:** issues #29, #40 and #83, and pull request #56. Decide whether each is an example or a public vendor name.
- **AI and attribution words:** pull request #56 (graphify docs, mentions the word "claude"), #46 ("Copilot", upstream release-note text in a Dependabot bump) and issue #42 ("LLM", a product feature). None is a Co-Authored-By line.
- **An email-like string:** pull request #97 (Dependabot, 2 matches; probably a bot or noreply address).
- **Internal notes:** issue #18 (upstream watch), #9, #39 and #82 (operational), #13 to #16, #21, #23 to #30 and #40 to #42 (planning), and pull requests #53, #58, #60, #61, #64 to #69, #75, #78, #88, #96 and #102. This is a review list, not a list of problems.
- **Everything newer than #103**, and every comment since 2026-11-24. Step 14 repeats this for items since this step.

- **Who:** the owner reads; an agent may prepare the list. **Owner's yes** for each change.
- **How:** an edit changes the text but keeps its edit history visible, so use an edit only for non-sensitive fixes. For a sensitive value: delete the comment, or delete the issue (`gh issue delete <N> -R nbacheller/wrendns --yes`, admin only). A pull request cannot be deleted by the owner, only by GitHub Support. A value in a pull request's text or edit history means asking GitHub Support before the flip.
- **Verify:** the owner writes "text review done" and the numbers changed.
- **Done 2026-11-25, for items up to #108** (the owner's answers through the question tool; all 108 items were read, and none held a private address, host name, email or token):
  - Issues #28, #40, #41 and #42 (the hosted service and its paid offerings) were transferred to the WrenDNS Cloud tracker, where they are cloud #1 to #4. The node-side part of #40 is issue #110 here.
  - Issue #9 and pull request #56 were reworded (a mention of local tooling). Pull requests #66 and #96 had sentences about paid offerings and legal review trimmed, and #66 lost the old issue number in its title. The old wording of all four stays in their edit history.
  - Issue #18 (upstream watch) was deleted. The script that wrote it and the export of issues #1 to #29 in `.github/issues-archive/` were removed from the tree; both stay in the history.
  - Everything else stays as it is, issue #29 included.
  - Step 14 still repeats the review for items newer than #108.
- **Undo:** a deleted issue or comment cannot be restored.

### 5. Set the version to 1.0.0 and write the notes, through a pull request

- **Who:** an agent or the owner.
- **How:** on a branch, `deploy/release/bump.sh 1.0.0` (`main` says `0.8.0` in `Cargo.toml`; the script also updates the chart, the crates, `Cargo.lock` and `docs/api/openapi.json`). Write `deploy/release/notes/v1.0.0.md` (highlights, what to do when upgrading, known issues; no first line beginning `_Draft`; `v0.8.0.md` is a starting point). Open a pull request and merge it once CI is green.
- **Verify:** locally, in `<checkout>` at the merged head: `GH_TOKEN=$(gh auth token) sh deploy/release/preflight.sh 1.0.0` prints `preflight OK: v1.0.0 at <sha> ...`. It only reads. It will fail again after step 15, which deletes the CI run it reads; step 19 makes a new one.
- **Undo:** revert. `bump.sh 0.8.0` goes back while no tag exists.

### 6. A release rehearsal that publishes nothing

`release.yml` has no dry-run input and always checks out `main`, so the rehearsal uses only the parts that publish nothing.

- **Who:** an agent or the owner.
- **How:** push a branch `rehearsal/v1.0.0` at `main`'s head and run `gh workflow run image.yml --ref rehearsal/v1.0.0 -R nbacheller/wrendns`. Its `version` job sets `publish=false` for a branch, so it builds and tests the three architectures and the release assets and pushes nothing. Delete the branch afterwards, before step 7.
- **Verify:** the image run is green, with `merge`, `chart`, `release` and `verify` skipped.
- **Undo:** delete the branch. The run is deleted in step 15.

### 7. First full privacy pass

This pass covers everything git can serve once the repository is public. GitHub keeps a hidden ref `refs/pull/<N>/head` for every pull request, closed and unmerged ones included, and `refs/pull/<N>/merge` for open ones. Deleting a branch does not remove them. Once public, anyone can fetch them (67 such refs on 2026-11-24).

- **Who:** the owner, or an agent the owner trusts with the list. An agent must not look for the list.
- **Without the list in hand (added 2026-11-25):** the `privacy-full` job of `nightly.yml` runs this step's history scan and tree scan, and step 8's scan of the `edge` release, with the list from the repository secret, every night and on `gh workflow run nightly.yml -R nbacheller/wrendns`. It fetches every ref, `refs/pull/*` included, and prints the counts. A hit is printed as `path:line: pattern #N` only. A green `privacy-full` job on the head being released is this step's and step 8's verify. The secret scan below is still separate.
- **How:**
  - **A mirror clone**, which fetches with the refspec `+refs/*:refs/*`, so it holds every branch, tag and `refs/pull/*` ref: `git clone --mirror https://github.com/nbacheller/wrendns.git <outside>/wrendns-scan.git`. Count the pull request refs: `git -C <outside>/wrendns-scan.git for-each-ref refs/pull --format='%(refname)' | wc -l`.
  - **The history:** `WRENDNS_PRIVACY_DENYLIST=<list> python3 <checkout>/scripts/check-private.py --root <outside>/wrendns-scan.git --history --require`. It reads, from every ref (`refs/pull/*`, `cla-signatures`, the Dependabot branches and the tags included): every added line, every commit message, every branch and tag name, annotated tag messages and names, every path, and non-commit ref targets.
  - If it exits 2 on the bare mirror, use a normal clone with the refs fetched explicitly, and record that here: `git clone https://github.com/nbacheller/wrendns.git <outside>/wrendns-scan`, then `git -C <outside>/wrendns-scan fetch origin '+refs/pull/*:refs/remotes/origin/pull/*' '+refs/tags/*:refs/tags/*'`, then the same command with `--root <outside>/wrendns-scan`.
  - **The tree:** in `<checkout>`, `python3 site/build.py`, so the built site is scanned too, then `WRENDNS_PRIVACY_DENYLIST=<list> python3 scripts/check-private.py --require`.
  - **Secret scan:** run a secret scanner of the owner's choice (for example gitleaks or trufflehog) over the mirror in its own documented all-history mode.
  - **`cla-signatures`** is a full copy of `main`'s tree at 2026-11-19 (its base is `2e99850b`, the `permissive-final` commit, which is in `main`'s history anyway) plus one bot commit that creates `signatures/cla.json` holding `{"signedContributors": []}`. The history scan covers it like any ref. It stays: `cla.yml` writes signatures to it.
- **Verify:** the history check prints `check-private: history of N commit(s) clean against M pattern(s)` and exits 0. The tree check exits 0. The secret scan is clean. Exit 2 means the list was missing or unusable: not a pass.
- **On a hit:** **stop.** In the tree: fix it in a normal pull request. In history: only a rewrite and a force push remove it, which E1 rules out, so the owner decides before anything else happens. In a `refs/pull/*` ref only: GitHub Support can remove a pull request and its ref.
- **Undo:** delete the directories.

### 8. Scan what the builds published

The `edge` release becomes public at the flip and stays until step 19 replaces it. It still holds `telltale-*` binaries until a build from `main` after Q8's change has replaced it; the scan reads whatever it holds. Its assets are not in git.

- **Who:** the owner, or an agent the owner trusts with the list.
- **How:**
  - `mkdir -p <outside>/asset-scan/assets-text && git -C <outside>/asset-scan init -q`. The scan runs `git ls-files` in its root, so the root must be a git repository, and every `--extra` directory must be inside it.
  - `gh release download edge -R nbacheller/wrendns -D <outside>/asset-scan/assets`. It holds `wrendns-*` and `telltale-*` binaries, the `.cdx.json` SBOMs, the `.debug.zst` debug files, `SHA256SUMS`, `releases.json` and their `.minisig` files (16 assets on 2026-11-24).
  - Debug files and binaries are binary, so extract their printable strings (debug files can hold build paths): for each `assets/*.debug.zst`, `zstd -dc <file> | strings > assets-text/<file name>.txt`; for each `assets/*-linux` binary, `strings <file> > assets-text/<file name>.txt`.
  - Q1 deletes the existing `wrendns` packages, so their old versions need no scan. The image that step 19 publishes is built from the scanned tree.
  - Scan: `WRENDNS_PRIVACY_DENYLIST=<list> python3 <checkout>/scripts/check-private.py --root <outside>/asset-scan --require --extra assets --extra assets-text`.
  - Read the `edge` and `permissive-final` release notes: `gh release view edge -R nbacheller/wrendns` and the same for `permissive-final`.
- **Verify:** `check-private: N file(s) clean against M pattern(s)`, exit 0. Exit 2 is not a pass.
- **On a hit:** fix it at the source and publish a new edge build before step 10.
- **Undo:** delete the directory.

### 9. Delete the leftover branches, and the tags on the owner's list

Branches on GitHub on 2026-11-24 (`git ls-remote --heads origin`): `main`, `cla-signatures`, `feat/ipam-integrations`, `fix/flake-syslog-tls`, `fix/flake-three-node-secrets` and five `dependabot/*` branches (`cargo/fuzz/fuzz-minor-patch-30c711cce5`, `cargo/miniz_oxide-0.9.1`, `cargo/rusqlite-0.43.0`, `github_actions/actions-28f155eaaa`, `npm_and_yarn/ui/ui-minor-patch-c2d374546f`). Local-only branches do not matter.

- **Who:** the owner. **Owner's yes** (deletes branches and tags).
- **How:**
  - Keep `main` and `cla-signatures`.
  - Q9: each work branch that is merged into `main` is deleted on GitHub: `git push origin --delete <branch>`. Check first with `git merge-base --is-ancestor origin/<branch> origin/main`. A branch that is not merged goes back to the owner, who merges it through a pull request or says to delete it. All this happens before step 14, so the final scan sees the result.
  - The Dependabot branches are left (Q9).
  - Tags (Q7, owner's yes at the time): `git push origin --delete fork-base upstream-sync-last`. Keep `permissive-final` (E7) and `edge` (`image.yml` re-creates it).
- **Verify:** `git ls-remote --heads origin` lists only what the owner kept. A deleted branch's commits stay reachable by hash. Those that a `refs/pull/*` ref reaches were scanned in step 7 (the mirror holds every ref). **Commits that no ref reaches were not scanned**: a branch deleted before today that never had a pull request, or a pull request head replaced by a force push (`refs/pull/<N>/head` keeps only the latest). See "The gap in the history scan" and Q11 (step 14).
- **Undo:** push the branch or tag again from a clone that has it.

## Part B: the window

### 10. Freeze every ref

- **Who:** the owner announces it to every session and agent.
- **How:** from now until the tag in step 24: no merge, no push and no tag on `main` or any branch, and no new issue or comment. After the flip (step 17) the freeze covers `main` and the tags; the refs that the fork tests create (`refs/pull/*`, step 20) and the CLA signature that `cla.yml` may write to `cla-signatures` are expected. Dependabot cannot be paused this way, which step 16 checks. Plan the window away from the scheduled runs: `nightly.yml` runs at 04:41 UTC daily and 05:17 UTC on Mondays, `codeql.yml` on Mondays at 04:23 UTC, and Dependabot at 02:00 America/New_York (ADR-1078 point 4).
- **Verify:** step 16.
- **Undo:** lift the freeze.

### 11. Stop the eight runners (E4)

- **Who:** the owner, on the build box. **Owner's yes** (build box).
- **How:** for each runner, the first two points of "Rolling back to host runners" in `docs/ci-runners.md`: disable the runner's supervisor (a running job finishes first), and stop the container's runner cleanly so it deletes its GitHub session. Do **not** do the third point: the host unit stays disabled. The host-side commands are kept on the build box, not in this repository. **To confirm at step 11:** the exact command, recorded here.
- **Verify:** `gh api repos/nbacheller/wrendns/actions/runners --jq '.runners[].status'` prints `offline` eight times.
- **Undo:** start the supervisors again.

### 12. Remove the runner variables (Q3)

The owner's answer to Q3 is yes (2026-11-25). With the variables unset, every job falls back to `ubuntu-latest` (`docs/ci-runners.md`), so nothing of the repository's own waits for the stopped box, and every log made before step 26 comes from GitHub-hosted runners. (Unset, `runs-on` evaluates to `ubuntu-latest` in every job that reads the variables. A fork can still write the self-hosted labels into its own copy of a workflow, so this does not replace step 18.)

- **Who:** the owner. **Owner's yes** (variables).
- **How:** `gh variable delete WRENDNS_RUNNER -R nbacheller/wrendns` and `gh variable delete WRENDNS_PR_RUNNER -R nbacheller/wrendns`. Their values (`["self-hosted","wrendns"]`) are set again in step 26.
- **Verify:** `gh variable list -R nbacheller/wrendns` is empty.
- **Undo:** step 26's `gh variable set` commands.

### 13. Packages: carry out the owner's answer to Q1

- **Who:** the owner. **Owner's yes** (packages).
- **How** (Q1: delete `wrendns` and `charts/wrendns`): your profile, Packages, the package, Package settings, "Delete this package", for each of the two. Leave `telltale` and `charts/telltale` alone (E7, Q2).
- **Verify:** `gh api user/packages/container/wrendns` and `gh api user/packages/container/charts%2Fwrendns` answer 404. `gh api user/packages/container/telltale --jq .visibility` still says `private`.
- **Undo:** a deleted package can be restored from the account's package settings for a limited time. **To confirm at step 13:** how long, and that a restore brings back every version.

### 14. Final re-scan and review

Steps 7 to 13 are only as good as the moment they ran. This step repeats them on the frozen state. Its clean result is the condition for the yes at step 17.

- **Who:** the owner, or an agent the owner trusts with the list.
- **How:**
  - A new mirror: `git clone --mirror https://github.com/nbacheller/wrendns.git <outside>/wrendns-final.git`, then `git -C <outside>/wrendns-final.git for-each-ref --format='%(objectname) %(refname)' | sort > <outside>/refs-at-scan.txt`.
  - Step 7's history check with `--root <outside>/wrendns-final.git`, its tree check in a `<checkout>` at the frozen head, and its secret scan on the new mirror.
  - Step 8 again if `edge` changed since then (`gh release view edge -R nbacheller/wrendns --json name` names the commit).
  - Step 4 again for every issue, pull request and comment since step 4.
  - Step 3's collaborators, invitations, forks and installed apps, again.
  - Q11, carried out: the unreachable-commit scan of the owner's local clones (in a scratch clone, give each `git rev-list --reflog` commit a temporary ref, then run `check-private.py --history` there), and the owner's written acceptance of what it cannot reach (GitHub's own unreachable objects).
- **Verify:** every scan is clean, the clone scan of Q11 is clean (the remainder is accepted: Q11, 2026-11-24), and the owner writes "pre-flip review done" to the agent, naming anything removed.
- **On a hit:** as in step 7. The flip waits.
- **Undo:** nothing to undo.

### 15. Delete all Actions runs and caches (E3)

Run logs can hold what no scan has read, and logs of jobs on the build box name the runner and the machine. Caches can be restored by pull request jobs. All of it goes.

- **Who:** the owner, or a command with the owner's go-ahead. **Owner's yes** (deletes runs and caches). **It cannot be undone.**
- **How:**
  1. Counts before (760 runs, 331 artifacts and 179 caches, about 10.4 GB, on 2026-11-24):
     - `gh api 'repos/nbacheller/wrendns/actions/runs?per_page=1' --jq .total_count`
     - `gh api 'repos/nbacheller/wrendns/actions/artifacts?per_page=1' --jq .total_count`
     - `gh api repos/nbacheller/wrendns/actions/cache/usage --jq .active_caches_count`
  2. No run may be queued or in progress: `gh run list -R nbacheller/wrendns --status queued` and `--status in_progress` list nothing. Cancel any with `gh run cancel <id> -R nbacheller/wrendns` and wait for it to end.
  3. List every run id into a file first, then delete one at a time, about one call a second (about 800 calls in all, roughly 15 minutes):
     - `gh api 'repos/nbacheller/wrendns/actions/runs?per_page=100' --paginate --jq '.workflow_runs[].id' > <outside>/run-ids.txt`; `wc -l < <outside>/run-ids.txt` equals the first count.
     - `while read -r id; do gh api -X DELETE "repos/nbacheller/wrendns/actions/runs/$id" --silent; sleep 1; done < <outside>/run-ids.txt`
     Deleting a run deletes its logs and artifacts.
  4. Caches: `gh cache delete --all -R nbacheller/wrendns`.
  5. Counts after: the three commands of point 1 each print `0`. If runs appeared meanwhile (a schedule, Dependabot), list and delete again.
- **What it costs:** every GitHub-hosted job starts cold: the Rust caches (`Swatinem/rust-cache`), the npm cache and the build caches are gone, so the first runs compile everything. `_cluster3.yml` notes that a cold image build on a 4-vCPU runner takes well over the 3 to 6 minutes measured warm. **To confirm at step 19:** how long the first `main` and `image` runs take, recorded here. The build box keeps its own caches on the host (`docs/ci-runners.md`, "Shared build caches"), so it is not slowed. The site shows its coverage placeholder until the next `nightly` run makes a report. `deploy/release/preflight.sh` needs a green `main` run on `main`'s head, which step 19 makes.
- **Verify:** point 5.
- **Undo:** none.

### 16. Last look, minutes before the flip

- **Who:** an agent or the owner. Read only.
- **How and verify:**
  - Refs unchanged since step 14: `git ls-remote https://github.com/nbacheller/wrendns.git | awk '$2 != "HEAD" && $2 !~ /\^\{\}$/ {print $1" "$2}' | sort | diff <outside>/refs-at-scan.txt -` prints nothing. If anything differs, go back to step 14.
  - Step 15's three counts print `0`.
  - Step 11's runner check prints `offline` eight times, and `gh variable list -R nbacheller/wrendns` is empty if step 12 ran.
  - `gh api repos/nbacheller/wrendns/forks --jq length` prints `0`.
  - Packages (Q1): `gh api user/packages/container/wrendns` and `gh api user/packages/container/charts%2Fwrendns` answer 404. `telltale` and `charts/telltale` are unchanged from step 3, still private.
- **Undo:** nothing to undo.

### 17. Make the repository public

- **Who:** the owner. **Owner's explicit yes, given now, after a clean step 14 and step 16.**
- **How:** Settings, General, Danger Zone, Change repository visibility, Public, and the typed confirmation. **Step 18 is the very next action, in the same minute**, before anything else: it closes the window in which a fork pull request can leave a queued job for the self-hosted labels (see "What the repository already answers"). Steps 19 to 24 follow at once: E2 puts v1.0.0 within the hour.
- **Verify:** `gh repo view nbacheller/wrendns --json visibility` shows `PUBLIC`, and from a machine with no GitHub login `curl -fsSIL -o /dev/null -w '%{http_code}\n' https://github.com/nbacheller/wrendns` prints `200`.
- **Undo:** **cannot be undone.** Setting it private again stops new readers, but whatever was cloned, forked, fetched or cached meanwhile stays out (step 33).

## Part C: after the flip

### 18. Require approval for fork pull requests, first

From this minute anyone can fork and open a pull request. The runners are stopped (step 11). This setting is what keeps the build box away from forks later (E4).

- **Who:** the owner. **Owner's yes.**
- **How:** Settings, Actions, General, the fork pull request workflow approval setting: **Require approval for all outside collaborators**. GitHub may word the choice as "all external contributors". Save.
- **Verify:**
  - `gh api repos/nbacheller/wrendns/actions/permissions/fork-pr-contributor-approval` now answers with the policy instead of the 422. **To confirm at step 18:** the value it shows for this choice, recorded here.
  - **No queued fork run.** List every pull request run that is waiting, queued, pending or awaiting approval, with its head repository: for each of `queued`, `waiting`, `pending` and `action_required`, `gh api "repos/nbacheller/wrendns/actions/runs?event=pull_request&status=$status&per_page=100" --jq '.workflow_runs[] | [.id, .status, .head_repository.full_name] | @tsv'`. **The rule:** every run whose head repository is not `nbacheller/wrendns` is cancelled at once, before any runner starts: `gh run cancel <id> -R nbacheller/wrendns` (a run still awaiting approval is no threat, but cancel it too and let the contributor push again). Then list again: no fork run remains. Step 26 repeats this and makes zero such runs a condition.
- **Undo:** none wanted. Never relax it while runners are attached.

### 19. Start the first runs after the flip

- **Who:** a command, with the owner's yes. **Owner's yes** (it publishes the edge image, chart and release).
- **How:** the image first, because `main.yml`'s `helm` job pulls the published `edge` image, and under Q1 the package does not exist yet:
  - `gh workflow run image.yml --ref main -R nbacheller/wrendns`. It publishes the edge image and chart (creating the packages again, Q1) and deletes and re-creates the `edge` release, now with attestations.
  - `gh workflow run main.yml --ref main -R nbacheller/wrendns` at the same time, to save time. If its `helm` jobs fail because the edge image is not there yet, re-run them once the image run's `merge` job is green: `gh run rerun <run id> --failed -R nbacheller/wrendns`.
  - `gh workflow run codeql.yml --ref main -R nbacheller/wrendns` after step 21.
- **Verify:** `gh run list -R nbacheller/wrendns --limit 5`: the `image` and `main` runs end `completed success`. Every job ran on a GitHub-hosted runner if step 12 ran (step 20 shows how to read a job's runner).
- **Undo:** none for what was published. Edge is replaced by the next push to `main`.

### 20. The test fork pull requests A and B

**Order:** steps 20 to 22 do not feed the release. If time is short they may follow step 24, with two conditions: step 20 before step 26, and step 22 before step 25. E2's "within the hour" is measured from step 17 to the `v1.0.0` tag push in step 24; what can spend it is the cold first builds of step 19 and step 23's package visibility, not a second GitHub account (below).

- **Who:** the owner, from a second GitHub account that is not a collaborator. **To confirm at step 20:** that such an account exists. **Owner's yes** to approve test A's run.
- **How and verify:**
  - **Test A, a docs change.** Fork, change one line of a doc, and open a pull request to `main`.
    1. The `pr` run (and `main`, if labelled) shows as awaiting approval. `cla` runs anyway: `pull_request_target` is not held for approval, and it checks out no pull request code. Sign with the sentence in `CONTRIBUTING.md` if you want to see a signature written. Read the CLA context name in the checks list (step 31).
    2. Read the whole diff, `.github/` first, then approve the run.
    3. Every job is GitHub-hosted: `gh api repos/nbacheller/wrendns/actions/runs/<run id>/jobs --jq '.jobs[] | [.name, (.labels | join(",")), .runner_name] | @tsv'` shows no `self-hosted` label.
    4. The `privacy` job **fails**: `check-private: required, but neither WRENDNS_PRIVACY_DENYLIST nor WRENDNS_PRIVACY_DENYLIST_TEXT is set`. So `pr-ok` is red, and once step 22 is in place the pull request cannot merge.
    5. `dependency-review` ran.
  - **Test B, a fork that edits `runs-on`.** A second fork pull request changes one job's `runs-on` in `.github/workflows/pr.yml` to `["self-hosted","wrendns"]`. **Never approve it.** It must stay awaiting approval with no job started. Keep it open until step 26.
- **Undo:** close the pull requests and delete the forks after step 26. A test signature stays in `signatures/cla.json` on `cla-signatures`; remove it with a commit there.

### 21. The settings that exist only once public

- **Who:** the owner. **Owner's yes.**
- **How:** Settings, Code security (labels can drift):
  - **Private vulnerability reporting:** enable. `SECURITY.md` links to `https://github.com/nbacheller/wrendns/security/advisories/new`.
  - **Secret scanning** and **Push protection:** enable.
  - **Dependabot alerts:** enable. Version updates keep coming from `.github/dependabot.yml`.
  - **CodeQL default setup must be off:** `gh api repos/nbacheller/wrendns/code-scanning/default-setup --jq .state` prints `not-configured`. If it is on, switch it off: `codeql.yml` is the advanced setup, and GitHub refuses its results while the default setup is on. CodeQL reports only (ADR-1080 point 5). Then step 19's `codeql` dispatch.
  - Q6 is yes (2026-11-25), once step 19's runs are green: Settings, Actions, General, "Require actions to be pinned to a full-length commit SHA" (`sha_pinning_required`).
  - Discussions stay on: `CONTRIBUTING.md` and `README.md` link to them.
- **Verify:** `gh api repos/nbacheller/wrendns --jq .security_and_analysis` shows secret scanning and push protection `enabled` (it was `null` while private). `gh api -i repos/nbacheller/wrendns/vulnerability-alerts` answers `204` when Dependabot alerts are on and 404 when off (GitHub's documented REST endpoint; **to confirm at step 21**). `gh api repos/nbacheller/wrendns/private-vulnerability-reporting --jq .enabled` prints `true` (GitHub's documented REST endpoint; **to confirm at step 21**). The advisory form opens in a private window. The `codeql` run uploads results.
- **Undo:** each can be switched off again.

### 22. The ruleset

- **Who:** the owner. **Owner's yes** (ruleset).
- **How:** Settings, Rules, Rulesets, `main` (id 27699911). Keep: target the default branch, restrict deletions, block force pushes, enforcement Active. Add:
  - **Require status checks to pass**, with the contexts **`privacy`**, **`site`** and **`pr-ok`**. All three are job ids in `.github/workflows/pr.yml` and none has a `name:`, so the context is the job id. `pr-ok` is the aggregate of the CI jobs (ADR-1073). The CLA context comes in step 31. **To confirm at step 22:** `main.yml` has a job `site` too, which reports on a pull request labelled `ci:full`; check which runs GitHub lists for the `site` context before choosing its source.
  - **No bypass actor for the GitHub Actions app** (E6).
  - **No separate pull-request rule** (Q4), and **the repository admin role bypasses for pull requests only** (Q5: set the bypass mode to "For pull requests only", not "Always"). Direct pushes to `main` are then refused, and the owner's merges go through pull requests (merge commits, the subject typed at merge time). **To confirm at step 22:** that GitHub, with no pull-request rule in the ruleset, indeed refuses a direct push by the admin role under this mode (the required checks refuse a commit that has not passed them on another ref), and what the pull request page shows when the owner bypasses; record both here.
  - Do not target `cla-signatures`: `cla.yml` commits to it with the workflow token. CodeQL is not required (ADR-1080 point 5).
- **Verify:** `gh api repos/nbacheller/wrendns/rulesets/27699911 --jq '[.rules[].type], .bypass_actors'` lists `required_status_checks` (three contexts) beside `deletion` and `non_fast_forward`, no `pull_request` rule, and one bypass actor, the repository admin role, with `bypass_mode` `pull_request`, and none for the GitHub Actions app. A pull request from a branch of the repository cannot merge until the three checks are green.
- **Undo:** edit the ruleset back. Its page keeps the history.

### 23. Packages: link and visibility

- **Who:** the owner. **Owner's yes** (packages).
- **How:**
  - After step 19's `merge` and `chart` jobs: `gh api user/packages/container/wrendns --jq '.repository.full_name, .visibility'` and the same for `charts%2Fwrendns`. **To confirm at step 23:** that each re-created package is linked to `nbacheller/wrendns` (through the `Dockerfile` label and the chart's `sources`, or the workflow's repository), and its visibility. If one is not linked, connect it in Package settings.
  - Your profile, Packages: for `wrendns` and `charts/wrendns`, Package settings, Change package visibility, Public.
  - `telltale` and `charts/telltale` stay private here (Q2). Step 24a makes them public.
- **Verify:** with no registry login, `docker pull ghcr.io/nbacheller/wrendns:edge` and `helm pull oci://ghcr.io/nbacheller/charts/wrendns --devel` both work. Each package page links `nbacheller/wrendns`.
- **Undo:** a public package can be set private again, but whatever was pulled stays out.

### 24. Cut v1.0.0 and verify it (E2)

- **Who:** the owner. **Owner's yes** (it publishes a release that can never be moved or reused).
- **Before:** `main`'s head is still the head frozen in step 10, which carries step 5's version and notes; step 19's `main` run on it is `completed success`; DB-IP's terms were re-checked (`docs/releasing.md` step 2).
- **How:** Actions, **release**, Run workflow, version `1.0.0`, `next` left empty (it means `1.1.0`).
- **What `release.yml` does:**
  1. **Preflight** (`deploy/release/preflight.sh 1.0.0`): the version, `Cargo.toml`, `Chart.yaml`, a new tag, the notes, and a green newest `main` run on `main`'s head.
  2. **Tag:** tags `v1.0.0` as `github-actions[bot]` and pushes the tag. The ruleset targets the default branch only, so the tag push is allowed.
  3. **Build and publish the tag:** `gh workflow run image.yml --ref v1.0.0`.
  4. **Next version:** prints a `::notice` that names `deploy/release/bump.sh 1.1.0` and a pull request (step 25). It does not push to `main` and dispatches nothing for `main`, so the run ends green.
- **Then wait** for the **image** run on `v1.0.0`, about 30 minutes: `gh run list --workflow image.yml -R nbacheller/wrendns --limit 3`. It publishes the image tagged `1.0.0`, `1.0`, `1` and `latest`, signed with cosign and now with the provenance and SBOM attestations; the chart `1.0.0`; and the release `v1.0.0`, marked latest, with its notes from `deploy/release/notes/v1.0.0.md` above GitHub's generated notes (from pull request titles, reviewed in steps 4 and 14). The assets are the `wrendns-*` files only, once Q8's change is on `main`. Then **verify** runs `deploy/release/verify.sh 1.0.0` anonymously, which works now.
- **Verify:** the image run's `verify` job is green, every line `ok`. `curl -fsSIL -o /dev/null -w '%{http_code}\n' https://github.com/nbacheller/wrendns/releases/latest/download/SHA256SUMS` prints `200` (`-L` follows GitHub's redirect to the file). The freeze ends here.
- **Undo:** none for the tag (`docs/releasing.md`). A failed job is re-run. A code fix becomes `1.0.1`.

### 24a. Scan and publish the `telltale` packages (Q2)

A separate step after v1.0.0. Nothing before it waits on it, and v1.0.0 does not need it. Making a package public publishes every version of it, so each version is scanned first.

- **Who:** the owner, or an agent the owner trusts with the list. **Owner's yes** to make the packages public and, separately, to delete any version that fails. Making a package public cannot be taken back in effect: whatever was pulled stays out.
- **How:**
  1. List the versions: `gh api 'user/packages/container/telltale/versions?per_page=100' --paginate --jq '.[] | [.id, .name, ((.metadata.container.tags // []) | join(","))] | @tsv' > <outside>/telltale-versions.tsv`, and the same with `charts%2Ftelltale`. Note the counts.
  2. A scan root that is a git repository, since `check-private.py` runs `git ls-files` in `--root` and refuses an `--extra` directory outside it: `mkdir -p <outside>/pkg-scan && git -C <outside>/pkg-scan init -q`. Work in one new, empty directory per version, `<outside>/pkg-scan/v<version id>/`.
  3. Fetch every version with a tool that does not depend on its format, because the package also holds the cosign signature versions (images have been signed since 2026-10-17) and per-platform images, which `docker pull` by digest does not cover. Use `skopeo copy --all docker://ghcr.io/nbacheller/telltale@<digest> oci:<outside>/pkg-scan/v<id>/oci` or `crane pull --format=oci ghcr.io/nbacheller/telltale@<digest> <outside>/pkg-scan/v<id>/oci`. **To confirm at step 24a:** which of `skopeo` and `crane` is installed on the owner's machine (neither is confirmed here); install one. Then make the content text the scan can read, because the script skips binary files (a file with a NUL byte near its start):
     - Signature and attestation versions are scanned by their manifest and payload JSON, kept as text.
     - For an image manifest, keep its config and manifest JSON (labels, build history) and extract every filesystem layer into `rootfs/` (`tar -xf <layer> -C rootfs/`, as an unprivileged user, never from inside an extracted directory), for each platform.
     - Record the symlinks, then delete them, because the scan follows a link and an absolute one would read a file of the scanning host: `find rootfs -type l -printf '%p -> %l\n' >> paths.txt`, then `find rootfs -type l -delete`.
     - Write the printable strings of every binary: `find rootfs -type f -exec sh -c 'file -b "$1" | grep -q ELF && strings "$1" > "$1.strings.txt"' _ {} \;`.
     - Write the file names too, `find . -type f >> paths.txt`, since extra files are scanned by content and not by name.
  4. For each chart version: `helm pull oci://ghcr.io/nbacheller/charts/telltale --version <v> --untar --untardir <outside>/pkg-scan/v<id>/chart`.
  5. Scan: `WRENDNS_PRIVACY_DENYLIST=<list> python3 <checkout>/scripts/check-private.py --root <outside>/pkg-scan --require --extra v<id1> --extra v<id2> ...` (each `--extra` path is relative to `--root`, and every directory under it is read recursively). A hit prints a path and `pattern #N`, never the value.
  6. A version that fails is deleted (Package settings, or `gh api -X DELETE user/packages/container/telltale/versions/<id>`), **with the owner's yes**, and the scan is repeated for the rest.
  7. When every remaining version is clean: your profile, Packages, `telltale`, Package settings, Change package visibility, Public, and the same for `charts/telltale`.
- **Verify:** the scan prints `check-private: N file(s) clean against M pattern(s)` and exits 0 (exit 2 is not a pass). `docker pull` of an old tag of `ghcr.io/nbacheller/telltale` and `helm pull oci://ghcr.io/nbacheller/charts/telltale --version <v>` work with no login. `LICENSING.md` is then true as it reads: they are public, as an archive.
- **Undo:** a public package can be set private again, but whatever was pulled stays out. A deleted version may be restorable for a limited time (**to confirm**).

### 25. Start 1.1.0 through a pull request (E6)

- **Who:** an agent or the owner.
- **How:** on a branch, `deploy/release/bump.sh 1.1.0`, commit `chore: start 1.1.0 development (after v1.0.0) [OPS-004]`, open a pull request and merge it once the required checks are green. The merge starts CI and edge. Until then edge builds read `1.0.0-edge.N`, which sorts below the release; that is short and harmless.
- **Verify:** `Cargo.toml` on `main` says `1.1.0`, and the next edge is `1.1.0-edge.N`.
- **Undo:** revert.

### 26. Start the runners, then test C

- **Who:** the owner, on the build box. **Owner's yes** (build box, variables, and approving test C's run). Only after step 18 is verified and step 20's tests behaved as stated, **and only with zero fork runs waiting** (point 0).
- **How:**
  0. **Before any runner starts**, repeat step 18's four listings (`queued`, `waiting`, `pending`, `action_required`, `event=pull_request`). Cancel every run whose head repository is not `nbacheller/wrendns` (`gh run cancel <id> -R nbacheller/wrendns`), then list again. **Condition of the owner's yes:** no such run is left. Test B stays awaiting approval with no job started; if it shows up as `queued` or `waiting`, cancel it and open it again later. A run from a branch of this repository may stay.
  1. Start each runner's supervisor ("Adding a runner", point 4, in `docs/ci-runners.md`). The runners keep their registration: the identity was copied, not re-registered. **To confirm at step 26:** the exact command on the build box, recorded here.
  2. If step 12 ran: `gh variable set WRENDNS_RUNNER -R nbacheller/wrendns --body '["self-hosted","wrendns"]'` and the same for `WRENDNS_PR_RUNNER`.
  3. **Test C:** push one more commit to test A's fork branch. The commit touches nothing under `.github/` and no `runs-on`; approve the new run after reading its diff, and check with step 20's jobs command that every job is still GitHub-hosted, now that the variables are set and runners are attached.
- **Verify:** the listings of point 0 held no fork run when the runners started. `gh api repos/nbacheller/wrendns/actions/runners --jq '.runners[].status'` prints `online` eight times. A pull request from a branch of this repository runs `clippy` on the box. Test B is still awaiting approval with no job started. Then close tests A and B, with a comment that follows E5.
- **Undo:** stop the supervisors and delete the variables. Every job then falls back to `ubuntu-latest`.

### 27. The site switch

`site/build.py` shows GitHub, release and installer links only when `repoPublic` is `true` in `site/data/site.json`. The held branch `ci/flip-public` (commit `e90dc176`) sets it, updates the site test that pins it, and rewords two comments in `.github/workflows/main.yml` that say the package and the repository are private. Push it only after v1.0.0's `verify` is green and the packages are public, so every link it turns on answers.

- **Who:** an agent prepares it. **Owner's yes** to push and merge.
- **How:**
  - `e90dc176` was committed with an address that is not the noreply address, so re-author it on today's `main`: `git rebase --exec 'git commit --amend --no-edit --reset-author' origin/main ci/flip-public`, with the noreply address set in `user.email`. Check: `git log -1 --format=%ae ci/flip-public | grep -c '@users.noreply.github.com$'` prints `1`.
  - `python3 site/build.py --check`, `python3 site/test_site.py` and `python3 scripts/check-workflows.py`.
  - Push the branch, open a pull request, merge once the required checks are green. `site.yml` deploys on the push to `main`, with its privacy check first.
- **Verify:** on https://www.wrendns.com the Download, Install, Standards and Developers pages show links instead of "Source and downloads open at launch", and each answers (step 29).
- **Undo:** set `repoPublic` back to `false` in a pull request.

### 28. The social preview

- **Who:** the owner. **Owner's yes.** The API cannot set it.
- **How:** Settings, General, Social preview: upload `brand/social-preview.png` (1280 by 640; `brand/README.md`, "Social preview").
- **Verify:** paste the repository address into a post preview.
- **Undo:** remove the image on the same page.

### 29. Anonymous checks from the outside

- **Who:** a command, from a machine or private window with no GitHub login and no registry login. Every `curl` below uses `-L`, so it follows redirects and reports the final answer; `-o /dev/null -w '%{http_code}\n'` prints only that code.
- **How and verify:**
  - `curl -fsSIL -o /dev/null -w '%{http_code}\n' <url>` prints `200` for each of `https://github.com/nbacheller/wrendns`, `https://raw.githubusercontent.com/nbacheller/wrendns/main/deploy/systemd/install.sh`, `https://github.com/nbacheller/wrendns/releases/latest/download/SHA256SUMS`, `https://github.com/nbacheller/wrendns/releases/download/edge/SHA256SUMS` and `https://github.com/nbacheller/wrendns/releases/tag/permissive-final`.
  - `curl -sIL -o /dev/null -w '%{http_code}\n' https://github.com/nbacheller/wrendns-archive` prints `404`. **To confirm at step 29:** that `https://github.com/nbacheller/telltaledns` also answers `404` (it redirects to the private archive), recorded here.
  - Only runs after the flip are public: `curl -fsSL 'https://api.github.com/repos/nbacheller/wrendns/actions/runs?per_page=1'` shows a `total_count` that counts only runs since step 19.
  - `docker pull ghcr.io/nbacheller/wrendns:1.0.0` and `helm pull oci://ghcr.io/nbacheller/charts/wrendns --version 1.0.0` work.
  - On a disposable machine or container: `curl -fsSLO https://raw.githubusercontent.com/nbacheller/wrendns/main/deploy/systemd/install.sh`, read it, then `sudo sh install.sh`. It checks `SHA256SUMS` against the release key.
  - `minisign -Vm SHA256SUMS -p deploy/release/wrendns-release.pub` on the downloaded `SHA256SUMS` and its `.minisig`.
  - `cosign verify ghcr.io/nbacheller/wrendns:1.0.0 --certificate-identity-regexp '^https://github\.com/nbacheller/wrendns/\.github/workflows/image\.yml@' --certificate-oidc-issuer https://token.actions.githubusercontent.com` (the identity `verify.sh` uses).
  - The Discussions, Issues and Security tabs load. The site's external links answer (`site/build.py --check` checks only the internal ones).
- **Undo:** nothing to undo.

### 30. The Software Heritage save

`LICENSING.md` says a save of `https://github.com/nbacheller/wrendns` at Software Heritage has been requested, and spec/10 T33.5 says "requested, not confirmed". It cannot have succeeded while the repository was private.

- **Who:** the owner. **Owner's yes** (it copies the repository into a public archive for good).
- **How:** request a save of `https://github.com/nbacheller/wrendns` with Software Heritage's "Save code now" form. **To confirm at step 30:** the form's address, from `https://www.softwareheritage.org/`. Once the save is shown as done, update `LICENSING.md` (and spec/10 T33.5) through a pull request.
- **Verify:** Software Heritage lists the repository with a visit after the flip.
- **Undo:** none: an archived copy stays.

### 31. The CLA context in the ruleset

ADR-1080 point 1 requires four checks; the fourth is the CLA's. `cla.yml` runs `contributor-assistant/github-action` with `statuses: write` on `pull_request_target`.

- **Who:** the owner. **Owner's yes** (ruleset).
- **How:** read the context name from the checks list of test A (step 20) or of step 25's pull request. **To confirm at step 31:** whether the action posts its status for an allow-listed author such as `nbacheller`; if it does not, only fork pull requests carry it, and requiring it would block every maintainer pull request. Then add it to step 22's required checks, and record the name in the header of `cla.yml` in a pull request (T39.13).
- **Verify:** step 22's `gh api` call lists four contexts. A maintainer pull request still merges.
- **Undo:** remove the context from the ruleset.

## The record of 2026-11-25

Part A's step 9 and Parts B and C up to step 25 were carried out on 2026-11-25. Times are UTC. Each step had the owner's yes at the time, through the question tool.

- **Step 9:** the leftover branches and tags were deleted; the list is kept with the owner.
- **Step 10, 14:58:** the freeze began. No scheduled run fell inside the window.
- **Step 11:** the eight supervisors (`wrendns-lxd-runner@01` to `08`) were disabled and each container's runner service stopped, then the container powered off: the first two points of `rollback-runner.sh`, without its third. Each service stop took its full five-minute timeout. All eight runners read `offline` at 15:15. To start them again (step 26): `systemctl enable --now wrendns-lxd-runner@NN` for each.
- **Step 12:** both variables deleted.
- **Step 13:** `wrendns` (417 versions) and `charts/wrendns` (34) deleted through the API. Both were still linked to the earlier repository.
- **Step 14:** the `privacy-full` job of `nightly.yml`, dispatched on `main`'s head: the history of 1,532 commits, the tree of 1,414 files and the 19 files of the `edge` release, each clean against 61 patterns. Items #109 to #115 were read. One collaborator; no invitation, fork, webhook or deploy key. Not done, and accepted by the owner: a secret scanner over the mirror, and Q11's scan of local clones (nobody holds the list outside the repository secret).
- **Step 15:** 854 runs, 402 artifacts and about 217 caches deleted. GitHub answered many of the deletions with HTTP 500, and `gh cache delete --all` stops at the first failure; deleting each run, artifact and cache by id, in repeated passes, brought all three counts to 0 in about 45 minutes. The `cache/usage` figure lagged behind the empty cache list.
- **Step 16:** refs unchanged since the scan, and every other check as written.
- **Step 17, 16:47:27:** the owner made the repository public.
- **Step 18, 16:47:28:** set through the API: `PUT repos/nbacheller/wrendns/actions/permissions/fork-pr-contributor-approval` with `{"approval_policy":"all_external_contributors"}`. The read-back showed the old value for a few seconds, then `all_external_contributors`. No fork and no waiting fork run.
- **Step 19:** `image`, `main` and `codeql` on `main`'s head, all on GitHub-hosted runners with cold caches: `image` took about 30 minutes. `main`'s two `helm` jobs failed once because the edge image did not exist yet, and passed on the re-run.
- **Step 21:** private vulnerability reporting, secret scanning and push protection enabled through the API; Dependabot alerts answered 204; CodeQL default setup was `not-configured`. `sha_pinning_required` set to `true` after the green runs.
- **Step 22:** the ruleset updated through the API: `required_status_checks` with `privacy`, `site` and `pr-ok` (the GitHub Actions app as their source) beside `deletion` and `non_fast_forward`; one bypass actor, the repository admin role, in `pull_request` mode. Pull request #116 merged with the three checks green. Whether a direct push by the admin role is refused was not tried.
- **Step 23:** the image run re-created both packages already public and linked to `nbacheller/wrendns`; nothing had to be changed. Both pull with no login.
- **Step 24, 17:28 to 17:49:** `release.yml` with version `1.0.0` tagged `v1.0.0` on `0a787a28` and printed its next-version notice; the `image` run on the tag was green, `verify` included. The release has 13 files. From the flip to the release: 62 minutes.
- **Step 25:** pull request #116, `1.1.0` on `main`.

- **Step 26, 20:22:** the owner could not run step 20's fork tests for the foreseeable future and gave the yes for step 26 without them; no fork, fork pull request or waiting fork run existed; the eight supervisors were enabled again with `systemctl enable --now wrendns-lxd-runner@NN`, all eight runners read online, and both variables were set again. Consequence: nothing has shown in practice that a fork pull request waits for approval, so no fork run is approved before its whole diff is read.
- **Step 27:** the site switch went through a pull request (#118).

Still open after this record: step 20's fork tests, step 24a, and steps 28 to 31.

## Part D: standing procedures

### 32. Accepting a contribution (E5)

- **Who:** a maintainer.
- **How:**
  1. Read the whole change. Its branch will run on the build box with this repository's secrets, so read everything under `.github/`, build scripts, `build.rs` files and tests first.
  2. The contributor signs the CLA on their fork pull request (`cla.yml`).
  3. `git fetch origin pull/<N>/head:contrib/pr-<N>`, then `git push origin contrib/pr-<N>`. The commits keep their hashes and their authorship.
  4. Open a pull request from `contrib/pr-<N>`. Every check runs, the privacy check included. **To confirm the first time:** that the CLA check finds the contributor's signature on this pull request.
  5. Merge it once the required checks are green.
  6. `gh pr close <N> -R nbacheller/wrendns --comment 'Merged in #<M>, with your authorship kept. Thank you.'`

  No required check is bypassed. A maintainer never approves a fork run whose diff touches `.github/` or changes a `runs-on`.
- **Verify:** the merged commits show the contributor as author.
- **Undo:** revert the merge.

### 33. If something private is found after the flip

- **Who:** the owner decides each step. **A history rewrite or a force push needs the owner's explicit yes**, and E1 rules it out unless the owner changes it.
- **How, in order:**
  1. Make the repository private again (step 17's undo). This also hides the releases from installed nodes. GitHub splits public forks off into their own network, and they stay public.
  2. Write down where the value is (file and line, issue and comment, run id, package version) without copying it.
  3. Rotate the value first, if it is a credential.
  4. Remove it:
     - in the tree: a normal pull request;
     - in an issue, comment or release: delete or edit it, keeping in mind that edit history is visible;
     - in a log: delete the run;
     - in a package: delete the version;
     - in history or a `refs/pull/*` ref: a rewrite of the affected refs and a force push, then GitHub Support to remove cached views and pull request refs.
  5. Run steps 7, 8 and 14 again until clean.
  6. Only then, step 17 again.
- **Verify:** the scans are clean.
- **Undo:** none. A value that was public may have been copied, which is why the gate in step 14 comes first.

## Open questions for the owner

Each is asked through the question tool at step 2. The recommendation is not a decision. On 2026-11-24 the owner answered Q1, Q2, Q4, Q5, Q7, Q8, Q9 and Q11; the answers are in "The route, and the owner's decisions of 2026-11-24". Q3, Q6 and Q10 were answered on 2026-11-25:

- **Q3. Remove the two runner variables for the window (step 12)?** **Recommended: yes.** Every job then runs on GitHub-hosted runners until step 26, nothing queues for the stopped box, the first public logs name no machine, and step 19's `main` run can make preflight's green run without the box. Without it, step 19's `main` run waits for the runners, so the release waits for steps 20 and 26.
- **Q6. Turn on `sha_pinning_required`?** `scripts/check-workflows.py` already enforces the pinning. **Recommended: yes**, at step 21, after step 19's runs are green.
- **Q10. The text found in step 4:** edit, delete or keep, item by item.

The owner's answers of 2026-11-25:

- **Q3: yes.** The two variables are removed for the window and put back at step 26.
- **Q6: yes, after the first public runs.** `sha_pinning_required` is turned on at step 21, once step 19's runs are green.
- **Q10: a page to mark up.** An agent prepares a private page that lists each item of step 4 with its flagged text and a suggested action (keep, edit or delete). The owner marks each one. Nothing on GitHub changes before those marks, and each change keeps its own yes.

Answered 2026-11-24, kept here with the reasoning that was put to the owner:

- **Q1. The packages `wrendns` and `charts/wrendns`: answered, delete both.** They hold 333 and 27 versions from the private era, back to 2026-11-19, and are linked to `nbacheller/wrendns-archive`. Both packages are deleted before the flip (step 13), and step 19's first image run creates them again from the scanned tree. Nothing public is lost: no stable version exists, and nobody outside could pull the old ones. `main.yml`'s `helm` job fails until edge exists, which step 19 handles. Not confirmable from here: whether a deleted package's name can be used again at once (if not, restore the package, delete its versions but the newest edge, and scan before making it public), and whether a package created by the workflow is linked to `nbacheller/wrendns` and private or public at first (step 23 checks).
- **Q2. The `telltale` and `charts/telltale` packages: answered.** Public after a scan of their versions against the denylist, as a separate step after v1.0.0 (step 24a). `LICENSING.md` says they "are made public as an archive ... once checked".
- **Q4. "Require a pull request before merging": answered, no.** With required checks alone, a pushed commit must already have passed the checks on another ref.
- **Q5. The admin bypass: answered, for pull requests only.** Direct pushes to `main` are refused, the owner's local `merge: ... into main` pushes end, merges go through pull requests, and a bypass is visible on the pull request.
- **Q7. The tags `fork-base` and `upstream-sync-last`: answered, delete** (step 9). Nothing in the repository refers to them, and ADR-1026 ended upstream syncs. Their commits stay in `main`'s history.
- **Q8. The `telltale-*` copies in the releases: answered, stop publishing them before v1.0.0.** No code path of this project reads a `telltale-*` asset: `updates.rs` and `install.sh` read `wrendns-*` from `nbacheller/wrendns`, and an old TelltaleDNS binary reads upstream's releases and trusts only upstream's key (ADR-1028 point 8, ADR-1034, `docs/running.md`). ADR-1028 point 10 had planned this for the release after. The migration path itself stays: `deploy/systemd/migrate-from-telltale.sh`, the `install.sh` hooks, the `legacy*` modules and the `rebrand:keep` formats.
- **Q9. The branches: answered, delete the merged work branches before the final scan; Dependabot's are left.**
- **Q11. Commits that no ref reaches: answered, option 1, and option 3 for the remainder.** Scan the owner's local clones with the privacy check, and accept in writing what that cannot reach: GitHub's own unreachable objects cannot be listed, and asking GitHub Support to garbage-collect (option 2) is slow and not guaranteed.

## Tasks to do before the flip

Marked "done" when the change is on branch `chore/pre-flip-tasks` (2026-11-24); a task counts as landed when that branch is merged.

- **Done.** `.github/workflows/release.yml`, "Move main to the next version": the step no longer bumps, commits or pushes, and no longer dispatches `main.yml` and `image.yml`; it ends with one `::notice` that names `deploy/release/bump.sh <next>` and a pull request. Why the two dispatches went: they existed to start CI and edge for the bump commit, because a push with the workflow's token starts no workflows. With no bump commit, `main`'s head is the commit that was just released, and CI on it was already green (preflight requires it); the tag's own build is started by the "Build and publish the tag" step; the pull request that bumps the version starts CI, and its merge starts CI and edge. The job keeps `contents: write` (the tag push) and `actions: write` (the dispatch of `image.yml` for the tag). The header, `docs/releasing.md`, the header of `deploy/release/bump.sh` and the comment at `.github/workflows/main.yml` line 17 say the same.
- **Done.** `AGENTS.md` rule 9: `main` then moves on through `deploy/release/bump.sh` and a pull request.
- **Done.** `docs/ci-runners.md`, "Trust model": the `runs-on` expression is not a barrier against a fork, which can edit it; the barriers are the fork-approval setting, the rule that a maintainer never approves a fork run whose diff touches `.github/` or `runs-on`, and the runners being unprivileged, reset containers.
- **Done.** `CONTRIBUTING.md` (the privacy check paragraph) and the comment above the `privacy` job in `.github/workflows/pr.yml`: the E5 procedure (step 32) instead of "a maintainer runs the check on a branch".
- **Done.** `LICENSING.md`: the sentence on `ghcr.io/nbacheller/telltale` and `ghcr.io/nbacheller/charts/telltale` says they are made public as an archive once checked (Q2).
- **Done (Q8).** `deploy/release/legacy-assets.sh`, its use in the Checksums step of `.github/workflows/image.yml`, `deploy/release/tests/legacy-assets-test.sh` and its lines in `.github/workflows/main.yml` and `.github/workflows/pr.yml`, "The rename window" in `docs/releasing.md`, and the release-files row in the rename table of `docs/running.md` are removed. A dated owner-decision note is in ADR-1028 (items 8 and 10) in `spec/11-decisions.md`.
- `deploy/release/notes/v1.0.0.md` and the 1.0.0 version (`deploy/release/bump.sh 1.0.0`): step 5.
