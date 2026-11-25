# Releasing WrenDNS

How stable releases are cut. Written for maintainers and for agents: follow it as is. The
**release** workflow does the steps the same way every time; this page explains what it
does, what to check, and what to do when a step fails. Decision record: ADR-097.

## Versions and channels

| | Built from | Binaries (`wrendns --version`) | Container image | Helm chart | GitHub |
|---|---|---|---|---|---|
| **edge** | every push to `main` | `X.Y.Z-edge.N`, channel `edge` | `:edge`, `:sha-<7 chars>` | `X.Y.Z-edge.N` (appVersion `edge`) | the `edge` prerelease, replaced each time |
| **stable** | a `vX.Y.Z` tag | `X.Y.Z`, channel `stable` | `:X.Y.Z`, `:X.Y`, `:X`, `:latest` | `X.Y.Z` (appVersion `X.Y.Z`) | release `vX.Y.Z`, marked latest |

- `X.Y.Z` on `main` is the version being worked toward: `[workspace.package] version` in
  `Cargo.toml` and `version` in `deploy/helm/wrendns/Chart.yaml` (always equal). `N` is the
  image workflow's run number.
- Semver sorts `X.Y.Z-edge.N` **below** `X.Y.Z`. So as soon as `X.Y.Z` is released, `main`
  moves to the next version (`X.Y+1.0` by default), through a pull request (step 5 below).
  Until then edge builds look older than the release, and `helm --devel` and update checks
  don't offer them.
- `install.sh` and `wrendns self-update` take the **latest release** for `stable` (GitHub's
  `releases/latest`, which skips prereleases) and the `edge` prerelease for `--edge` /
  `--channel edge`. Both verify `SHA256SUMS` against the release key; an unsigned release
  isn't installable.
- `:sha-<7 chars>` images are immutable. Pin one (with chart `X.Y.Z-edge.N`) to deploy a
  specific edge build through GitOps.

## Cutting a release

1. **Write the notes** in a pull request: `deploy/release/notes/vX.Y.Z.md`, a short Markdown
   summary for people upgrading (highlights, anything to do when upgrading, known issues).
   GitHub appends its generated changelog below it. Merge the pull request once its required
   checks pass, then wait for CI (`main.yml`) to pass on `main`'s new head. Tasks may start the
   file early, with upgrade items, under a first line beginning `_Draft`: preflight refuses
   the notes until that line is gone.
2. **Re-check DB-IP's terms** (ADR-959 section 1): open the DB-IP.com IP to Country Lite page,
   confirm the licence is still CC BY 4.0 with free redistribution of the derived file and the
   attribution wording in `docs/third-party-notices.md` is still what they ask for. If it
   changed, stop here, before the workflow, and open an issue: the GeoIP feature's source needs a new ADR.
3. **Run the workflow:** GitHub → Actions → **release** → Run workflow, version `X.Y.Z`
   (`next` is optional; the default is `X.Y+1.0`).
4. **Watch two runs:**
   - **release** (about a minute): preflight, tag, start the tag's build, then try to move
     `main` on. The ruleset on `main` requires checks and has no bypass for the workflow
     (ADR-1080, owner decision 2026-11-24; it is set when the repository goes public,
     `docs/going-public.md`), so that last push is refused. The step fails and the run ends red, but the
     release itself is not affected: the tag and its build were started before it.
   - **image** on ref `vX.Y.Z` (about 30 minutes): build and test every architecture, push
     the image tags, publish the chart, sign and publish the GitHub release, then
     **verify**. The release is done when `verify` is green.
5. **Move `main` on** through a pull request: on a branch, run `deploy/release/bump.sh <next>`
   (`X.Y+1.0` unless you chose another), commit
   (`chore: start <next> development (after vX.Y.Z) [OPS-004]`), open a pull request and merge
   it once the required checks pass. The merge starts CI and edge by itself.
6. **After:** the README's release badge updates itself. Deployments that follow edge pin
   the next edge chart as usual.

### What preflight checks

`deploy/release/preflight.sh X.Y.Z` stops before anything is published unless:
the version is `X.Y.Z` (no suffix); `Cargo.toml` and `Chart.yaml` say `X.Y.Z`; the tag
`vX.Y.Z` doesn't exist; `deploy/release/notes/vX.Y.Z.md` exists; and the newest run of the `main` workflow (`main.yml`) on
`main`'s head passed.

### What verify checks

`deploy/release/verify.sh X.Y.Z` (run by the tag build, or by hand with `curl`, `minisign`,
`helm`, and `docker`):
`SHA256SUMS` and `releases.json` are signed with `deploy/release/wrendns-release.pub`; the
x86_64 binary matches its sum and reports `X.Y.Z … channel stable`; all three architectures
are listed with their SBOM and their debug file (`wrendns-<arch>-linux.debug.zst`, the symbols
that make a stack from the stripped binary readable); `releases/latest` points at `vX.Y.Z`; `:X.Y.Z`, `:X.Y`, `:X`, and `:latest` are
the same multi-arch image (amd64, arm64, arm/v7); chart `X.Y.Z` has appVersion `X.Y.Z`.

## The rename window (T33.2)

<!-- rebrand:keep-start -->
For the first release after the rename, `deploy/release/legacy-assets.sh` also copies each binary to its pre-rename name (`telltale-<arch>-linux`, the same bytes) before the checksums are made, so `SHA256SUMS` and the release carry both names. A node still running the old `self-update` looks for the old name and would otherwise find nothing. The release after that drops the script and the step in `.github/workflows/image.yml` (ADR-1028 lists everything that goes), and `deploy/release/tests/legacy-assets-test.sh` with them.
<!-- rebrand:keep-end -->

## When something fails

- **Preflight fails:** nothing was published. Fix what it names (often: CI hasn't finished,
  or the notes file is missing) and run the workflow again.
- **The tag's image run fails** (a flaky test, a registry hiccup): re-run the failed jobs on
  that run. Nothing is re-tagged.
- **The tag needs a code fix:** never move or reuse a published tag. Fix it through a pull
  request, set the version to the patch release in a pull request
  (`deploy/release/bump.sh X.Y.Z+1`, wait for CI on `main`), write `notes/vX.Y.Z+1.md`, and
  release `X.Y.Z+1`. Then move `main` on through a pull request again (step 5).
- **Moving `main` on fails in the release run:** this is expected. The ruleset refuses the
  workflow's push to `main` (ADR-1080, owner decision 2026-11-24), and the CI and edge
  dispatches after that push do not run. The release itself is fine. Move `main` on as step 5
  says.
- **Verify fails:** it prints each check as `ok` or `FAIL`. Registry or "latest" lag gets
  three tries; anything else is a real problem: fix it, then re-run the `verify` job.

## Without the workflow

From a machine with push access: `git tag -a vX.Y.Z -m "WrenDNS X.Y.Z"` on a commit
whose CI passed, then `git push origin vX.Y.Z`. A tag pushed by a person starts the image
workflow by itself. Then move `main` on through a pull request (step 5 above), and check with
`deploy/release/verify.sh X.Y.Z` once the tag's build is green.

## Things that aren't obvious

- **A tag or commit pushed with a workflow's own token starts no workflows.** That's why the
  release workflow starts the tag's build explicitly (`gh workflow run`). Its dispatch of CI
  and edge for a version commit never runs while the ruleset refuses that commit's push. `main.yml` and `image.yml` accept `workflow_dispatch` for this. The
  image workflow's push, sign and publish jobs (`merge`, `chart`, `release`, `verify`) run for
  pushes *and* dispatches on `main` or `v*` tags; a dispatch on a branch only builds and tests.
  Each architecture is one leg (`image`) that compiles once and pushes its image by digest;
  `merge` joins the three into the tagged manifest list and signs it.
- **Workspace crates name each other's version** (`wrendns-proto = { version = "X.Y.Z",
  path = … }`). A version change has to update them and `Cargo.lock` too: use
  `deploy/release/bump.sh`, never a hand edit. The committed OpenAPI document
  (`docs/api/openapi.json`, `info.version`) carries the version too; CI fails if it's stale,
  and `bump.sh` updates it (learned from v0.1.0: the first bump missed it).
- **`Chart.yaml` says `appVersion: "edge"`** on `main`. The tag's build packages the chart
  with appVersion `X.Y.Z`, so a stable chart installs the matching stable image.
- **Signing needs the `MINISIGN_SECRET_KEY` secret.** Without it the build warns and
  publishes nothing. The public half lives in `deploy/release/wrendns-release.pub`,
  `crates/wrendns/src/selfupdate.rs`, and `deploy/systemd/install.sh`. A new key means
  updating all three (the test `ops_004_release_key_is_the_same_in_all_three_places` checks they agree; ADR-1034).
- **The `edge` prerelease is deleted and re-created** by each push to `main`. A superseded
  run steps aside instead of racing the newer one. It never affects "latest".
