# Developer container (telltale-dev:1)

A reproducible dev environment for TelltaleDNS, so the toolchain can be swapped without touching
the repo. It is not a release image: nothing here is shipped, and CI does not use it.

## What is in the image

| Area | Contents |
|---|---|
| OS | Ubuntu 24.04, pinned by digest in the Dockerfile |
| Rust | `rustup` with the repo's pinned toolchain (1.99.0, `rust-toolchain.toml`) plus `rustfmt`, `clippy` |
| Build speed | `mold` through `clang` as linker. `sccache` is installed but off by default (see below) |
| Cargo tools | `cargo-nextest`, `cargo-deny`, `cargo-bloat` (versions pinned in the Dockerfile) |
| UI | Node 24, Playwright 1.65.0 with Chromium and its system libraries |
| Other | `python3`, `dnsperf`, `snmp` tools (net-snmp), `git`, `clang`, `bc` |

Not installed: `cargo-llvm-cov` (used by the nightly CI job). Add it when a coverage run is needed.

Environment variables set by the image (not by the repo):

- `CARGO_TARGET_DIR=/target`
- `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang`, `RUSTFLAGS="-C link-arg=-fuse-ld=mold"`
- `SCCACHE_DIR=/sccache`, `SCCACHE_CACHE_SIZE=20G` (used only when sccache is enabled)

`RUSTC_WRAPPER` and `CARGO_INCREMENTAL` are not set by the image, so cargo's defaults apply and
incremental builds work. The image's own `cargo install` layers never touch sccache.

### sccache is opt-in

The earlier image set `RUSTC_WRAPPER=sccache` and `CARGO_INCREMENTAL=0` for every build. A run on
the earlier container showed almost no Rust cache hits (1 hit, 1089 misses), so no speedup was
shown. Enable it per shell only to test it:

```bash
RUSTC_WRAPPER=sccache cargo build -p telltale
sccache --show-stats
```

Compare it with a plain build on an idle machine before relying on it. Do not add it to the image
without that comparison.

The repo has no `.cargo/config.toml` that would conflict with these. If the CI runners should use
mold too, they need the same linker setting; that is a separate decision (not made here).

## Build and start

```bash
deploy/dev/up.sh            # build the image if missing, create volumes, clone once, start wrendns-dev2
deploy/dev/up.sh --rebuild  # rebuild the image after editing the Dockerfile
deploy/dev/up.sh --sync     # fetch new commits from the Windows repo into the clone
```

`--sync` needs `wrendns-dev2` to be running; it stops with an error otherwise.

Volumes (created by `up.sh`, never removed by it):

| Volume | Mounted at | Holds |
|---|---|---|
| `tt-src` | `/src` | the Linux clone, `/src/telltale`; worktrees go in `/src/telltale/.wt/<name>` |
| `tt-cargo2` | `/root/.cargo/registry` | crates.io index and sources, for `wrendns-dev2` only |
| `tt-sccache` | `/sccache` | compiled-object cache (only when sccache is enabled) |
| `tt-target2` | `/target` | `CARGO_TARGET_DIR` |

`tt-cargo` is not used by this image. It is the whole `CARGO_HOME` of the older `wrendns-dev`
container, so mounting it here wrote cargo's cache files into that container's home. Do not mount
it here.

The Windows repo is mounted read-only at `/mnt/win` for sync and the first clone.

Start the container with `docker exec -it wrendns-dev2 bash`. Its working directory is `/src/telltale`.

## Git inside the container

- The clone's remote `winrepo` is the Windows checkout (`/mnt/win`, read-only). `up.sh --sync`
  runs `git fetch winrepo --prune`, then a best-effort `git fetch origin --prune`.
- `origin` is set on first clone from `TT_ORIGIN` (default: the Windows checkout's `origin` URL),
  so pushes and pulls can go through the real remote instead. The container has no credentials
  for it, so fetches from `origin` may fail; `--sync` then still succeeds.
- Set your identity inside the container (`git config --global user.name ...`); the volume keeps it.
  No `.gitconfig` is created by the image.
- Work in a worktree: `git worktree add .wt/<name> -b <branch> feat/ipam-integrations` from
  `/src/telltale`, then `cd .wt/<name>` and use `CARGO_TARGET_DIR=/target/<name>`.
- Line endings: the clone sets `core.autocrlf input`, so files are LF. Tests then pass without the
  CRLF fixes the Windows checkout needs (the 6-8 tests that fail only from CRLF).

## Checks

Inside the container:

```bash
cargo build -p telltale
cargo nextest run -p telltale-policy
cd ui && npm ci            # installs playwright from ui/package-lock.json (1.65.0), once per volume
cd ui && TELLTALE_BIN=/target/debug/telltale npx playwright test
```

`npm ci` in `ui` is required before the Playwright run. Without it, `npx` may fetch a different
Playwright whose Chromium revision is not installed in `/ms-playwright`.

The `telltale` crate tests have not been run in this container yet. Run them on an LF export
(`git -c core.autocrlf=false archive HEAD`) to get a clean result.

## Reproducibility

- The base image is pinned by digest; the Dockerfile says when to bump it.
- Node is pinned to a major version (NodeSource). rustup-init comes from `sh.rustup.rs` and is not
  pinned. apt packages are not pinned. A rebuild can therefore drift in these areas.

## Not in the image

- `helm`, the Docker CLI for building release images, and `cargo-zigbuild` (the release build
  stage stays in `Dockerfile` at the repo root).
- Secrets. `deploy/docker-desktop/secrets/` is never read or copied.

## Rollback

`wrendns-dev` is not used by this image and its volumes are not mounted here. To go back, use it as
before. Stray cargo files written into `tt-cargo` by earlier `wrendns-dev2` runs remain there and need
removing by hand before `wrendns-dev` is used again.
