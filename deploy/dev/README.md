# Developer container (telltale-dev:1)

A reproducible dev environment for TelltaleDNS, so the toolchain can be swapped without touching
the repo. It is not a release image: nothing here is shipped, and CI does not use it.

## What is in the image

| Area | Contents |
|---|---|
| OS | Ubuntu 24.04 (as the old `wrendns-dev`) |
| Rust | `rustup` with the repo's pinned toolchain (1.99.0, `rust-toolchain.toml`) plus `rustfmt`, `clippy` |
| Build speed | `sccache` as `RUSTC_WRAPPER` (cache on the `tt-sccache` volume); `mold` through `clang` as linker |
| Cargo tools | `cargo-nextest`, `cargo-deny`, `cargo-bloat` (versions pinned in the Dockerfile) |
| UI | Node 24, Playwright 1.65 with Chromium and its system libraries |
| Other | `python3`, `dnsperf`, `snmp` tools (net-snmp), `git`, `clang` |

Environment variables set by the image (not by the repo):

- `CARGO_TARGET_DIR=/target`
- `RUSTC_WRAPPER=sccache`, `SCCACHE_DIR=/sccache`, `SCCACHE_CACHE_SIZE=20G`
- `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang`, `RUSTFLAGS="-C link-arg=-fuse-ld=mold"`

The repo has no `.cargo/config.toml` that would conflict with these. If the CI runners should use
mold too, they need the same two settings; that is a separate decision (not made here).

## Build and start

```bash
deploy/dev/up.sh            # build the image if missing, create volumes, clone once, start wrendns-dev2
deploy/dev/up.sh --rebuild  # rebuild the image after editing the Dockerfile
deploy/dev/up.sh --sync     # fetch new commits from the Windows repo into the clone
```

Volumes (created by `up.sh`, never removed by it):

| Volume | Mounted at | Holds |
|---|---|---|
| `tt-src` | `/src` | the Linux clone, `/src/telltale`; worktrees go in `/src/telltale/.wt/<name>` |
| `tt-cargo` | `/root/.cargo/registry` | crates.io index and sources |
| `tt-sccache` | `/sccache` | compiled-object cache |
| `tt-target2` | `/target` | `CARGO_TARGET_DIR` |

The Windows repo is mounted read-only at `/mnt/win` for sync and the first clone.

Start the container with `docker exec -it wrendns-dev2 bash`. Its working directory is `/src/telltale`.

## Git inside the container

- The clone's remote `winrepo` is the Windows checkout (`/mnt/win`, read-only). `up.sh --sync`
  runs `git fetch /mnt/win` and then `git fetch --all`.
- `origin` is set on first clone from `TT_ORIGIN` (default: the Windows checkout's `origin` URL),
  so pushes and pulls can go through the real remote instead.
- Set your identity inside the container (`git config --global user.name ...`); the volume keeps it.
- Work in a worktree: `git worktree add .wt/<name> -b <branch> feat/ipam-integrations` from
  `/src/telltale`, then `cd .wt/<name>` and use `CARGO_TARGET_DIR=/target/<name>`.
- Line endings: the clone sets `core.autocrlf input`, so files are LF. Tests then pass without the
  CRLF fixes the Windows checkout needs (the 6-8 tests that fail only from CRLF).

## Checks

Inside the container:

```bash
cargo build -p telltale
cargo nextest run -p telltale-policy
cd ui && TELLTALE_BIN=/target/debug/telltale npx playwright test
```

## Not in the image

- `helm`, the Docker CLI for building release images, and `cargo-zigbuild` (the release build
  stage stays in `Dockerfile` at the repo root).
- Secrets. `deploy/docker-desktop/secrets/` is never read or copied.

## Rollback

`wrendns-dev` is untouched. To go back, use it as before.
