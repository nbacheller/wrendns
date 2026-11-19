# syntax=docker/dockerfile:1.7
# Developer container image (not a release artifact; no spec requirement covers it, see README.md).
# It replaces the hand-built wrendns-dev container: the same toolchain, pinned, plus sccache, mold,
# nextest, deny and bloat. Release images are built by the root Dockerfile, not this one.
#
#   docker build -t telltale-dev:1 deploy/dev
#   deploy/dev/up.sh            # volumes + container wrendns-dev2 (see README.md)
#
# The Rust version comes from the repo's rust-toolchain.toml (1.99.0); the image preinstalls it so
# the first cargo call in a fresh volume does not download it. Nothing here is committed config:
# the linker is an environment variable, set by the image only. sccache is installed but NOT
# enabled: set RUSTC_WRAPPER=sccache yourself for a run, and compare it with a plain build first.

# Digest pinned for reproducible rebuilds (ubuntu:24.04 as of 2026-11-16). Bump it deliberately.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
ARG RUST_TOOLCHAIN=1.99.0
ARG NODE_MAJOR=24
# Must equal the exact version in ui/package-lock.json (node_modules/playwright). The browser
# revision is tied to it, so a mismatch makes "browser not found" errors.
ARG PLAYWRIGHT_VERSION=1.65.0
ARG NEXTEST_VERSION=0.9.100
ARG DENY_VERSION=0.18.4
ARG BLOAT_VERSION=0.12.1

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    CARGO_TARGET_DIR=/target \
    SCCACHE_DIR=/sccache \
    SCCACHE_CACHE_SIZE=20G \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System packages: compilers and linkers, DNS and SNMP tools the tests exercise, git, Python, bc
# (used by the repo's scripts). apt packages are not version-pinned (see README.md, Reproducibility).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg xz-utils unzip git \
      build-essential pkg-config clang mold sccache \
      python3 python3-pip python3-venv \
      dnsperf snmp bc \
 && rm -rf /var/lib/apt/lists/*

# Node 24 from NodeSource (major pinned; the UI's package-lock.json pins the rest).
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && node --version

# Rust: rustup with the repo's pinned toolchain and its components. rustup-init is not pinned
# (see README.md, Reproducibility).
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none \
 && rustup toolchain install ${RUST_TOOLCHAIN} --profile minimal --component rustfmt --component clippy \
 && rustup default ${RUST_TOOLCHAIN}

# Cargo tools used by the repo's Makefile and CI (built from source, locked). RUSTC_WRAPPER is
# not set by the image, so these builds leave no objects in /sccache.
RUN cargo install --locked cargo-nextest --version ${NEXTEST_VERSION} \
 && cargo install --locked cargo-deny --version ${DENY_VERSION} \
 && cargo install --locked cargo-bloat --version ${BLOAT_VERSION} \
 && rm -rf /root/.cargo/registry/cache /root/.cargo/git

# Playwright and its Chromium with the system libraries it needs (the old wrendns-dev lacked libglib).
RUN npm install -g playwright@${PLAYWRIGHT_VERSION} \
 && npx playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/* /root/.npm

WORKDIR /src
CMD ["sleep", "infinity"]
