# syntax=docker/dockerfile:1.7
# REQ: OPS-001 — developer container image (not a release artifact). It replaces the hand-built
# wrendns-dev container: the same toolchain, pinned, plus sccache, mold, nextest, deny and bloat.
#
#   docker build -t telltale-dev:1 deploy/dev
#   deploy/dev/up.sh            # volumes + container wrendns-dev2 (see README.md)
#
# The Rust version comes from the repo's rust-toolchain.toml (1.99.0); the image preinstalls it so
# the first cargo call in a fresh volume does not download it. Nothing here is committed config:
# the linker and sccache settings are environment variables, set by the image only.

FROM ubuntu:24.04
ARG RUST_TOOLCHAIN=1.99.0
ARG NODE_MAJOR=24
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
    RUSTC_WRAPPER=sccache \
    SCCACHE_DIR=/sccache \
    SCCACHE_CACHE_SIZE=20G \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold" \
    CARGO_INCREMENTAL=0 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# System packages: compilers and linkers, DNS and SNMP tools the tests exercise, git, Python.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg xz-utils unzip git \
      build-essential pkg-config clang mold sccache \
      python3 python3-pip python3-venv \
      dnsperf snmp \
 && rm -rf /var/lib/apt/lists/*

# Node 24 from NodeSource (major pinned; the UI's package-lock.json pins the rest).
RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && node --version

# Rust: rustup with the repo's pinned toolchain and its components.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none \
 && rustup toolchain install ${RUST_TOOLCHAIN} --profile minimal --component rustfmt --component clippy \
 && rustup default ${RUST_TOOLCHAIN}

# Cargo tools used by the repo's Makefile and CI (built from source, locked).
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
