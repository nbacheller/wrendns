# syntax=docker/dockerfile:1.7
# REQ: OPS-001 — multi-arch image: FROM scratch + one static musl binary + a compact zoneinfo, running
# as 65532:65532 (spec/08 §2). There is no CA bundle: every TLS client verifies against the Mozilla
# roots compiled in with webpki-roots, and none reads the system store (NFR-001, ADR-168). The
# build stage runs on the build host's platform and cross-compiles with cargo-zigbuild, so
# arm64/armv7 images never compile under QEMU.
#
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t telltale:dev .
#   docker buildx build --load -t telltale:dev .                       # host arch only
#   docker buildx build --build-arg PROFILE=bench-fast --load -t telltale:dev .   # quick local build

ARG RUST_VERSION=1.99.0
ARG NODE_VERSION=24

# REQ: API-005 — the web UI is built once (it's platform-independent) and embedded in the
# binary (ADR-009). No Node in the final image.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
# The help glossary (API-011) is shared with the site and imported from docs/help/.
COPY docs/help/topics.json /docs/help/topics.json
RUN npm run build

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS build
ARG TARGETARCH
ARG TARGETVARIANT
ARG PROFILE=release
ARG ZIG_VERSION=0.15.2
ARG ZIGBUILD_VERSION=0.23.4
# REQ: NFR-005 (T10.10) — release binaries carry their dependency list (`cargo audit bin`,
# syft and other scanners read it).
ARG AUDITABLE_VERSION=0.7.7

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils tzdata \
 && rm -rf /var/lib/apt/lists/*

# Pinned toolchain downloads, checksum-verified (supply chain: spec/08 §7).
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)  zig_sha=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 ;; \
      aarch64) zig_sha=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f ;; \
      *) echo "unsupported build host $(uname -m)"; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-$(uname -m)-linux-${ZIG_VERSION}.tar.xz"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && rm /tmp/zig.tar.xz; \
    if [ "$(uname -m)" = x86_64 ]; then \
      curl -fsSLo /tmp/zb.tar.xz "https://github.com/rust-cross/cargo-zigbuild/releases/download/v${ZIGBUILD_VERSION}/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"; \
      echo "9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b  /tmp/zb.tar.xz" | sha256sum -c -; \
      tar -xJf /tmp/zb.tar.xz -C /usr/local/cargo/bin --strip-components=1 \
        cargo-zigbuild-x86_64-unknown-linux-musl/cargo-zigbuild && rm /tmp/zb.tar.xz; \
      curl -fsSLo /tmp/ca.tar.xz "https://github.com/rust-secure-code/cargo-auditable/releases/download/v${AUDITABLE_VERSION}/cargo-auditable-x86_64-unknown-linux-musl.tar.xz"; \
      echo "7676443367c5e33d9fb22acef63cccb5e9202de12dae1b0579995eb3e2bc7a18  /tmp/ca.tar.xz" | sha256sum -c -; \
      mkdir /tmp/ca && tar -xJf /tmp/ca.tar.xz -C /tmp/ca && rm /tmp/ca.tar.xz; \
      find /tmp/ca -type f -name cargo-auditable -exec install -m 755 {} /usr/local/cargo/bin/ \; ; \
      rm -rf /tmp/ca; \
    else \
      cargo install --locked cargo-zigbuild --version "${ZIGBUILD_VERSION}"; \
      cargo install --locked cargo-auditable --version "${AUDITABLE_VERSION}"; \
    fi; \
    cargo auditable --version
ENV PATH="/opt/zig:${PATH}"

RUN case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64)  echo x86_64-unknown-linux-musl ;; \
      arm64)  echo aarch64-unknown-linux-musl ;; \
      armv7)  echo armv7-unknown-linux-musleabihf ;; \
      *) echo "unsupported target ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac > /rust-target \
 && rustup target add "$(cat /rust-target)" \
 && rustup component add llvm-tools

# REQ: NFR-001 (ADR-169) — the image's zoneinfo is built from the package's own tzdata.zi: one copy
# of the database, each name a hard link to one file, about 0.2 MiB smaller compressed than the
# distribution's three trees (the main directory, `posix/`, and `right/`). It is `-b fat` on
# purpose: `zic -b slim` is smaller still, but jiff (the reader) refuses one of its files
# (America/Ojinaga, tzdata 2025b), and a schedule in that zone would fail. The build fails if any
# zone name the distribution's directory has (apart from the host's own `localtime` and
# `posixrules`, and the `posix/` and `right/` trees) is missing from it.
# crates/telltale-config/tests/zoneinfo.rs builds the same way and checks that jiff reads every
# file and agrees with the distribution's offsets.
RUN set -eu; \
    zic -b fat -d /zoneinfo /usr/share/zoneinfo/tzdata.zi; \
    cd /usr/share/zoneinfo; \
    for f in $(find . \( -path ./posix -o -path ./right \) -prune -o \( -type f -o -type l \) -print | sed 's|^\./||'); do \
      case "$f" in localtime|posixrules|posix/*|right/*) continue ;; esac; \
      if [ "$(head -c4 "$f" 2>/dev/null || true)" = TZif ] && [ ! -e "/zoneinfo/$f" ]; then \
        echo "the built zoneinfo lacks $f" >&2; exit 1; \
      fi; \
    done; \
    test "$(find /zoneinfo -type f | wc -l)" -gt 300

WORKDIR /src
# REQ: OPS-004 (ADR-046) — the build identity CI stamps into every architecture alike.
# Empty: build.rs stamps the crate version with `-dev` (ADR-948, T21.6).
ARG TELLTALE_BUILD_VERSION=
ARG TELLTALE_BUILD_COMMIT=
ARG TELLTALE_BUILD_DATE=
ARG TELLTALE_BUILD_CHANNEL=dev
# REQ: NFR-005 (T10.10) — reproducible builds: C code compiled into the binary (mimalloc,
# zstd) takes `__DATE__`/`__TIME__` from this instead of the clock (CI passes the commit's
# time); BuildKit stamps the image layers with it too. Unset, a local build uses the clock.
ARG SOURCE_DATE_EPOCH
# The cargo target cache is shared by every build of this architecture on a host, and cargo
# trusts it by file time; a checkout that must not reuse another checkout's output (a worktree
# building older code) names its own cache, e.g. --build-arg BUILD_CACHE_SCOPE=-bundle.
ARG BUILD_CACHE_SCOPE=
COPY . .
COPY --from=ui /ui/dist /src/ui/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=telltale-target-${TARGETARCH}${TARGETVARIANT}${BUILD_CACHE_SCOPE},sharing=locked \
    set -eu; t="$(cat /rust-target)"; \
    mkdir -p /out/usr/local/bin /out/var/lib/telltale /out/etc/telltale /out/usr/share /debug; \
    # REQ: OPS-013 (ADR-164) — link once with symbols and line tables, then split that one output:
    # the shipped binary is the stripped copy (what `strip = true` made before: the symbol table
    # and debug sections are gone, the dependency data stays; the line tables shift the layout by
    # 0.015%, benchmarked in ADR-164), and
    # `/debug/telltale.debug` is the rest, matched to it by debuglink (name and CRC). It stays out
    # of `/out`, which the image copies whole: it is only a release asset (the `bin` target), so a
    # stack from a stripped binary can be read afterwards.
    up="$(echo "${PROFILE}" | tr 'a-z-' 'A-Z_')"; \
    export "CARGO_PROFILE_${up}_STRIP=none" "CARGO_PROFILE_${up}_DEBUG=line-tables-only"; \
    cargo auditable zigbuild --locked --profile "${PROFILE}" -p telltale --target "$t"; \
    oc="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"; \
    "$oc" --only-keep-debug "target/$t/${PROFILE}/telltale" /debug/telltale.debug; \
    "$oc" --strip-all --keep-section=.dep-v0 --add-gnu-debuglink=/debug/telltale.debug \
      "target/$t/${PROFILE}/telltale" /out/usr/local/bin/telltale; \
    cp -a /zoneinfo /out/usr/share/zoneinfo; \
    printf 'root:x:0:0:root:/:/sbin/nologin\ntelltale:x:65532:65532:telltale:/var/lib/telltale:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'root:x:0:\ntelltale:x:65532:\n' > /out/etc/group; \
    # The data directory belongs to the image's user. Owned here, because `COPY --from` keeps
    # ownership; a later `COPY --chown` of the empty directory left it owned by root.
    chown 65532:65532 /out/var/lib/telltale

# REQ: OPS-004 — just the static binary, for release assets and native installs:
#   docker buildx build --platform linux/arm64 --target bin --output type=local,dest=out .
FROM scratch AS bin
COPY --from=build /out/usr/local/bin/telltale /telltale
COPY --from=build /debug/telltale.debug /telltale.debug

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="TelltaleDNS" \
      org.opencontainers.image.description="See every question. Answer on your terms. A filtering, encrypted, observable, clustered DNS resolver." \
      org.opencontainers.image.source="https://github.com/paimonsoror/telltaledns" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/ /
# REQ: OPS-004 (ADR-046) — containers update by pulling a new image.
ENV TELLTALE_INSTALL=container
USER 65532:65532
# The only writable path; run with a read-only root filesystem (spec/08 §2).
VOLUME ["/var/lib/telltale"]
EXPOSE 53/udp 53/tcp 8053/tcp 9153/tcp
ENTRYPOINT ["/usr/local/bin/telltale"]
CMD ["run"]
