#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""REQ: OPS-001 / OPS-004 (ADR-1075) - a pushed manifest list names exactly the expected platforms.

Usage: check-platforms.py <image reference> <platform>...
       check-platforms.py ghcr.io/o/wrendns:edge linux/amd64 linux/arm64 linux/arm/v7

Reads the index with `docker buildx imagetools inspect --raw` and fails when a platform is
missing or an unexpected one is present (provenance attestation entries, `unknown/unknown`,
are ignored). The merge job runs it before signing, so the signature is only ever put on a
manifest list that carries all three architectures.
"""

import json
import subprocess
import sys


def platform(desc):
    p = desc.get("platform", {})
    s = f"{p.get('os', 'unknown')}/{p.get('architecture', 'unknown')}"
    return s + (f"/{p['variant']}" if p.get("variant") else "")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    ref, want = sys.argv[1], sorted(sys.argv[2:])
    raw = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", ref],
                         capture_output=True, text=True, check=True).stdout
    got = sorted(p for p in map(platform, json.loads(raw).get("manifests", [])) if p != "unknown/unknown")
    print(f"{ref}: {', '.join(got) or 'no platforms'}")
    if got != want:
        sys.exit(f"FAIL: expected {', '.join(want)}")


if __name__ == "__main__":
    main()
