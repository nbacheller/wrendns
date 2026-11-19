# Security policy

WrenDNS answers every DNS question on a network and holds credentials for routers and alerting, so security reports are taken seriously and handled first.

## Reporting a vulnerability

Please report privately, never in a public issue, discussion or pull request.

1. **GitHub private vulnerability reporting (preferred):** [open a private report](https://github.com/nbacheller/wrendns/security/advisories/new). Only the maintainer sees it, and the fix, the advisory and the credit are worked out there with you.
2. **Email:** [support@wrendns.com](mailto:support@wrendns.com) with **SECURITY** at the start of the subject.

Include what you can: the version (`wrendns --version`), how WrenDNS runs (native, container, Helm), the steps or a proof of concept, and what an attacker gains. A [support package](https://www.wrendns.com/support) made at the `strict` level is safe to attach: it replaces addresses and names and removes secrets. Don't send real credentials or someone else's data.

## What to expect

- **Within 3 working days:** an acknowledgement that a person has read your report.
- **Within 10 working days:** a first assessment: whether it is a vulnerability, how severe (CVSS), and the plan.
- **A fix** in a release as soon as it is ready, aimed at 30 days for high and critical issues, then a GitHub security advisory (with a CVE where it applies). You are credited in the advisory unless you prefer not to be.
- Progress updates at least every two weeks until it is closed, and a heads-up before anything is published. Please give us a reasonable time to ship the fix before you disclose it.

WrenDNS is maintained by one person for MySummitKeep, LLC, so these are commitments in good faith, not a service level.

## Supported versions

Only the **latest release** gets security fixes; upgrade to it (`wrendns self-update`, `install.sh`, a new image or chart, see the [README](README.md#upgrading)). Builds of `main` (the `edge` channel) get fixes as soon as they are merged. Older releases, `permissive-final` and TelltaleDNS releases are not supported. <!-- rebrand:keep -->

| Version | Supported |
|---|---|
| The latest release | Yes |
| `edge` (builds of `main`) | Yes, fixed on merge |
| Anything older | No |

## Scope

In scope: the `wrendns` binary and image, its DNS listeners (plain, DoT, DoH, DoQ), the web UI, the REST API and MCP server, the cluster protocol, the installer and units in `deploy/`, the Helm chart, the release signing and self-update, and the Home Assistant integration.

Out of scope: the content of third-party blocklists, a resolver or router you point WrenDNS at, denial of service by flooding a node you can already reach without limit, and findings that need an administrator's own credentials to cause harm an administrator can already cause.

## How WrenDNS protects itself

The design is in [`spec/08-deployment-config-security.md`](spec/08-deployment-config-security.md) and the reviews in [`docs/security-review.md`](docs/security-review.md): a static binary in an image built from scratch, run as a non-root user with a read-only root filesystem, a sandboxed systemd unit, write-only secrets that never appear on a read surface, signed releases verified before an update is installed (minisign, ADR-1034) and signed images (cosign), an SBOM per binary, `cargo deny` and CodeQL in CI, and fuzzing of the DNS parsers.
