# Licensing

This page says, in plain language, under which terms you can use WrenDNS. The licence texts themselves are what count: [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), [`LICENSE-UPSTREAM-APACHE`](LICENSE-UPSTREAM-APACHE) and [`LICENSE-UPSTREAM-MIT`](LICENSE-UPSTREAM-MIT). This page is not legal advice.

## WrenDNS is AGPL-3.0-or-later

WrenDNS is free and open-source software under the [GNU Affero General Public License, version 3 or (at your option) any later version](LICENSE) (SPDX: `AGPL-3.0-or-later`). Copyright MySummitKeep, LLC.

In practice:

- **Running it unchanged on your own network is free**, at home or at work, on as many nodes as you like. Nothing in the licence asks you to publish anything for that.
- **If you change WrenDNS and let other people use your changed version over a network** (for example, you host a resolver or its web UI for customers, or your employees use a changed copy at work), the AGPL asks you to offer those users the source of your changed version, under the same licence.
- **If you distribute WrenDNS** (a binary, an image, a device with it installed), changed or not, you pass on the same rights: the source, the licence and the notices.
- There is no warranty (sections 15 and 16 of the licence).

## A commercial licence

MySummitKeep, LLC, which holds the copyright, can also license WrenDNS under other terms, for example to a company that wants to build WrenDNS into a product without the AGPL's obligations. There is no standard commercial licence text yet: ask at **[support@wrendns.com](mailto:support@wrendns.com)** and say what you want to do.

Payments through the [Support WrenDNS](https://www.wrendns.com/download.html#support) links are voluntary support, not a licence: they buy no rights, features or priority support (see the [Terms](https://www.wrendns.com/terms)).

## The permissive baseline: `permissive-final`

WrenDNS started from [TelltaleDNS](https://github.com/paimonsoror/telltaledns) by paimonsoror, which is licensed under Apache-2.0 OR MIT. The last version of this repository released entirely under Apache-2.0 OR MIT is marked, so anyone can see where the line is:

- the annotated git tag **`permissive-final`** (commit `2e99850b`);
- the GitHub release [permissive-final](https://github.com/nbacheller/wrendns/releases/tag/permissive-final) (source only), published 2026-11-19;
- an archive copy at [Software Heritage](https://www.softwareheritage.org/) was requested on 2026-11-26, after the repository became public (a save of `https://github.com/nbacheller/wrendns`; accepted and in progress on that day, not yet confirmed as done);
- the container images and Helm chart built before the rename, `ghcr.io/nbacheller/telltale` and `ghcr.io/nbacheller/charts/telltale` (last built before the rename), which are made public as an archive of the permissive-era builds once their versions have been checked, and are no longer updated. Current builds are `ghcr.io/nbacheller/wrendns` and `ghcr.io/nbacheller/charts/wrendns`.

Everything in that version stays available under Apache-2.0 OR MIT for good: a licence once granted cannot be taken back. Changes made after the tag are licensed under AGPL-3.0-or-later, except for the parts listed under [What stays Apache-2.0](#what-stays-apache-20); the TelltaleDNS portions keep Apache-2.0 OR MIT.

## What stays Apache-2.0

- **The Home Assistant integration** in [`integrations/home-assistant/`](integrations/home-assistant/), which ships on its own (HACS), is Apache-2.0, so other projects and stores can adopt it. It has its own [`LICENSE`](integrations/home-assistant/LICENSE).
- A browser extension, if one ships later, will be Apache-2.0 the same way, with its own `LICENSE` (ADR-1033). None is in the repository today.

## Upstream's code keeps its notices

The parts of WrenDNS that came from TelltaleDNS are copyright The TelltaleDNS Authors (paimonsoror and its contributors, named in [`NOTICE`](NOTICE)) and remain available under Apache-2.0 OR MIT. Their texts are kept unchanged as [`LICENSE-UPSTREAM-APACHE`](LICENSE-UPSTREAM-APACHE) and [`LICENSE-UPSTREAM-MIT`](LICENSE-UPSTREAM-MIT), and `NOTICE` keeps upstream's copyright line, as both licences require. If you only want the permissive code, take the `permissive-final` tag or upstream's repository.

## Third-party components

Dependencies keep their own licences. For the Rust dependencies, `cargo deny` allows only licences that work with both the AGPL and a commercial licence: permissive ones (MIT, Apache-2.0, BSD, ISC, Zlib and similar) and MPL-2.0 per file; no GPL, LGPL or AGPL dependency ([`deny.toml`](deny.toml)). The web UI's npm packages, which are built into the binary, are held to the same rule by review; no automated check covers them yet. The fonts, icons and data sets bundled with WrenDNS are listed with their licences in [`docs/third-party-notices.md`](docs/third-party-notices.md).

## Source file headers

A source file added since `permissive-final` starts with `SPDX-License-Identifier: AGPL-3.0-or-later`; CI checks it (`scripts/check-spdx.py`). Older files are not edited for this: `LICENSE` and `NOTICE` cover them.

## Contributing

Contributions are welcome under the [Contributor Licence Agreement](CONTRIBUTING.md#contributor-licence-agreement), which keeps the commercial licence possible; you keep the copyright in your work. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## The name

The licences cover the code, not the name. "WrenDNS" and the wren logo are MySummitKeep, LLC's; a fork of the code needs its own name and logo.
