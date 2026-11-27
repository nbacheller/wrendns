// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: DSC-914, DSC-910 (T36.10c) — the locations, read for the badges and filters on the clients list, the
// networks and the CMDB. A device's location is what the API composed (its pin, else its address's network), never
// worked out here, and never from the CMDB (DSC-901): the CMDB list has no address, so a CI is matched by its name.
import { api, type S } from './api';

export type Loc = { slug: string; label: string; pinned: boolean };

export const locs = $state<{ items: S['LocationInfo'][] }>({ items: [] });
let pending: Promise<void> | null = null;

/** Reads the locations now (a read already under way is shared). A failed read leaves the list empty: no badges, no filter. */
export function loadLocations(): Promise<void> {
  pending ??= api
    .locations()
    .then((r) => void (locs.items = r.items))
    .catch(() => void (locs.items = []))
    .finally(() => (pending = null));
  return pending;
}

export const labelOf = (l: S['LocationInfo']) => l.label || l.slug;

let seen: S['LocationInfo'][] | null = null;
let byAddress = new Map<string, Loc>();
let byLabel = new Map<string, Loc | null>();

function index() {
  if (seen === locs.items) return;
  seen = locs.items;
  byAddress = new Map();
  byLabel = new Map();
  for (const l of locs.items) {
    const loc = { slug: l.slug, label: labelOf(l), pinned: false };
    for (const d of l.devices) {
      const here = { ...loc, pinned: d.pinned };
      for (const a of [d.address, ...(d.addressesV6 ?? [])]) byAddress.set(a.toLowerCase(), here);
      // The same label in two locations names no one device: no badge rather than a wrong one.
      for (const n of [d.name, d.flatName]) {
        const k = n?.split('.')[0]?.toLowerCase();
        if (k) byLabel.set(k, byLabel.has(k) && byLabel.get(k)?.slug !== l.slug ? null : here);
      }
    }
  }
}

/** The location of a device by address, when it has one. */
export function locationOfAddress(address: string | null | undefined): Loc | undefined {
  index();
  return address ? byAddress.get(address.toLowerCase()) : undefined;
}

/** The location whose networks, as resolved now, include this subnet. */
export function locationOfNetwork(subnet: string): Loc | undefined {
  const l = locs.items.find((x) => x.networks.some((n) => n.resolved.includes(subnet)));
  return l ? { slug: l.slug, label: labelOf(l), pinned: false } : undefined;
}

/** The location of a CMDB CI by its name (an address, or a device's name or flat name's first label). */
export function locationOfName(name: string | null | undefined): Loc | undefined {
  index();
  const n = name?.trim().toLowerCase();
  return n ? (byAddress.get(n) ?? byLabel.get(n.split('.')[0] ?? '') ?? undefined) : undefined;
}
