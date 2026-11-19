#!/usr/bin/env python3
"""REQ: OBS-902 (T26.5, ADR-958 section 8) - builds `ui/src/lib/world-data.ts`: the world view's land
mask (a 1-bit equirectangular grid, so the map is a dot grid and needs no tiles, fonts or scripts
from outside) and one point per country (name, longitude, latitude) for the arcs to end at.

Sources, both free to use and redistribute (they are baked into the file, never fetched at run time):
- Natural Earth 1:110m admin-0 countries (public domain), for the land and the centroids;
- the tz database's `iso3166.tab` (country names) and `zone.tab` (a coordinate per time zone, whose
  mean places the small states Natural Earth's 110m set leaves out).

Run it when the data should change (it does not run in the build):

    python3 ui/scripts/gen-world-data.py ne_110m_admin_0_countries.geojson > ui/src/lib/world-data.ts
"""
import base64
import json
import re
import sys

STEP = 2.0  # degrees per cell
LON_MIN, LAT_MAX, LAT_MIN = -180.0, 84.0, -56.0
W = int(360 / STEP)
H = int((LAT_MAX - LAT_MIN) / STEP)
SUB = 3  # samples per cell side; a cell is land when enough of the samples are


def rings_of(geom):
    """Every polygon of a geometry as (outer ring, holes)."""
    if geom["type"] == "Polygon":
        polys = [geom["coordinates"]]
    else:
        polys = geom["coordinates"]
    return [(p[0], p[1:]) for p in polys]


def inside(ring, x, y):
    n = len(ring)
    c = False
    j = n - 1
    for i in range(n):
        xi, yi = ring[i][0], ring[i][1]
        xj, yj = ring[j][0], ring[j][1]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            c = not c
        j = i
    return c


def area_centroid(ring):
    a = cx = cy = 0.0
    for i in range(len(ring) - 1):
        x0, y0 = ring[i][0], ring[i][1]
        x1, y1 = ring[i + 1][0], ring[i + 1][1]
        f = x0 * y1 - x1 * y0
        a += f
        cx += (x0 + x1) * f
        cy += (y0 + y1) * f
    a /= 2
    if abs(a) < 1e-9:
        return 0.0, ring[0][0], ring[0][1]
    return abs(a), cx / (6 * a), cy / (6 * a)


def main(path):
    data = json.load(open(path, encoding="utf-8"))
    polys = []  # (bbox, outer, holes)
    centres = {}
    names_ne = {}
    for f in data["features"]:
        p = f["properties"]
        cc = p.get("ISO_A2_EH") or p.get("ISO_A2")
        if not cc or cc == "-99":
            cc = None
        best = (0.0, 0.0, 0.0)
        for outer, holes in rings_of(f["geometry"]):
            xs = [pt[0] for pt in outer]
            ys = [pt[1] for pt in outer]
            polys.append(((min(xs), min(ys), max(xs), max(ys)), outer, holes))
            a = area_centroid(outer)
            if a[0] > best[0]:
                best = a
        if cc and best[0] > 0:
            centres[cc] = (best[1], best[2])
            names_ne[cc] = p.get("NAME") or p.get("ADMIN")

    # The land mask.
    bits = bytearray((W * H + 7) // 8)
    for r in range(H):
        for c in range(W):
            hits = 0
            for sy in range(SUB):
                for sx in range(SUB):
                    x = LON_MIN + (c + (sx + 0.5) / SUB) * STEP
                    y = LAT_MAX - (r + (sy + 0.5) / SUB) * STEP
                    for (x0, y0, x1, y1), outer, holes in polys:
                        if x0 <= x <= x1 and y0 <= y <= y1 and inside(outer, x, y):
                            if not any(inside(h, x, y) for h in holes):
                                hits += 1
                                break
            if hits >= 3:
                i = r * W + c
                bits[i // 8] |= 1 << (i % 8)

    # Names, and a point for the states the 110m set leaves out.
    names = {}
    for line in open("/usr/share/zoneinfo/iso3166.tab", encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cc, name = line.rstrip("\n").split("\t", 1)
        names[cc] = name
    zone = {}
    for line in open("/usr/share/zoneinfo/zone.tab", encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        cc, coord = line.split("\t")[:2]
        m = re.match(r"([+-])(\d\d)(\d\d)(\d\d)?([+-])(\d{3})(\d\d)(\d\d)?$", coord)
        if not m:
            continue
        la = int(m[2]) + int(m[3]) / 60 + (int(m[4]) / 3600 if m[4] else 0)
        lo = int(m[6]) + int(m[7]) / 60 + (int(m[8]) / 3600 if m[8] else 0)
        la = -la if m[1] == "-" else la
        lo = -lo if m[5] == "-" else lo
        zone.setdefault(cc, []).append((lo, la))
    for cc, pts in zone.items():
        if cc not in centres:
            centres[cc] = (sum(p[0] for p in pts) / len(pts), sum(p[1] for p in pts) / len(pts))
    # Kosovo is in Natural Earth only.
    for cc, n in names_ne.items():
        names.setdefault(cc, n)

    rows = []
    for cc in sorted(centres):
        if cc not in names:
            continue
        lo, la = centres[cc]
        name = names[cc].replace("|", " ").replace(";", ",")
        rows.append(f"{cc}|{name}|{lo:.1f}|{la:.1f}")
    out = []
    out.append("// REQ: OBS-902 (T26.5, ADR-958 section 8) - generated by `ui/scripts/gen-world-data.py`; do not edit.")
    out.append("// Land: Natural Earth 1:110m (public domain). Names and the small states' points: the tz database.")
    out.append(f"export const GRID = {{ w: {W}, h: {H}, step: {STEP}, lonMin: {LON_MIN}, latMax: {LAT_MAX} }} as const;")
    out.append("// One bit per cell, row by row from the north-west corner, least significant bit first.")
    out.append(f"export const LAND_MASK = '{base64.b64encode(bytes(bits)).decode()}';")
    out.append("// Country code | name | longitude | latitude.")
    out.append("export const COUNTRY_DATA =")
    out.append("  '" + ";".join(rows) + "';")
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1])
