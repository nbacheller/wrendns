#!/usr/bin/env python3
"""The site's brand assets, from brand/ (spec/10 T33.2 and T33.3; brand/README.md is the brand book).

  python3 site/brand.py           writes site/assets/brand.css and copies the logos
  python3 site/brand.py --check   fails when either is out of date (site/build.py runs this)

`site/assets/brand.css` holds the colour tokens for Day (the default) and Night (`prefers-color-scheme`,
or `data-theme="dark"` from the header's toggle), the type scale, spacing, radius, shadow and the
`@font-face` rules for the three font files in `site/assets/fonts/` (Figtree and IBM Plex Mono, SIL OFL,
latin subset; the licences are in that folder). The logos are copied byte for byte from `brand/logos/`:
they are never redrawn, recoloured or retyped. The favicon, `assets/logo.svg`, is the app icon.
"""
import json
import os
import shutil
import sys

SITE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SITE)
OUT = os.path.join(SITE, "assets", "brand.css")

# (file in brand/logos, where it goes under site/assets/)
LOGOS = [
    ("wrendns-lockup-day.svg", "brand/wrendns-lockup-day.svg"),
    ("wrendns-lockup-night.svg", "brand/wrendns-lockup-night.svg"),
    ("wrendns-mark-day.svg", "brand/wrendns-mark-day.svg"),
    ("wrendns-mark-night.svg", "brand/wrendns-mark-night.svg"),
    ("wrendns-app-icon.svg", "logo.svg"),
]


def _tokens():
    with open(os.path.join(ROOT, "brand", "tokens.json"), encoding="utf-8") as f:
        return json.load(f)


def _bytes(path):
    with open(path, "rb") as f:
        return f.read()


def css():
    t = _tokens()
    by_name = {c["name"]: c for c in t["color"]["tokens"]}

    def resolve(name, theme):
        v = by_name[name]["value"][theme]
        return resolve(v[1:-1], theme) if v.startswith("{") else v

    def colors(theme):
        return ["  --brand-{}: {};".format(c["name"], resolve(c["name"], theme)) for c in t["color"]["tokens"]]

    def shadows(theme):
        return ["  --{}: {};".format(s["name"], s["value"][theme]) for s in t["shadow"]["tokens"]]

    type_vars = []
    for g in t["type"]["groups"]:
        for s in g["styles"]:
            fam = "var(--brand-font-mono)" if g["family"] == "mono" else "var(--brand-font-sans)"
            type_vars.append("  --type-{}-font: {};".format(s["name"], fam))
            type_vars.append("  --type-{}-size: {};".format(s["name"], s["fontSize"]))
            type_vars.append("  --type-{}-line: {};".format(s["name"], s["lineHeight"]))
            type_vars.append("  --type-{}-weight: {};".format(s["name"], s["fontWeight"]))
            if s.get("letterSpacing"):
                type_vars.append("  --type-{}-tracking: {};".format(s["name"], s["letterSpacing"]))
    other = ["  --{}: {};".format(x["name"], x["value"]) for x in t["spacing"]["tokens"] + t["radius"]["tokens"]]
    faces = []
    for f in t["type"]["fonts"]:
        faces.append(
            "@font-face {{\n  font-family: '{family}';\n  font-style: {style};\n  font-weight: {weight};\n  font-display: swap;\n"
            "  src: url('{file}') format('woff2');\n}}".format(
                family=f["family"], style=f["style"], weight=f["weight"], file=f["file"]
            )
        )
    night = colors("dark") + shadows("dark") + ["  color-scheme: dark;"]
    return (
        "/* Generated from brand/tokens.json by site/brand.py. Do not edit; run `python3 site/brand.py`. */\n"
        + "\n".join(faces)
        + "\n\n/* Day (the default). */\n:root {\n"
        + "\n".join(colors("light") + shadows("light"))
        + "\n  --brand-font-sans: {};\n  --brand-font-mono: {};\n".format(t["type"]["families"]["sans"], t["type"]["families"]["mono"])
        + "\n".join(type_vars + other)
        + "\n  color-scheme: light;\n}\n\n/* Night: the system's choice, unless the visitor picked Day. */\n"
        + "@media (prefers-color-scheme: dark) {\n  :root:not([data-theme=\"light\"]) {\n"
        + "\n".join("  " + l for l in night)
        + "\n  }\n}\n\n/* Night: the visitor's choice. */\n:root[data-theme=\"dark\"] {\n"
        + "\n".join(night)
        + "\n}\n"
    )


def problems():
    """What is out of date, as a list of sentences (empty when everything is current)."""
    out = []
    want = css()
    have = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else None
    if have != want:
        out.append("site/assets/brand.css is out of date (python3 site/brand.py)")
    for src, dst in LOGOS:
        a, b = os.path.join(ROOT, "brand", "logos", src), os.path.join(SITE, "assets", dst)
        if not os.path.exists(b) or _bytes(a) != _bytes(b):
            out.append("site/assets/{} differs from brand/logos/{} (python3 site/brand.py)".format(dst, src))
    for f in _tokens()["type"]["fonts"]:
        if not os.path.exists(os.path.join(SITE, "assets", f["file"])):
            out.append("site/assets/{} is missing (the font tokens.json lists)".format(f["file"]))
    return out


def sync():
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(css())
    for src, dst in LOGOS:
        target = os.path.join(SITE, "assets", dst)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, "brand", "logos", src), target)


if __name__ == "__main__":
    if "--check" in sys.argv:
        found = problems()
        for p in found:
            print("brand: " + p, file=sys.stderr)
        sys.exit(1 if found else 0)
    sync()
    print("brand: wrote site/assets/brand.css and the logos")
