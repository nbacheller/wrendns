"""REQ: DOC-001, DOC-006 (T33.3, ADR-1030) — the site's brand, support section and headers.

Run: python3 -m unittest site/test_site.py   (or python3 site/test_site.py)
Standard library only. The full build (links, partials, generated pages) is `python3 site/build.py --check`.
"""
import copy
import json
import os
import sys
import unittest

SITE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SITE)
import brand  # noqa: E402
import build  # noqa: E402


def read(*parts):
    with open(os.path.join(SITE, *parts), encoding="utf-8") as f:
        return f.read()


class Support(unittest.TestCase):
    page = read("download.html")

    def test_hidden_while_both_links_are_empty(self):
        out = build.render_support(self.page, {"support": {"one_time_url": "", "monthly_url": ""}})
        self.assertNotIn("Support WrenDNS", out.split("<!-- @footer -->")[0].split("<main")[1])
        self.assertNotIn("@support", out)

    def test_one_link_shows_only_that_card(self):
        out = build.render_support(self.page, {"support": {"one_time_url": "https://buy.stripe.com/test_abc", "monthly_url": ""}})
        self.assertIn('id="support"', out)
        self.assertIn("https://buy.stripe.com/test_abc", out)
        self.assertIn("Give once", out)
        self.assertNotIn("Give monthly", out)

    def test_both_links_show_both_cards_and_noopener(self):
        cfg = {"support": {"one_time_url": "https://buy.stripe.com/aaa", "monthly_url": "https://buy.stripe.com/bbb"}}
        out = build.render_support(self.page, cfg)
        self.assertIn("Give once", out)
        self.assertIn("Give monthly", out)
        self.assertEqual(out.count('rel="noopener noreferrer"'), 2 + self.page.count('rel="noopener noreferrer"'))
        self.assertEqual(build.site_config_errors(cfg), [])

    def test_an_optional_note_is_shown_escaped(self):
        cfg = {"support": {"one_time_url": "https://buy.stripe.com/aaa", "monthly_url": "", "note": "Paid to <Maker> & Co."}}
        out = build.render_support(self.page, cfg)
        self.assertIn("Paid to &lt;Maker&gt; &amp; Co.", out)
        out = build.render_support(self.page, {"support": {"one_time_url": "https://buy.stripe.com/aaa", "monthly_url": ""}})
        self.assertNotIn("Paid to", out)

    def test_only_stripe_payment_links_are_accepted(self):
        for bad in ("http://buy.stripe.com/x", "https://evil.example/x", "https://buy.stripe.com/", "https://buy.stripe.com/x y", 'https://buy.stripe.com/x"'):
            errs = build.site_config_errors({"support": {"one_time_url": bad, "monthly_url": ""}})
            self.assertTrue(any("Payment Link" in e for e in errs), bad)

    def test_the_committed_value_is_valid_and_holds_no_key(self):
        cfg = json.loads(read("data", "site.json"))
        self.assertEqual(build.site_config_errors(cfg), [])
        self.assertNotRegex(read("data", "site.json"), build.STRIPE_SECRET)

    def test_a_stripe_key_anywhere_is_refused(self):
        self.assertTrue(build.STRIPE_SECRET.search("sk_live_" + "a" * 24))
        self.assertTrue(build.STRIPE_SECRET.search("pk_test_" + "b" * 24))
        self.assertTrue(build.STRIPE_SECRET.search("whsec_" + "c" * 24))
        self.assertFalse(build.STRIPE_SECRET.search("https://buy.stripe.com/test_abc"))


class Headers(unittest.TestCase):
    cfg = json.loads(read("staticwebapp.config.json"))

    def test_the_security_headers_are_there(self):
        self.assertEqual(build.swa_errors(self.cfg), [])
        h = self.cfg["globalHeaders"]
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        self.assertIn("script-src 'self'", h["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertIn("includeSubDomains", h["Strict-Transport-Security"])
        self.assertTrue(h["Referrer-Policy"])

    def test_a_weakened_policy_fails_the_build(self):
        weak = copy.deepcopy(self.cfg)
        weak["globalHeaders"]["Content-Security-Policy"] += "; script-src 'unsafe-inline'"
        self.assertTrue(build.swa_errors(weak))
        missing = copy.deepcopy(self.cfg)
        del missing["globalHeaders"]["Strict-Transport-Security"]
        self.assertTrue(build.swa_errors(missing))

    def test_inline_script_style_and_external_resources_are_found(self):
        import tempfile

        d = tempfile.mkdtemp()
        for name, text in {
            "a.html": "<script>x()</script>",
            "b.html": '<p style="color:red">x</p>',
            "c.html": '<img src="https://example.com/x.png">',
            "d.html": '<script src="assets/site.js"></script><p onclick="x()">',
            "ok.html": '<script src="assets/site.js" defer></script><img src="assets/x.png">',
        }.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(text)
        errs = build.csp_errors(d, ["a.html", "b.html", "c.html", "d.html", "ok.html"])
        self.assertEqual(sorted({e.split(":")[0] for e in errs}), ["a.html", "b.html", "c.html", "d.html"])


class Brand(unittest.TestCase):
    def test_tokens_logos_and_fonts_are_current(self):
        self.assertEqual(brand.problems(), [])

    def test_day_and_night_tokens_are_in_the_css(self):
        css = read("assets", "brand.css")
        tokens = json.load(open(os.path.join(brand.ROOT, "brand", "tokens.json"), encoding="utf-8"))
        by = {c["name"]: c["value"] for c in tokens["color"]["tokens"]}
        self.assertIn("--brand-surface: {};".format(by["surface"]["light"]), css)
        self.assertIn("--brand-surface: {};".format(by["surface"]["dark"]), css)
        self.assertIn("prefers-color-scheme: dark", css)
        self.assertIn(':root[data-theme="dark"]', css)
        self.assertIn("font-family: 'Figtree'", css)
        self.assertIn("font-family: 'IBM Plex Mono'", css)

    def test_the_logos_are_the_brand_files_byte_for_byte(self):
        for src, dst in brand.LOGOS:
            a = open(os.path.join(brand.ROOT, "brand", "logos", src), "rb").read()
            b = open(os.path.join(SITE, "assets", dst), "rb").read()
            self.assertEqual(a, b, dst)

    def test_the_header_uses_the_lockup_and_the_hero_the_tagline(self):
        header = read("partials", "header.html")
        self.assertIn("assets/brand/wrendns-lockup-day.svg", header)
        self.assertIn("assets/brand/wrendns-lockup-night.svg", header)
        self.assertNotIn("yarn", header)
        self.assertIn("Put a bird on it!", read("index.html"))

    def test_the_tagline_is_on_the_hero_only(self):
        for name in build.PAGES:
            if name != "index.html":
                self.assertNotIn("Put a bird on it", read(name), name)

    def test_no_old_logo_or_old_name_is_left(self):
        for name in ["site.css"]:
            css = read("assets", name)
            self.assertNotIn("e4572e", css)
            self.assertNotIn("flutter", css)


if __name__ == "__main__":
    unittest.main()
