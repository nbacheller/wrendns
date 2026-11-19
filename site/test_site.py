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
    download = read("download.html")
    support = read("support.html")
    thanks = read("thanks.html")
    full = {
        "support": {
            "one_time_url": "https://donate.stripe.com/aaa",
            "monthly": [{"label": "$3 a month", "url": "https://buy.stripe.com/bbb"}, {"label": "$5 a month", "url": "https://buy.stripe.com/ccc"}],
        }
    }

    def test_hidden_while_no_link_is_set(self):
        out = build.render_support(self.download, {"support": {"one_time_url": "", "monthly": []}})
        main = out.split("<!-- @footer -->")[0].split("<main")[1]
        self.assertNotIn("Support WrenDNS", main)
        self.assertNotIn("@support", out)
        sup = build.render_support(self.support, {"support": {}})
        self.assertIn("not set up yet", sup)
        self.assertNotIn("buy.stripe.com", sup)

    def test_one_link_shows_only_that_card(self):
        out = build.render_support(self.download, {"support": {"one_time_url": "https://buy.stripe.com/test_abc", "monthly": []}})
        self.assertIn('id="support"', out)
        self.assertIn("https://buy.stripe.com/test_abc", out)
        self.assertIn("Give once", out)
        self.assertNotIn("Give monthly", out)

    def test_every_tier_gets_a_button_and_noopener(self):
        out = build.render_support(self.download, self.full)
        self.assertIn("Give once", out)
        self.assertIn("Give monthly", out)
        self.assertIn("$3 a month", out)
        self.assertIn("$5 a month", out)
        self.assertEqual(out.count('rel="noopener noreferrer"') - self.download.count('rel="noopener noreferrer"'), 3)
        self.assertEqual(build.site_config_errors(self.full), [])

    def test_the_tax_statement_is_said_wherever_a_gift_is_offered_and_on_the_thanks_page(self):
        for page in (self.download, self.support):
            out = build.render_support(page, self.full)
            self.assertIn("not a tax-deductible donation", out)
        self.assertIn("not a tax-deductible donation", build.render_support(self.thanks, self.full))

    def test_an_optional_note_is_shown_escaped(self):
        cfg = {"support": {"one_time_url": "https://buy.stripe.com/aaa", "monthly": [], "note": "Paid to <Maker> & Co."}}
        out = build.render_support(self.download, cfg)
        self.assertIn("Paid to &lt;Maker&gt; &amp; Co.", out)
        out = build.render_support(self.download, {"support": {"one_time_url": "https://buy.stripe.com/aaa", "monthly": []}})
        self.assertNotIn("Paid to", out)

    def test_only_stripe_payment_links_are_accepted(self):
        for bad in ("http://buy.stripe.com/x", "https://evil.example/x", "https://buy.stripe.com/", "https://buy.stripe.com/x y", 'https://buy.stripe.com/x"', "https://donate.stripe.com/"):
            errs = build.site_config_errors({"support": {"one_time_url": bad, "monthly": []}})
            self.assertTrue(any("Payment Link" in e for e in errs), bad)
        errs = build.site_config_errors({"support": {"monthly": [{"label": "", "url": "https://buy.stripe.com/x"}]}})
        self.assertTrue(errs)
        errs = build.site_config_errors({"support": {"monthly": [{"label": "$3", "url": ""}]}})
        self.assertTrue(errs)
        self.assertEqual(build.site_config_errors({"support": {"one_time_url": "https://donate.stripe.com/x", "monthly": []}}), [])

    def test_the_committed_values_are_valid_stripe_links_and_hold_no_key(self):
        cfg = json.loads(read("data", "site.json"))
        self.assertEqual(build.site_config_errors(cfg), [])
        self.assertNotRegex(read("data", "site.json"), build.STRIPE_SECRET)
        urls = [cfg["support"]["one_time_url"]] + [t["url"] for t in cfg["support"]["monthly"]]
        self.assertTrue(all(u.startswith(build.STRIPE_HOSTS) for u in urls))

    def test_the_pages_exist_and_the_footer_links_the_support_page(self):
        self.assertIn('href="support.html"', read("partials", "footer.html"))
        for name in ("support.html", "thanks.html", "download.html"):
            self.assertIn(name, build.PAGES)
        self.assertIn("support@wrendns.com", self.support)
        self.assertIn('name="robots" content="noindex"', self.thanks)

    def test_a_stripe_key_anywhere_is_refused(self):
        self.assertTrue(build.STRIPE_SECRET.search("sk_live_" + "a" * 24))
        self.assertTrue(build.STRIPE_SECRET.search("pk_test_" + "b" * 24))
        self.assertTrue(build.STRIPE_SECRET.search("whsec_" + "c" * 24))
        self.assertFalse(build.STRIPE_SECRET.search("https://buy.stripe.com/test_abc"))


class Legal(unittest.TestCase):
    def test_the_drafts_render_with_anchors_and_without_their_own_notes(self):
        md = "# Terms\n\n<!-- DRAFT: a note\nover two lines -->\n\nIntro with **bold** and a [link](https://example.com).\n\n## 1. First\n\n- one\n- two\n\n### 1.1 Sub\n\n| a | b |\n|---|---|\n| x | [confirm] |\n"
        title, body = build.render_legal(md)
        self.assertEqual(title, "Terms")
        self.assertNotIn("DRAFT", body)
        self.assertIn('<h2 id="1-first">1. First</h2>', body)
        self.assertIn('<h3 id="1-1-sub">1.1 Sub</h3>', body)
        self.assertIn("<li>one</li>", body)
        self.assertIn("<b>bold</b>", body)
        self.assertIn('<span class="confirm">[confirm]</span>', body)
        self.assertEqual(body.count('class="confirm"'), 1)

    def test_terms_and_privacy_pages_come_from_docs_legal(self):
        for page, md in build.LEGAL.items():
            self.assertIn(page, build.PAGES)
            self.assertTrue(os.path.exists(os.path.join(brand.ROOT, "docs", "legal", md)))
            self.assertIn("<!-- @legal -->", read(page))
        title, body = build.render_legal(open(os.path.join(brand.ROOT, "docs", "legal", "terms.md"), encoding="utf-8").read())
        self.assertIn("4.2 Not a charitable donation", body)
        self.assertIn("support@wrendns.com", body)

    def test_every_page_has_the_footer_with_support_privacy_terms_and_the_maker(self):
        footer = read("partials", "footer.html")
        for needle in ('href="support.html"', 'href="privacy.html"', 'href="terms.html"', "WrenDNS is a product of MySummitKeep LLC"):
            self.assertIn(needle, footer)
        for name in build.PAGES:
            self.assertIn("<!-- @footer -->", read(name), name)

    def test_the_support_page_says_how_to_reach_us_and_how_to_cancel(self):
        support = read("support.html")
        self.assertIn("support@wrendns.com", support)
        self.assertIn("Stopping a monthly payment", support)
        self.assertIn("no service level", support)


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
