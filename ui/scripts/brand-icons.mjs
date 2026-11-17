// REQ: OBS-039 (ADR-167) — builds the domain icons' data from Simple Icons (CC0-1.0):
//   ui/src/lib/icons/brands.ts    brand colour and 24x24 glyph path per slug (a lazy chunk in the UI)
//   ui/src/lib/icons/map.data.ts  the domains (or hosts) each brand owns, and the brand titles
// Both are committed: a build never needs the network or this package. Run it to change the curated
// list below or to move to another Simple Icons release (then review the diff):
//   cd ui && npm i --no-save simple-icons@16.38.0 && node scripts/brand-icons.mjs
// or point SIMPLE_ICONS_DIR at an installed copy. It reports the brands Simple Icons doesn't carry
// (the pack has dropped several large companies' marks: those names wear a monogram) and which
// of our service presets (presets/services) still have no icon.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PINNED = '16.38.0';
const ROOT = path.resolve(import.meta.dirname, '../..');
const OUT = path.join(ROOT, 'ui/src/lib/icons');
const dir = process.env.SIMPLE_ICONS_DIR ?? path.join(import.meta.dirname, '../node_modules/simple-icons');
const installed = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version;
if (installed !== PINNED) {
  console.error(`simple-icons ${installed} is installed but ${PINNED} is pinned here. Install ${PINNED}, or change PINNED and review the diff.`);
  process.exit(1);
}
const si = await import(pathToFileURL(path.join(dir, 'index.mjs')).href);
const all = Object.values(si).filter((x) => x && typeof x === 'object' && x.slug);
const bySlug = new Map(all.map((x) => [x.slug, x]));

// [candidate slugs (the first one Simple Icons has wins), the domains the brand owns]. A full host is
// allowed (`teams.microsoft.com`): the longest matching suffix of a name wins.
const LIST = [
  // Google and friends
  [['google'], ['google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'gvt1.com', 'gvt2.com', 'ggpht.com', 'withgoogle.com', 'google.co.uk']],
  [['youtube'], ['youtube.com', 'ytimg.com', 'googlevideo.com', 'youtu.be', 'youtube-nocookie.com']],
  [['googleads'], ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'googletagservices.com']],
  [['googleanalytics'], ['google-analytics.com', 'analytics.google.com']],
  [['googletagmanager'], ['googletagmanager.com']],
  [['firebase'], ['firebaseio.com', 'firebaseapp.com', 'app-measurement.com', 'firebaselogging-pa.googleapis.com']],
  [['android'], ['android.com']],
  [['gmail'], ['gmail.com']],
  // Apple
  [['apple'], ['apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com', 'apple-dns.net', 'icloud-content.com', 'aaplimg.com']],
  [['applemusic'], ['music.apple.com']],
  [['appletv'], ['tv.apple.com']],
  // Microsoft (Simple Icons dropped the main logo; the product marks it keeps are used where they exist)
  [['microsoft'], ['microsoft.com', 'msftconnecttest.com']],
  [['microsoftoffice', 'microsoft365'], ['office.com', 'office365.com', 'office.net', 'officeapps.live.com', 'microsoftonline.com', 'sharepoint.com']],
  [['microsoftteams'], ['teams.microsoft.com', 'teams.events.data.microsoft.com']],
  [['microsoftedge'], ['edge.microsoft.com', 'msedge.net']],
  [['microsoftazure', 'azure'], ['azure.com', 'azureedge.net', 'azurewebsites.net', 'windows.net']],
  [['bing'], ['bing.com', 'bing.net']],
  [['windows11', 'windows'], ['windowsupdate.com', 'windows.com', 'live.com']],
  [['xbox'], ['xbox.com', 'xboxlive.com']],
  [['github'], ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.io', 'githubcopilot.com']],
  [['linkedin'], ['linkedin.com', 'licdn.com']],
  // Amazon
  [['amazon'], ['amazon.com', 'media-amazon.com', 'ssl-images-amazon.com', 'amazon.co.uk']],
  [['amazonwebservices', 'amazonaws'], ['amazonaws.com', 'awsstatic.com', 'aws.amazon.com']],
  [['amazoncloudfront', 'amazonaws'], ['cloudfront.net']],
  [['primevideo'], ['primevideo.com', 'aiv-cdn.net', 'amazonvideo.com', 'pv-cdn.net']],
  [['amazonalexa', 'alexa'], ['alexa.amazon.com', 'alexa.com']],
  [['ring'], ['ring.com']],
  // Social and messaging
  [['facebook'], ['facebook.com', 'fbcdn.net', 'fb.com', 'fbsbx.com', 'facebook.net']],
  [['meta'], ['meta.com']],
  [['instagram'], ['instagram.com', 'cdninstagram.com']],
  [['whatsapp'], ['whatsapp.com', 'whatsapp.net', 'wa.me']],
  [['messenger'], ['messenger.com']],
  [['x'], ['x.com', 'twitter.com', 'twimg.com', 't.co']],
  [['reddit'], ['reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com']],
  [['tiktok'], ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'tiktokcdn-us.com', 'ttwstatic.com']],
  [['snapchat'], ['snapchat.com', 'sc-cdn.net', 'snap-dev.net']],
  [['pinterest'], ['pinterest.com', 'pinimg.com']],
  [['tumblr'], ['tumblr.com']],
  [['discord'], ['discord.com', 'discordapp.com', 'discord.gg', 'discordapp.net']],
  [['telegram'], ['telegram.org', 't.me', 'telegram.me']],
  [['signal'], ['signal.org']],
  [['mastodon'], ['mastodon.social', 'joinmastodon.org']],
  [['twitch'], ['twitch.tv', 'ttvnw.net', 'jtvnw.net', 'twitchcdn.net']],
  [['tinder'], ['tinder.com', 'gotinder.com']],
  [['slack'], ['slack.com', 'slack-edge.com']],
  [['zoom'], ['zoom.us', 'zoom.com']],
  // Streaming
  [['netflix'], ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxso.net', 'nflxext.com']],
  [['spotify'], ['spotify.com', 'scdn.co', 'spotifycdn.com']],
  [['disneyplus', 'disney'], ['disneyplus.com', 'disney.com', 'bamgrid.com', 'dssott.com']],
  [['hulu'], ['hulu.com', 'hulustream.com']],
  [['hbomax', 'max'], ['max.com', 'hbomax.com']],
  [['paramountplus'], ['paramountplus.com']],
  [['plex'], ['plex.tv', 'plex.direct']],
  [['roku'], ['roku.com']],
  [['soundcloud'], ['soundcloud.com', 'sndcdn.com']],
  [['vimeo'], ['vimeo.com', 'vimeocdn.com']],
  [['crunchyroll'], ['crunchyroll.com']],
  // Gaming
  [['steam'], ['steampowered.com', 'steamcontent.com', 'steamstatic.com', 'steamcommunity.com', 'valvesoftware.com']],
  [['epicgames'], ['epicgames.com', 'unrealengine.com', 'epicgames.dev']],
  [['roblox'], ['roblox.com', 'rbxcdn.com', 'rbx.com', 'robloxlabs.com']],
  [['minecraft'], ['minecraft.net', 'mojang.com']],
  [['playstation'], ['playstation.com', 'playstation.net', 'sonyentertainmentnetwork.com']],
  [['nintendo', 'nintendoswitch'], ['nintendo.com', 'nintendo.net']],
  [['ea'], ['ea.com']],
  [['battledotnet', 'battlenet'], ['battle.net', 'blizzard.com']],
  // Developer and infrastructure
  [['cloudflare'], ['cloudflare.com', 'cloudflare-dns.com', 'cloudflarestream.com', 'workers.dev', 'pages.dev']],
  [['jsdelivr'], ['jsdelivr.net']],
  [['npm'], ['npmjs.org', 'npmjs.com']],
  [['docker'], ['docker.com', 'docker.io']],
  [['kubernetes'], ['kubernetes.io', 'k8s.io']],
  [['helm'], ['helm.sh']],
  [['grafana'], ['grafana.com', 'grafana.org', 'grafana.net']],
  [['prometheus'], ['prometheus.io']],
  [['gitlab'], ['gitlab.com']],
  [['ubuntu'], ['ubuntu.com', 'canonical.com']],
  [['debian'], ['debian.org']],
  [['fedora'], ['fedoraproject.org']],
  [['archlinux'], ['archlinux.org']],
  [['redhat'], ['redhat.com']],
  [['python'], ['python.org']],
  [['pypi'], ['pypi.org', 'pythonhosted.org']],
  [['rust'], ['rust-lang.org', 'crates.io']],
  [['nodedotjs'], ['nodejs.org']],
  [['letsencrypt'], ['letsencrypt.org']],
  [['homeassistant'], ['home-assistant.io', 'nabucasa.com']],
  [['openai'], ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com']],
  [['anthropic'], ['anthropic.com']],
  [['claude'], ['claude.ai']],
  [['stackoverflow'], ['stackoverflow.com', 'sstatic.net']],
  [['stackexchange'], ['stackexchange.com']],
  [['ycombinator'], ['ycombinator.com']],
  [['wikipedia'], ['wikipedia.org']],
  [['wikimediacommons', 'wikimedia'], ['wikimedia.org']],
  [['firefox'], ['mozilla.org', 'mozilla.com', 'mozilla.net', 'firefox.com']],
  [['brave'], ['brave.com']],
  [['duckduckgo'], ['duckduckgo.com']],
  [['protonmail', 'proton'], ['proton.me', 'protonmail.com']],
  [['dropbox'], ['dropbox.com', 'dropboxstatic.com']],
  [['atlassian'], ['atlassian.com', 'atlassian.net']],
  [['notion'], ['notion.so', 'notion.com']],
  [['figma'], ['figma.com']],
  [['adobe'], ['adobe.com', 'adobe.io', 'typekit.net']],
  [['datadog'], ['datadoghq.com']],
  [['sentry'], ['sentry.io']],
  [['newrelic'], ['newrelic.com']],
  [['fastly'], ['fastly.net']],
  [['akamai'], ['akamai.net', 'akamaiedge.net', 'akamaihd.net', 'akamaized.net']],
  [['wordpress'], ['wordpress.com', 'wp.com']],
  [['gravatar'], ['gravatar.com']],
  [['medium'], ['medium.com']],
  [['backstage'], ['backstage.io']],
  [['argo'], ['argoproj.io']],
  [['loki', 'grafana'], ['grafana.io']],
  // Devices and the home
  [['samsung'], ['samsung.com', 'samsungcloudsolution.com', 'samsungosp.com', 'samsungapps.com', 'samsungcloudsolution.net']],
  [['lg'], ['lg.com', 'lgtvsdk.com', 'lgsmartad.com']],
  [['sonos'], ['sonos.com']],
  [['philipshue'], ['meethue.com']],
  [['tplink'], ['tp-link.com', 'tplinkcloud.com', 'tplinkra.com']],
  [['ubiquiti'], ['ui.com', 'ubnt.com']],
  [['nest', 'googlenest'], ['nest.com']],
  [['ecobee'], ['ecobee.com']],
  [['tesla'], ['tesla.com']],
  // News, shopping, money
  [['bbc'], ['bbc.co.uk', 'bbc.com', 'bbci.co.uk']],
  [['nytimes', 'newyorktimes'], ['nytimes.com']],
  [['theguardian', 'guardian'], ['theguardian.com']],
  [['paypal'], ['paypal.com', 'paypalobjects.com']],
  [['stripe'], ['stripe.com', 'stripe.network']],
  [['shopify'], ['shopify.com', 'myshopify.com']],
  [['ebay'], ['ebay.com', 'ebaystatic.com']],
  [['walmart'], ['walmart.com']],
  [['airbnb'], ['airbnb.com']],
  [['uber'], ['uber.com']],
  [['webex', 'cisco'], ['webex.com']],
];

const brands = {};
const titles = {};
const map = {};
const dropped = [];
for (const [cands, domains] of LIST) {
  const slug = cands.find((c) => bySlug.has(c));
  if (!slug) {
    dropped.push(`${cands[0]} (${domains[0]}${domains.length > 1 ? ` +${domains.length - 1}` : ''})`);
    continue;
  }
  const i = bySlug.get(slug);
  brands[slug] = [i.hex, i.path];
  titles[slug] = i.title;
  for (const d of domains) map[d] = slug;
}

const sorted = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
const head = `// GENERATED by ui/scripts/brand-icons.mjs from simple-icons ${PINNED} (CC0-1.0); do not edit by hand.\n`;
fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(
  path.join(OUT, 'brands.ts'),
  `${head}// slug -> [brand colour (hex, no #), 24x24 SVG path]. A separate chunk: loaded when the first brand icon is drawn.\nexport const BRANDS: Record<string, [string, string]> = ${JSON.stringify(sorted(brands))};\n`,
);
fs.writeFileSync(
  path.join(OUT, 'map.data.ts'),
  `${head}/** A domain (or host) a brand owns -> its slug. The longest matching suffix of a name wins. */\nexport const BRAND_OF: Record<string, string> = ${JSON.stringify(sorted(map))};\nexport const BRAND_TITLE: Record<string, string> = ${JSON.stringify(sorted(titles))};\n`,
);

const suffixHit = (name) => {
  const parts = name.split('.');
  for (let k = 0; k < parts.length - 1; k++) if (map[parts.slice(k).join('.')]) return map[parts.slice(k).join('.')];
  return null;
};
const uncovered = [];
let services = 0;
const presets = path.join(ROOT, 'presets/services');
for (const f of fs.readdirSync(presets).filter((n) => n.endsWith('.toml'))) {
  for (const block of fs.readFileSync(path.join(presets, f), 'utf8').split('[[service]]').slice(1)) {
    services++;
    const id = /id = "([^"]+)"/.exec(block)?.[1];
    const doms = [...block.matchAll(/"\|\|([a-z0-9.-]+)\^"/g)].map((m) => m[1]);
    if (!doms.map(suffixHit).find(Boolean)) uncovered.push(id);
  }
}
const raw = JSON.stringify(sorted(brands)).length;
console.log(`${Object.keys(brands).length} of ${LIST.length} brands have an icon; ${Object.keys(map).length} domains mapped; glyph data ${(raw / 1024).toFixed(0)} KiB raw`);
console.log(`not in Simple Icons (${dropped.length}): ${dropped.join('; ')}`);
console.log(`service presets without an icon (${uncovered.length} of ${services}): ${uncovered.join(', ')}`);
