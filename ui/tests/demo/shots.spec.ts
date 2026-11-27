// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: DOC-002 — the screenshots of the README and the site, taken on the made-up network of
// demo.toml (a three-node cluster on loopback with a stub UniFi gateway) after run.sh has sent it
// synthetic traffic. Not part of the e2e suite.
//   README (docs/images/<page>-day.jpg and -night.jpg, 1280x860 at 1.5x): dashboard, map, cmdb,
//     queries, cluster.
//   Site (site/assets/shots/<page>-light.jpg and -dark.jpg, 1280x860): dashboard, traffic,
//     queries, why.
import { test, type Page } from '@playwright/test';
import { capture } from './capture';
import { resolve } from 'node:path';

const repo = resolve(import.meta.dirname, '../../..');
// The brand's names for the two themes (brand/README.md): Day and Night.
const brandName = { light: 'day', dark: 'night' } as const;

async function readmeShot(page: Page, name: string, theme: 'light' | 'dark') {
  await page.mouse.move(0, 0);
  await page.screenshot({ path: `${repo}/docs/images/${name}-${brandName[theme]}.jpg`, type: 'jpeg', quality: 72 });
}

for (const theme of ['light', 'dark'] as const) {
  test(`dashboard ${theme}`, async ({ browser }) => {
    // The README: sharp on high-density screens.
    const readme = await capture(browser, theme, 1280, 860, 1.5);
    await readmeShot(readme.page, 'dashboard', theme);
    await readme.context.close();
    // The site: the same size as its other screenshots (2-shots.spec.ts).
    const site = await capture(browser, theme, 1280, 860, 1);
    await site.page.screenshot({ path: `${repo}/site/assets/shots/dashboard-${theme}.jpg`, type: 'jpeg', quality: 80 });
    await site.context.close();
  });

  // REQ: OBS-026 — the traffic map, after two refreshes so growing tiles are marked.
  test(`traffic map ${theme}`, async ({ browser }) => {
    const site = await capture(browser, theme, 1280, 860, 1);
    await site.page.goto('/#/traffic');
    await site.page.getByRole('button', { name: 'Services', exact: true }).click();
    await site.page.waitForTimeout(11_000);
    await site.page.mouse.move(0, 0);
    await site.page.screenshot({ path: `${repo}/site/assets/shots/traffic-${theme}.jpg`, type: 'jpeg', quality: 80 });
    await site.context.close();
  });

  // The query log, and "Why?" on a blocked query (it names the list and the rule): the demo's
  // made-up devices read better than the e2e suite's leftovers.
  test(`query log ${theme}`, async ({ browser }) => {
    const site = await capture(browser, theme, 1280, 860, 1);
    await site.page.goto('/#/queries');
    await site.page.waitForTimeout(1500);
    await site.page.screenshot({ path: `${repo}/site/assets/shots/queries-${theme}.jpg`, type: 'jpeg', quality: 80 });
    const readme = await capture(browser, theme, 1280, 860, 1.5);
    await readme.page.goto('/#/queries');
    await readme.page.waitForTimeout(1500);
    await readmeShot(readme.page, 'queries', theme);
    await readme.context.close();
    await site.page.goto('/#/queries?status=blocked');
    // Wait for the filtered log: the first "Why?" must be on a blocked query.
    await site.page.waitForTimeout(2500);
    await site.page.getByRole('button', { name: 'Why?' }).first().click();
    await site.page.waitForTimeout(600);
    await site.page.screenshot({ path: `${repo}/site/assets/shots/why-${theme}.jpg`, type: 'jpeg', quality: 80 });
    await site.context.close();
  });

  // REQ: OBS-901 — the network map: the three nodes, the upstreams and the device groups, coloured
  // by health, after a few samples.
  test(`network map ${theme}`, async ({ browser }) => {
    const readme = await capture(browser, theme, 1280, 860, 1.5);
    await readme.page.goto('/#/map');
    await readme.page.getByRole('heading', { name: 'Network map' }).waitFor();
    await readme.page.waitForTimeout(8000);
    await readmeShot(readme.page, 'map', theme);
    await readme.context.close();
  });

  // REQ: DSC-901, DSC-903 — one device in the CMDB with the records of each source that reported
  // it (the configuration, the UniFi gateway, the queries), side by side.
  test(`cmdb device ${theme}`, async ({ browser }) => {
    const readme = await capture(browser, theme, 1280, 860, 1.5);
    await readme.page.goto('/#/cmdb');
    // One row in the list, so the device's card sits right under it.
    await readme.page.getByLabel('Find a CI').fill('Ava');
    await readme.page.getByRole('button', { name: "Ava's iPad" }).click();
    const card = readme.page.getByTestId('cmdb-ci');
    await card.waitFor();
    await readme.page.waitForTimeout(800);
    await card.evaluate((el) => el.scrollIntoView({ block: 'start' }));
    await readme.page.evaluate(() => window.scrollBy(0, -16));
    await readmeShot(readme.page, 'cmdb', theme);
    await readme.context.close();
  });

  // REQ: CLU-001 — the Cluster page of the demo's three real nodes: pi-01 (the primary), pi-02 and
  // k8s-a.
  test(`cluster ${theme}`, async ({ browser }) => {
    const readme = await capture(browser, theme, 1280, 860, 1.5);
    await readme.page.goto('/#/cluster');
    await readme.page.getByRole('heading', { name: 'Cluster' }).first().waitFor();
    await readme.page.waitForTimeout(2500);
    await readmeShot(readme.page, 'cluster', theme);
    await readme.context.close();
  });
}
