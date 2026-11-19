import { defineConfig, devices } from '@playwright/test';
import { BASE_URL } from './tests/e2e/ports';

// REQ: API-005 — T3.9 acceptance: the Playwright suite runs the real binary (`server.mjs`).
// Build first: `cargo build -p wrendns` and `npm run build` (or set WRENDNS_BIN).
export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: false,
  workers: 1,
  // No retries: the file is one `serial` group sharing one server, so a retry reruns the group
  // against what the first attempt left behind (an allowed `ads.e2e.test`, a longer query log)
  // and fails in `obs_026` or `obs_024` instead, hiding the real failure. Re-run the job instead.
  retries: 0,
  // Shared CI runners stall for seconds at a time (page loads, Argon2 sign-ins); 5 s flaked.
  expect: { timeout: process.env.CI ? 15_000 : 5_000 },
  // `github` turns failures into annotations (readable without the job log).
  reporter: process.env.CI ? [['list'], ['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'node tests/e2e/server.mjs',
    url: `${BASE_URL}/livez`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
