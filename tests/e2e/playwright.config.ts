import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env['ONESHOT_PORT'] ?? 5173);
export const baseURL = `http://127.0.0.1:${port}`;

// A different registrable domain from 127.0.0.1, so requests it makes to the app are cross-site, not merely
// cross-origin. It resolves only because of the resolver rule below; specs/cross-origin.spec.ts serves it.
export const ATTACKER_HOST = 'attacker.test';

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env['CI'],
  retries: 0,
  reporter: process.env['CI'] ? [['github'], ['list']] : [['list']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    // The app refuses to encrypt without crypto.subtle, which browsers expose on localhost over plain HTTP.
    ignoreHTTPSErrors: false,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Chromium's Local Network Access blocks any page outside the loopback address space from reaching
        // 127.0.0.1, so a cross-site attacker page has to be served from loopback too. Mapping a name the
        // browser treats as another site onto loopback gives the cross-origin specs a real foreign origin
        // instead of one the browser refuses to let near the app.
        launchOptions: { args: [`--host-resolver-rules=MAP ${ATTACKER_HOST} 127.0.0.1`] },
      },
    },
  ],
  webServer: {
    // --no-launch-profile: Properties/launchSettings.json (issue #78) sets ASPNETCORE_ENVIRONMENT=Development
    // for local `dotnet run`, and dotnet applies that unconditionally — it overrides an inherited environment
    // variable of the same name rather than deferring to it. Confirmed the hard way: without this flag, this
    // suite silently ran against Development instead of Production and two specs failed. The suite needs full
    // control of its own environment, not whatever a developer's local default happens to be.
    command: `dotnet run --project ../../src/OneShot.Web --no-launch-profile --urls ${baseURL}`,
    // Production, so the suite exercises the deployment the startup validation of task 49 actually allows.
    // Declaring loopback as a known proxy stands in for TLS terminating upstream, which is what lets a
    // plain-HTTP listener pass validation.
    env: {
      ASPNETCORE_ENVIRONMENT: 'Production',
      ForwardedHeaders__KnownProxies__0: '127.0.0.1',
      // Every spec talks to the app from the same loopback address, so they all share one rate-limit
      // partition and the whole suite spends a single 30-reads-per-minute budget. That budget is the
      // subject of tasks 20, 29 and 30, which prove it in-process with a distinct client address per test;
      // here it is only a cap on how many specs may run in a minute, so it is lifted rather than left as a
      // limit the suite grows into.
      RateLimiting__CreatePerWindow: '10000',
      RateLimiting__ReadPerWindow: '10000',
    },
    // Task 24's liveness endpoint: a bare 200 with no body, so readiness costs nothing.
    url: `${baseURL}/healthz`,
    reuseExistingServer: !process.env['CI'],
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
