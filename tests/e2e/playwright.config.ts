import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env['ONESHOT_PORT'] ?? 5173);
export const baseURL = `http://127.0.0.1:${port}`;

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
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `dotnet run --project ../../src/OneShot.Web --urls ${baseURL}`,
    // Task 24's liveness endpoint: a bare 200 with no body, so readiness costs nothing.
    url: `${baseURL}/healthz`,
    reuseExistingServer: !process.env['CI'],
    timeout: 180_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
