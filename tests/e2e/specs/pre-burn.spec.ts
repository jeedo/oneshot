import { expect, test } from '@playwright/test';

import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

// A gateway that merely fetches the link cannot burn it — but the dangerous case is one that runs the page's
// JavaScript, since the page itself calls whoami and peek on load. Only a real browser proves that path.
const scanners = [
  {
    name: 'Outlook SafeLinks',
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OutlookSafeLinks',
    headers: {},
  },
  {
    name: 'Mimecast with a prefetch hint',
    userAgent: 'Mozilla/5.0 (compatible; Mimecast Link Scanner)',
    headers: { Purpose: 'prefetch', 'Sec-Purpose': 'prefetch;prerender' },
  },
  {
    name: 'headless Chrome',
    userAgent:
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
    headers: {},
  },
];

test.describe('[T4] link scanners cannot pre-burn a secret', () => {
  for (const scanner of scanners) {
    test(`${scanner.name} loads the page, runs its script, and leaves the secret sealed`, async ({ page, browser, request }) => {
      const secret = `pre-burn-${scanner.name.replace(/\W+/g, '-')}`;
      const { link, id } = await createSecret(page, secret);

      const context = await browser.newContext({ userAgent: scanner.userAgent, extraHTTPHeaders: scanner.headers });
      const scannerPage = await context.newPage();
      await scannerPage.goto(link);
      // Wait for the page's own load path to finish: it reaches the point where Reveal becomes available.
      await expect(scannerPage.locator('#reveal')).toBeEnabled();
      await context.close();

      const peek = await request.get(`/api/secrets/${id}`);
      expect(peek.status()).toBe(200);
      expect((await peek.json()).state).toBe('available');
    });
  }

  test('a scanner visit does not stop the real recipient revealing afterwards', async ({ page, browser }) => {
    const secret = 'survives-the-scanner — ünïcödé';
    const { link } = await createSecret(page, secret);

    const scanner = await browser.newContext({ userAgent: scanners[0]!.userAgent });
    const scannerPage = await scanner.newPage();
    await scannerPage.goto(link);
    await expect(scannerPage.locator('#reveal')).toBeEnabled();
    await scanner.close();

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);

    expect(await revealSecret(recipientPage)).toBe(secret);
    await recipient.close();
  });

  test('only the explicit click consumes: the page load alone never does', async ({ page, request }) => {
    const { link, id } = await createSecret(page, 'click-is-the-only-trigger');

    // Each visit re-runs the whole load path, including its whoami and peek calls.
    for (let i = 0; i < 4; i++) {
      await page.goto(link);
      await expect(page.locator('#reveal')).toBeEnabled();
    }
    expect((await (await request.get(`/api/secrets/${id}`)).json()).state).toBe('available');

    await page.click('#reveal');
    await expect(page.locator('#result')).toBeVisible();

    expect((await (await request.get(`/api/secrets/${id}`)).json()).state).toBe('consumed');
  });

  test('[T8] reloading after the fragment is stripped prompts for the key again, without burning the secret', async ({ page, request }) => {
    const { link, id } = await createSecret(page, 'reload-loses-the-key');

    await page.goto(link);
    await expect(page.locator('#reveal')).toBeEnabled();
    expect(await page.evaluate(() => location.hash)).toBe('');

    // The reload carries no fragment, because the page removed it from the address bar on first load. The
    // reveal page cannot tell that apart from a link whose key was withheld on purpose for split-channel
    // delivery (issue #77), so it prompts for the key again instead of erroring — either way, the secret
    // itself stays untouched until a valid key is actually supplied.
    await page.reload();

    await expect(page.locator('#keyEntry')).toBeVisible();
    await expect(page.locator('#error')).toBeHidden();
    await expect(page.locator('#reveal')).toBeDisabled();
    expect((await (await request.get(`/api/secrets/${id}`)).json()).state).toBe('available');
  });
});
