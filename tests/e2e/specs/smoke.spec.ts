import { expect, test } from '@playwright/test';

import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

test.describe('harness smoke', () => {
  test('the app is reachable and reports liveness', async ({ request }) => {
    const response = await request.get('/healthz');

    expect(response.status()).toBe(200);
    expect(await response.text()).toBe('');
  });

  test('a secret survives the full create, share and reveal round trip', async ({ page, context }) => {
    const secret = 'harness-round-trip — ünïcödé ✓';

    const { link } = await createSecret(page, secret, 900);

    // A fresh context stands in for the recipient: no shared state with the sharer's page.
    const recipient = await context.browser()!.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);

    expect(await revealSecret(recipientPage)).toBe(secret);
    await recipient.close();
  });

  test('the browser exposes the crypto the client needs', async ({ page }) => {
    await page.goto('/');

    expect(await page.evaluate(() => typeof crypto.subtle?.encrypt)).toBe('function');
    expect(await page.evaluate(() => crypto.getRandomValues(new Uint8Array(4)).length)).toBe(4);
  });
});
