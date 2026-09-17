import { type Page, expect, test } from '@playwright/test';

// Issue #77: an opt-in that withholds the key from the link so the link and key can be sent over two
// different channels. This is the end-to-end proof that the two halves the unit/vitest suites cover in
// isolation (link.test.ts, createFlow.test.ts, revealFlow.test.ts) actually fit together in a browser: a real
// bare link, a real manually-typed key, and a real decrypt.
const SECRET = 'sent-over-two-channels — ünïcödé ✓';

async function readClipboard(page: Page): Promise<string> {
  return page.evaluate(() => navigator.clipboard.readText());
}

test.describe('[T1] [T8] [T9] split-channel key delivery', () => {
  test('create with the split-key option produces a bare link and a separate key, and the recipient can reveal by typing it in', async ({
    page,
    browser,
  }) => {
    const sharer = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const sharerPage = await sharer.newPage();

    await sharerPage.goto('/');
    await sharerPage.fill('#secret', SECRET);
    await sharerPage.check('#splitKey');
    await sharerPage.click('#create');
    await expect(sharerPage.locator('#result')).toBeVisible();

    const link = await sharerPage.inputValue('#link');
    expect(link).not.toContain('#');
    expect(link).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]{22}$/);

    await expect(sharerPage.locator('#keyField')).toBeVisible();
    const key = await sharerPage.inputValue('#key');
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // Both fields are independently copyable, since they are meant to go out through two different channels.
    await sharerPage.click('#copy');
    expect(await readClipboard(sharerPage)).toBe(link);
    await sharerPage.click('#copyKey');
    expect(await readClipboard(sharerPage)).toBe(key);
    await sharer.close();

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await recipientPage.goto(link);
    await expect(recipientPage.locator('#status')).toContainText('still sealed');
    // No fragment was ever given, so this is a prompt for the key, not the "invalid link" error.
    await expect(recipientPage.locator('#error')).toBeHidden();
    await expect(recipientPage.locator('#keyEntry')).toBeVisible();
    await expect(recipientPage.locator('#reveal')).toBeDisabled();

    // A key of the wrong shape must not arm Reveal — same gate the fragment path already enforces.
    await recipientPage.fill('#manualKey', key.slice(0, -4));
    await expect(recipientPage.locator('#reveal')).toBeDisabled();

    await recipientPage.fill('#manualKey', key);
    await expect(recipientPage.locator('#reveal')).toBeEnabled();
    await recipientPage.click('#reveal');
    await expect(recipientPage.locator('#result')).toBeVisible();
    expect(await recipientPage.textContent('#plaintext')).toBe(SECRET);
    await recipient.close();
  });

  test('without the split-key option the link still carries the key in the fragment, as before', async ({ page }) => {
    await page.goto('/');
    await page.fill('#secret', 'unsplit-secret');
    await page.click('#create');
    await expect(page.locator('#result')).toBeVisible();

    expect(await page.inputValue('#link')).toContain('#');
    await expect(page.locator('#keyField')).toBeHidden();
  });

  test('an unknown id with no fragment shows the unknown state, not a key prompt', async ({ page }) => {
    await page.goto('/s/AAAAAAAAAAAAAAAAAAAAAA');

    await expect(page.locator('#status')).toContainText('does not exist, or it has expired');
    await expect(page.locator('#keyEntry')).toBeHidden();
    await expect(page.locator('#reveal')).toBeDisabled();
  });
});
