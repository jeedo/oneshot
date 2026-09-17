import { type Page, expect, test } from '@playwright/test';

import { baseURL } from '../playwright.config';
import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

// The whole journey a real pair of people take, end to end, plus the three ways it can end badly and the
// keyboard path through both pages. The individual mitigations are covered elsewhere; this is the check that
// they add up to something a person can actually use.
const SECRET = 'correct horse battery staple — ünïcödé ✓';

async function readClipboard(page: Page): Promise<string> {
  return page.evaluate(() => navigator.clipboard.readText());
}

test.describe('[T2] [T8] the journey from sharer to recipient', () => {
  test('create, copy the link, open it elsewhere, reveal, and the second visit says so', async ({ page, browser }) => {
    // The sharer needs clipboard write for the copy button; the recipient context gets none of it.
    const sharer = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const sharerPage = await sharer.newPage();

    await sharerPage.goto('/');
    await sharerPage.fill('#secret', SECRET);
    await sharerPage.selectOption('#ttl', '900');
    await sharerPage.click('#create');
    await expect(sharerPage.locator('#result')).toBeVisible();

    // The link the recipient actually gets is the one the copy button puts on the clipboard, not the one the
    // test read out of the DOM — so that is what the rest of the journey uses.
    await sharerPage.click('#copy');
    const link = await readClipboard(sharerPage);
    expect(link).toBe(await sharerPage.inputValue('#link'));
    expect(link).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);
    // The sharer's copy of the plaintext is gone from the page once the link exists.
    expect(await sharerPage.inputValue('#secret')).toBe('');
    await sharer.close();

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);
    await expect(recipientPage.locator('#status')).toContainText('still sealed');
    await expect(recipientPage.locator('#expiry')).toContainText('Expires');

    expect(await revealSecret(recipientPage)).toBe(SECRET);
    // Reveal cannot be pressed twice, and the page says the secret is gone from the server.
    await expect(recipientPage.locator('#reveal')).toBeDisabled();
    await recipient.close();

    // Anyone who opens the link afterwards is told plainly, including the sender if they check.
    const second = await browser.newContext();
    const secondPage = await second.newPage();
    await openRevealPage(secondPage, link);

    await expect(secondPage.locator('#status')).toContainText('already been revealed');
    await expect(secondPage.locator('#status')).toContainText('treat the secret as compromised');
    await expect(secondPage.locator('#reveal')).toBeDisabled();
    await expect(secondPage.locator('#result')).toBeHidden();
    await second.close();
    await page.close();
  });

  test('a link whose secret is not there reads as unknown', async ({ page }) => {
    // An expired secret and one that never existed are the same state by design (task 12), and the store
    // proves the expiry half in process — the minimum TTL is 60 seconds, which is not a thing to wait for in
    // a browser suite. What is checked here is that the state reaches the reader as a plain sentence.
    const { fragment } = await createSecret(page, 'unknown-state-probe');

    await page.goto(`${baseURL}/s/AAAAAAAAAAAAAAAAAAAAAA#${fragment}`);

    await expect(page.locator('#status')).toContainText('does not exist, or it has expired');
    await expect(page.locator('#reveal')).toBeDisabled();
    await expect(page.locator('#expiry')).toBeHidden();
  });

  test('a truncated link is refused before the network, and the secret stays sealed', async ({ page, request }) => {
    const { link, id, fragment } = await createSecret(page, 'truncated-link-target');

    await page.goto(link.replace(`#${fragment}`, `#${fragment.slice(0, -4)}`));

    await expect(page.locator('#error')).toContainText('This link is incomplete');
    await expect(page.locator('#reveal')).toBeDisabled();
    // Nothing was asked of the server, so the secret is untouched and a correct link still works.
    expect((await (await request.get(`/api/secrets/${id}`)).json()).state).toBe('available');

    // A fresh page, not another goto: the two links differ only in their fragment, and navigating between
    // those is a same-document move that never re-runs the script.
    const retry = await page.context().newPage();
    await openRevealPage(retry, link);
    expect(await revealSecret(retry)).toBe('truncated-link-target');
    await retry.close();
  });
});

test.describe('both pages can be driven by keyboard alone', () => {
  test('the create page: tab to each control, type, choose a lifetime, and press the button', async ({ page }) => {
    await page.goto('/');

    await page.keyboard.press('Tab');
    await expect(page.locator('#secret')).toBeFocused();
    await page.keyboard.type('typed-with-the-keyboard');

    await page.keyboard.press('Tab');
    await expect(page.locator('#ttl')).toBeFocused();
    await page.selectOption('#ttl', '300');

    await page.keyboard.press('Tab');
    await expect(page.locator('#splitKey')).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.locator('#create')).toBeFocused();
    await page.keyboard.press('Enter');

    await expect(page.locator('#result')).toBeVisible();
    // The page puts focus on the link itself rather than leaving it on the button, so the thing the sharer
    // came for is already selected and one Tab away from the copy button.
    await expect(page.locator('#link')).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.locator('#copy')).toBeFocused();
  });

  test('the reveal page: tab to Reveal, press it, and reach the revealed text', async ({ page, browser }) => {
    const { link } = await createSecret(page, 'keyboard-reveal');

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);
    await expect(recipientPage.locator('#reveal')).toBeEnabled();

    await recipientPage.keyboard.press('Tab');
    await expect(recipientPage.locator('#reveal')).toBeFocused();
    await recipientPage.keyboard.press('Enter');

    await expect(recipientPage.locator('#result')).toBeVisible();
    expect(await recipientPage.textContent('#plaintext')).toBe('keyboard-reveal');
    // Same idea on this page: focus lands on the copy button, and the secret itself is focusable one Tab on,
    // so a keyboard or screen-reader user can reach and select it.
    await expect(recipientPage.locator('#copy')).toBeFocused();
    await recipientPage.keyboard.press('Tab');
    await expect(recipientPage.locator('#plaintext')).toBeFocused();
    await recipient.close();
  });

  test('every control is named, and the two live regions announce themselves', async ({ page, browser }) => {
    await page.goto('/');

    // getByLabel resolves through the label element, so this fails if a for/id pairing is ever broken.
    await expect(page.getByLabel('Secret')).toHaveId('secret');
    await expect(page.getByLabel('Expires after')).toHaveId('ttl');
    await expect(page.locator('#error')).toHaveAttribute('role', 'alert');

    const { link } = await createSecret(page, 'labels');
    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);

    // The status is what changes without the reader doing anything, so it has to be announced.
    await expect(recipientPage.locator('#status')).toHaveAttribute('role', 'status');
    await expect(recipientPage.locator('#error')).toHaveAttribute('role', 'alert');
    await revealSecret(recipientPage);
    await expect(recipientPage.getByLabel('Secret')).toHaveId('plaintext');
    await recipient.close();
  });
});
