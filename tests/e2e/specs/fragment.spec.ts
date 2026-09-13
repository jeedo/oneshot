import { expect, test } from '@playwright/test';

import { baseURL } from '../playwright.config';
import { createSecret, revealSecret } from '../support/oneshot';

// TransportTests shows the server redirects a plain-HTTP request before anything runs. This is the other half
// of that story, and it is a browser behaviour the design depends on rather than one the app controls: the
// fragment is never put on the wire, and it survives the upgrade so the recipient can still read the secret.
test.describe('[T8] the key rides in the fragment and never on the wire', () => {
  test('the navigation that opens a reveal link carries no fragment', async ({ page }) => {
    const { link, fragment } = await createSecret(page, 'fragment-on-the-wire');
    expect(link).toContain('#');

    const urls: string[] = [];
    page.on('request', (request) => urls.push(request.url()));
    await page.goto(link);
    await expect(page.locator('#reveal')).toBeEnabled();

    // The browser cuts the fragment off before sending, so the server never had the chance to log it.
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(url).not.toContain('#');
      expect(url).not.toContain(fragment);
    }
  });

  test('the key survives a redirect to the upgraded url and still decrypts', async ({ page, browser }) => {
    const plaintext = 'survives-the-upgrade';
    const { id, fragment } = await createSecret(page, plaintext);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    const urls: string[] = [];
    recipientPage.on('request', (request) => urls.push(request.url()));

    // Stands in for HttpsRedirectionMiddleware: the app answers a plain-HTTP request with a 307 to the same
    // path. The scheme differs in production, but what is being checked here is the browser's fragment
    // handling across a redirect, which is the same either way.
    await recipientPage.route(`${baseURL}/upgrade/**`, (route) =>
      route.fulfill({ status: 307, headers: { Location: `${baseURL}/s/${id}` }, body: '' }),
    );

    await recipientPage.goto(`${baseURL}/upgrade/s/${id}#${fragment}`);

    // The strongest evidence the key came through the redirect intact: the secret actually decrypts.
    expect(await revealSecret(recipientPage)).toBe(plaintext);
    for (const url of urls) {
      expect(url).not.toContain(fragment);
    }
    await recipient.close();
  });

  test('a link opened in a new tab keeps the key out of every request there too', async ({ page, context }) => {
    const plaintext = 'new-tab-target';
    const { link, fragment } = await createSecret(page, plaintext);

    const opened = context.waitForEvent('page');
    await page.evaluate((target) => window.open(target, '_blank'), link);
    const tab = await opened;
    const urls: string[] = [];
    tab.on('request', (request) => urls.push(request.url()));
    await tab.waitForLoadState();

    expect(await revealSecret(tab)).toBe(plaintext);
    // window.open carries the fragment to the new document without ever sending it, and the opener cannot
    // read it back out afterwards because the page has already stripped it.
    for (const url of urls) {
      expect(url).not.toContain(fragment);
    }
    expect(await tab.evaluate(() => location.hash)).toBe('');
    await tab.close();
  });
});
