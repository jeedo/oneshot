import { type Page, type Request, expect, test } from '@playwright/test';

import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

// The server side of T1 is swept in process by LeakTests. This is the half that cannot be: the key is
// generated in the browser and travels only in the URL fragment, so the only place its absence from the
// wire can be shown is the browser itself, watching every request the page actually makes.
const CANARY = 'CANARY-PLAINTEXT-4d71fe08';

interface Sent {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

function record(page: Page): Sent[] {
  const sent: Sent[] = [];
  page.on('request', (request: Request) => {
    void (async () => {
      sent.push({
        method: request.method(),
        url: request.url(),
        headers: await request.allHeaders().catch(() => ({})),
        body: request.postData(),
      });
    })();
  });
  return sent;
}

// Every shape the same key bytes could take on the wire. Takes the key itself (ShareLink.key) rather than the
// fragment specifically, so it works whether the key rode in the link or was shown separately (split-channel
// delivery, issue #77) — either way this is the value that must never appear on the wire.
function keyEncodings(key: string): string[] {
  const bytes = Buffer.from(key.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  expect(bytes.length).toBe(32);

  return [
    key,
    encodeURIComponent(key),
    bytes.toString('base64'),
    encodeURIComponent(bytes.toString('base64')),
    bytes.toString('hex'),
    bytes.toString('hex').toUpperCase(),
  ];
}

function assertAbsent(sent: Sent[], needles: string[]): void {
  expect(sent.length).toBeGreaterThan(0);

  for (const request of sent) {
    const haystack = [
      request.url,
      request.body ?? '',
      ...Object.entries(request.headers).map(([name, value]) => `${name}: ${value}`),
    ].join('\n');

    for (const needle of needles) {
      expect(haystack, `${request.method} ${request.url} carried a canary`).not.toContain(needle);
    }
  }
}

test.describe('[T1] the key and the plaintext never leave the browser', () => {
  test('creating a secret sends ciphertext and nonce and nothing else', async ({ page }) => {
    const sent = record(page);

    const { key, id } = await createSecret(page, CANARY);

    // Sanity first: without these the sweep below could pass on an empty or unrelated capture.
    const create = sent.find((request) => request.method === 'POST' && request.url.endsWith('/api/secrets'));
    expect(create, 'no create request was captured').toBeDefined();
    const posted = JSON.parse(create!.body!) as Record<string, unknown>;
    // Ciphertext of the canary plus the GCM tag, base64url encoded — proof that something was really
    // encrypted and sent, so the sweep below is not passing over an empty request.
    expect(Object.keys(posted).sort()).toEqual(['ciphertext', 'nonce', 'ttlSeconds']);
    expect((posted['ciphertext'] as string).length).toBeGreaterThan(CANARY.length);
    expect(id).toHaveLength(22);

    assertAbsent(sent, [CANARY, ...keyEncodings(key)]);
  });

  test('revealing a secret sends the id and nothing else', async ({ page, browser }) => {
    const { link, key, id } = await createSecret(page, CANARY);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    const sent = record(recipientPage);
    await openRevealPage(recipientPage, link, key);

    expect(await revealSecret(recipientPage)).toBe(CANARY);

    // The reveal really happened, so the sweep is over a real conversation with the server.
    const reveal = sent.find((request) => request.method === 'POST' && request.url.endsWith('/reveal'));
    expect(reveal, 'no reveal request was captured').toBeDefined();
    expect(reveal!.url).toContain(id);

    assertAbsent(sent, [CANARY, ...keyEncodings(key)]);
    await recipient.close();
  });

  test('no request carries a Referer, so no fragment can ride along in one', async ({ page, browser }) => {
    const { link, key } = await createSecret(page, CANARY);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    const sent = record(recipientPage);
    await openRevealPage(recipientPage, link, key);
    await revealSecret(recipientPage);

    for (const request of sent) {
      const referer = Object.entries(request.headers).find(([name]) => name.toLowerCase() === 'referer');
      expect(referer, `${request.url} sent ${referer?.[1]}`).toBeUndefined();
    }
    // Referrer-Policy: no-referrer applies to the document too, not only to subresources.
    expect(await recipientPage.evaluate(() => document.referrer)).toBe('');
    await recipient.close();
  });

  test('the key is gone from the address bar, the history entry and the resource timeline', async ({ page, browser }) => {
    const { link, key } = await createSecret(page, CANARY);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link, key);
    await revealSecret(recipientPage);

    const traces = await recipientPage.evaluate(() => ({
      href: location.href,
      hash: location.hash,
      // Resource timings outlive the requests themselves and are readable by any script on the page.
      resources: performance.getEntriesByType('resource').map((entry) => entry.name),
    }));

    for (const needle of keyEncodings(key)) {
      expect(traces.href).not.toContain(needle);
      expect(traces.resources.join('\n')).not.toContain(needle);
    }
    expect(traces.hash).toBe('');

    // The threat itself rather than a proxy for it: the page used replaceState, so pressing Back must not
    // land on a URL carrying the key — moot under split-channel delivery, where the original link never had
    // it, but `key` covers both: it equals the fragment in classic mode and is never in any URL either way.
    await recipientPage.goBack();
    expect(recipientPage.url()).not.toContain(key);
    await recipient.close();
  });

  test('no response on the secret path sets a cookie', async ({ page, browser }) => {
    const { link, key } = await createSecret(page, CANARY);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    const cookied: string[] = [];
    recipientPage.on('response', (response) => {
      const url = new URL(response.url());
      if (!url.pathname.startsWith('/api/whoami') && response.headers()['set-cookie'] !== undefined) {
        cookied.push(`${url.pathname}: ${response.headers()['set-cookie']}`);
      }
    });

    await openRevealPage(recipientPage, link, key);
    await revealSecret(recipientPage);

    expect(cookied).toEqual([]);
    await recipient.close();
  });
});
