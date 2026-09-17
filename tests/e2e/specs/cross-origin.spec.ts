import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';

import { type Page, expect, test } from '@playwright/test';

import { ATTACKER_HOST, baseURL } from '../playwright.config';
import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

// The attacker page has to be served for real: Chromium's Local Network Access refuses to let a page outside
// the loopback address space touch 127.0.0.1 at all, and a request the browser kills on its own doorstep
// proves nothing about this app. Served from loopback under a name that is a different site, every request
// below actually reaches the server and is refused there.
let server: Server;
let attackerOrigin = '';
let attackerHtml = '';

test.beforeAll(async () => {
  server = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    response.end(`<!doctype html><meta charset="utf-8"><title>attacker</title>${attackerHtml}`);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  attackerOrigin = `http://${ATTACKER_HOST}:${(server.address() as AddressInfo).port}`;
});

test.afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function openAttackerPage(page: Page, body: string): Promise<void> {
  attackerHtml = body;
  await page.goto(`${attackerOrigin}/csrf.html`);
  // If this ever became the app's own origin the whole file would be testing nothing.
  expect(new URL(page.url()).origin).toBe(attackerOrigin);
  expect(new URL(page.url()).origin).not.toBe(baseURL);
}

async function peekState(page: Page, id: string): Promise<string> {
  const response = await page.request.get(`${baseURL}/api/secrets/${id}`);
  return (await response.json()).state;
}

test.describe('[T4] a foreign origin cannot reach the consume path', () => {
  test('a cross-site form submission is refused for every enctype a form can produce', async ({ page }) => {
    const { id } = await createSecret(page, 'csrf-form-target');
    const revealUrl = `${baseURL}/api/secrets/${id}/reveal`;
    // These three are the whole of what an HTML form can send. None is application/json, and a form can set
    // no custom header, so none of them can satisfy the reveal policy however it is aimed.
    const enctypes = ['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];

    await openAttackerPage(
      page,
      enctypes
        .map(
          (enctype, i) => `
        <iframe name="sink${i}" style="display:none"></iframe>
        <form id="f${i}" method="POST" action="${revealUrl}" enctype="${enctype}" target="sink${i}">
          <input name="ciphertext" value="x" />
        </form>`,
        )
        .join(''),
    );

    const statuses: number[] = [];
    page.on('response', (response) => {
      if (response.url() === revealUrl) {
        statuses.push(response.status());
      }
    });

    await page.evaluate((count) => {
      for (let i = 0; i < count; i++) {
        (document.getElementById(`f${i}`) as HTMLFormElement).submit();
      }
    }, enctypes.length);

    // The submissions really are sent and really do reach the app: it refuses them, the browser does not.
    await expect.poll(() => statuses.length).toBe(enctypes.length);
    expect(statuses).toEqual(enctypes.map(() => 403));
    expect(await peekState(page, id)).toBe('available');
  });

  test('a no-cors fetch reaches the app, is refused, and tells the attacker nothing', async ({ page }) => {
    const { id } = await createSecret(page, 'no-cors-target');
    const revealUrl = `${baseURL}/api/secrets/${id}/reveal`;
    await openAttackerPage(page, '');

    let failure = '';
    page.on('requestfailed', (request) => {
      if (request.url() === revealUrl) {
        failure = request.failure()?.errorText ?? '';
      }
    });

    // no-cors is the only cross-origin fetch that skips the preflight, and the price is that it may carry
    // neither a custom header nor a JSON content type — so it cannot look like the page's own reveal.
    // Cross-Origin-Resource-Policy: same-origin (T8, issue #50) means the browser no longer even hands the
    // attacker's script an opaque response for this: NotSameOrigin below is Chromium naming the specific
    // reason it discarded a response the server did send — a strictly stronger, more specific signal than
    // the plain no-cors opacity this test used to rely on.
    const outcome = await page.evaluate(async (url) => {
      try {
        const response = await fetch(url, {
          method: 'POST',
          mode: 'no-cors',
          headers: { 'Content-Type': 'text/plain' },
          body: '{}',
        });
        return { threw: false, type: response.type, status: response.status, body: await response.text() };
      } catch (error) {
        return { threw: true, message: String(error) };
      }
    }, revealUrl);

    expect(outcome.threw).toBe(true);
    expect(outcome.message).toContain('Failed to fetch');
    await expect.poll(() => failure).toBe('net::ERR_BLOCKED_BY_RESPONSE.NotSameOrigin');
    expect(await peekState(page, id)).toBe('available');
  });

  test('a cors fetch carrying the reveal header dies at the preflight and never sends the POST', async ({ page }) => {
    const { id } = await createSecret(page, 'preflight-target');
    const revealUrl = `${baseURL}/api/secrets/${id}/reveal`;
    await openAttackerPage(page, '');

    const answered: number[] = [];
    const failed: string[] = [];
    page.on('response', (response) => {
      if (response.url() === revealUrl) {
        answered.push(response.status());
      }
    });
    page.on('requestfailed', (request) => {
      if (request.url() === revealUrl) {
        failed.push(request.failure()?.errorText ?? '');
      }
    });

    const outcome = await page.evaluate(async (url) => {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-OneShot-Reveal': '1' },
          body: '{}',
        });
        return `resolved ${response.status}`;
      } catch (error) {
        return `rejected ${(error as Error).name}`;
      }
    }, revealUrl);

    // The custom header and JSON body force a preflight; with no Access-Control-Allow-* in the answer the
    // browser abandons the request, so the one shape that would satisfy the reveal policy never leaves a
    // foreign origin. Contrast the no-cors case above, which does get answered — with a 403.
    expect(outcome).toBe('rejected TypeError');
    await expect.poll(() => failed).toEqual(['net::ERR_FAILED']);
    expect(answered).toEqual([]);
    expect(await peekState(page, id)).toBe('available');
  });

  test('cross-origin GETs of the peek endpoint burn nothing and leak nothing', async ({ page }) => {
    const { id } = await createSecret(page, 'cross-origin-get-target');
    const peekUrl = `${baseURL}/api/secrets/${id}`;
    await openAttackerPage(page, `<img src="${peekUrl}" alt="" /><script src="${peekUrl}"></script>`);

    // Cross-Origin-Resource-Policy: same-origin (T8, issue #50) blocks both now: a plain no-cors fetch used
    // to resolve opaquely (the body hidden but the promise still fulfilled), and it no longer does either —
    // and the CORS fetch below was already unreadable with no Access-Control-Allow-Origin in the response.
    const outcome = await page.evaluate(async (url) => {
      const attempt = async (init?: RequestInit) => {
        try {
          await fetch(url, init);
          return 'resolved';
        } catch (error) {
          return `rejected ${(error as Error).name}`;
        }
      };
      return { noCors: await attempt({ mode: 'no-cors' }), cors: await attempt() };
    }, peekUrl);

    expect(outcome.noCors).toBe('rejected TypeError');
    expect(outcome.cors).toBe('rejected TypeError');
    expect(await peekState(page, id)).toBe('available');
  });

  test('after every cross-origin attempt the real recipient still reveals the secret', async ({ page, browser }) => {
    const plaintext = 'survives-csrf — ünïcödé';
    const { link, id } = await createSecret(page, plaintext);
    const revealUrl = `${baseURL}/api/secrets/${id}/reveal`;
    await openAttackerPage(
      page,
      `<iframe name="sink" style="display:none"></iframe>
       <form id="f" method="POST" action="${revealUrl}" enctype="text/plain" target="sink"></form>`,
    );

    await page.evaluate(async (url) => {
      (document.getElementById('f') as HTMLFormElement).submit();
      // Cross-Origin-Resource-Policy (issue #50) makes this reject now instead of resolving opaquely — this
      // attempt is a no-op either way, which is all this test cares about.
      await fetch(url, { method: 'POST', mode: 'no-cors', body: '{}' }).catch(() => {});
    }, revealUrl);
    await expect.poll(() => peekState(page, id)).toBe('available');

    // The attacks were no-ops, not near-misses on something already spent: the secret is still whole.
    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    await openRevealPage(recipientPage, link);
    expect(await revealSecret(recipientPage)).toBe(plaintext);
    await recipient.close();
  });
});
