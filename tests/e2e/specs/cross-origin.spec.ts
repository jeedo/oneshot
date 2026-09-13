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

    let status = 0;
    page.on('response', (response) => {
      if (response.url() === revealUrl) {
        status = response.status();
      }
    });

    // no-cors is the only cross-origin fetch that skips the preflight, and the price is that it may carry
    // neither a custom header nor a JSON content type — so it cannot look like the page's own reveal.
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

    expect(outcome.threw).toBe(false);
    // Opaque: the attacker's script sees no status, no headers, and not one byte of the body.
    expect(outcome.type).toBe('opaque');
    expect(outcome.status).toBe(0);
    expect(outcome.body).toBe('');
    // The server nonetheless saw it and said no — the opacity above is not what saved the secret.
    await expect.poll(() => status).toBe(403);
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

    const outcome = await page.evaluate(async (url) => {
      const opaque = await fetch(url, { mode: 'no-cors' });
      try {
        await fetch(url);
        return { opaqueType: opaque.type, cors: 'resolved' };
      } catch (error) {
        return { opaqueType: opaque.type, cors: `rejected ${(error as Error).name}` };
      }
    }, peekUrl);

    expect(outcome.opaqueType).toBe('opaque');
    // Without Access-Control-Allow-Origin even the harmless state field is unreadable from another origin.
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
      await fetch(url, { method: 'POST', mode: 'no-cors', body: '{}' });
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
