import { expect, test } from '@playwright/test';

import { ClientBundlePath, createSecret } from '../support/oneshot';

const PERMISSIONS_POLICY =
  'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), ' +
  'geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), ' +
  'picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), ' +
  'web-share=(), xr-spatial-tracking=()';

// The in-process matrix (ResponseHeaderMatrixTests) covers far more paths, but TestServer never writes a
// Server header of its own — so only a real Kestrel listener can show that the one the framework would
// otherwise add is actually gone.
test.describe('[T7] [T8] the real listener sends the hardening headers and nothing that names the stack', () => {
  for (const path of ['/', '/s/abcdefghijklmnopqrstuv', '/api/secrets/abcdefghijklmnopqrstuv', '/healthz', '/nowhere']) {
    test(`${path} is hardened on the wire`, async ({ request }) => {
      const response = await request.get(path);
      const headers = response.headers();

      expect(headers['x-content-type-options']).toBe('nosniff');
      expect(headers['referrer-policy']).toBe('no-referrer');
      expect(headers['x-frame-options']).toBe('DENY');
      expect(headers['permissions-policy']).toBe(PERMISSIONS_POLICY);
      expect(headers['content-security-policy']).toMatch(
        /^default-src 'none'; script-src 'sha256-[A-Za-z0-9+/]{43}='; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'$/,
      );
      // Kestrel writes Server unless told not to (task 5); nothing here may name the stack or its version.
      for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
        expect(headers[name], `${path} carried ${name}`).toBeUndefined();
      }
    });
  }
});

test.describe('[T7] the browser refuses a bundle that does not match its recorded digest', () => {
  test('the untampered bundle runs: the reveal page strips the fragment', async ({ page }) => {
    const { link } = await createSecret(page, 'sri-control');

    await page.goto(link);

    // The page script ran, so it removed the key from the address bar. This is the control for the next test.
    await expect(page.locator('#reveal')).toBeEnabled();
    expect(await page.evaluate(() => location.hash)).toBe('');
  });

  test('one appended byte is enough for the script never to run', async ({ page }) => {
    const { link, fragment } = await createSecret(page, 'sri-tampered');

    await page.route(`**${ClientBundlePath}`, async (route) => {
      const response = await route.fetch();
      await route.fulfill({ response, body: `${await response.text()}\n/* tampered */` });
    });

    const violations: string[] = [];
    page.on('console', (message) => {
      if (message.type() === 'error') {
        violations.push(message.text());
      }
    });

    await page.goto(link);

    // Nothing ran: the fragment is still in the address bar and Reveal was never wired up. The bundle is
    // pinned twice over — the integrity attribute and the CSP script-src hash — and either one is enough.
    expect(await page.evaluate(() => location.hash)).toBe(`#${fragment}`);
    await expect(page.locator('#reveal')).toBeDisabled();
    expect(violations.join('\n')).toMatch(/integrity|Content Security Policy/i);
  });
});
