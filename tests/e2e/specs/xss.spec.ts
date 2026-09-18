import { type Page, expect, test } from '@playwright/test';

import { createSecret, openRevealPage, revealSecret } from '../support/oneshot';

// AES-GCM appends a 16-byte tag, so the largest plaintext that fits the store's 64 KiB ciphertext cap is
// 64 KiB minus the tag. Both sides of that boundary are exercised below.
const MAX_PLAINTEXT_BYTES = 64 * 1024 - 16;

// The invisible ones are written as backslash-u escapes, not literal characters. A file carrying literal
// control and bidi code points is treated as binary by git, so its diff never renders in review, which
// is exactly the wrong property for the file that records what this app must never execute.
const payloads: Record<string, string> = {
  'img onerror': '<img src=x onerror="window.__pwned = 1">',
  'svg onload': '<svg onload="window.__pwned = 1"></svg>',
  'javascript: link': '<a href="javascript:window.__pwned = 1">click me</a>',
  'pre breakout': '</pre><script>window.__pwned = 1</script><pre>',
  'attribute breakout': '"><script>window.__pwned = 1</script>',
  iframe: '<iframe src="javascript:parent.__pwned = 1"></iframe>',
  'details ontoggle': '<details open ontoggle="window.__pwned = 1">x</details>',
  'body onload': '<body onload="window.__pwned = 1">',
  'style import': '<style>@import "javascript:window.__pwned = 1";</style>',
  'markup already entity-encoded': '&lt;script&gt;window.__pwned = 1&lt;/script&gt; &amp; &quot;quoted&quot;',
  // Bidi overrides and zero-width joiners must survive byte for byte, not be stripped or normalised: a
  // secret is opaque data, and silently mangling it hands the reader the wrong password.
  'rtl override': 'invoice\u202Egnp.exe\u202D.pdf',
  'zero width': 'a\u200Bb\u200Cc\u200Dd\uFEFFe',
  'combining marks': 'p\u0301a\u0300s\u0302s\u0303w\u0308o\u030Ar\u0327d',
  'template syntax': '${window.__pwned = 1} {{7*7}} #{7*7}',
  'control characters': 'a\u0000b\u0007c\u001Bd\u007Fe',
};

interface Watched {
  dialogs: string[];
  violations: string[];
}

// Collect any CSP violation the page reports and any dialog a payload manages to open.
async function watch(page: Page): Promise<Watched> {
  const seen: Watched = { dialogs: [], violations: [] };

  page.on('dialog', async (dialog) => {
    seen.dialogs.push(`${dialog.type()}: ${dialog.message()}`);
    await dialog.dismiss();
  });
  await page.exposeFunction('__reportViolation', (directive: string) => void seen.violations.push(directive));
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (event) => {
      void (window as unknown as { __reportViolation(d: string): void }).__reportViolation(event.violatedDirective);
    });
  });

  return seen;
}

async function inspect(page: Page) {
  return page.evaluate(() => ({
    pwned: (window as unknown as { __pwned?: unknown }).__pwned,
    // A text node has no element children, however the payload is shaped.
    childElements: document.querySelector('#plaintext')!.childElementCount,
    // The only script on the page is the one the CSP admits by hash.
    scripts: document.querySelectorAll('script').length,
    injected: document.querySelectorAll('img, svg, iframe, a, details, style, object, embed').length,
  }));
}

test.describe('[T7] revealed secret content is text, never markup', () => {
  for (const [name, payload] of Object.entries(payloads)) {
    test(`${name} round-trips as literal text and executes nothing`, async ({ page, browser }) => {
      const { link, key } = await createSecret(page, payload);

      const recipient = await browser.newContext();
      const recipientPage = await recipient.newPage();
      const seen = await watch(recipientPage);
      await openRevealPage(recipientPage, link, key);

      const shown = await revealSecret(recipientPage);
      const dom = await inspect(recipientPage);

      // Execution is asserted before the text, so a payload that actually ran reports itself as such rather
      // than as a puzzling diff between the payload and whatever the DOM made of it.
      expect(dom.pwned).toBeUndefined();
      expect(dom.childElements).toBe(0);
      expect(dom.scripts).toBe(1);
      expect(dom.injected).toBe(0);
      expect(seen.dialogs).toEqual([]);
      expect(seen.violations).toEqual([]);
      // The exact characters come back: nothing stripped, normalised, or left HTML-escaped on screen.
      expect(shown).toBe(payload);
      await recipient.close();
    });
  }

  test('the largest plaintext the store accepts round-trips intact', async ({ page, browser }) => {
    // A repeating pattern rather than random bytes: a truncation or an off-by-one shows up in the diff.
    const payload = '<img src=x onerror=1>'.repeat(Math.ceil(MAX_PLAINTEXT_BYTES / 21)).slice(0, MAX_PLAINTEXT_BYTES);
    expect(new TextEncoder().encode(payload).length).toBe(MAX_PLAINTEXT_BYTES);

    const { link, key } = await createSecret(page, payload);

    const recipient = await browser.newContext();
    const recipientPage = await recipient.newPage();
    const seen = await watch(recipientPage);
    await openRevealPage(recipientPage, link, key);

    expect(await revealSecret(recipientPage)).toBe(payload);
    const dom = await inspect(recipientPage);
    expect(dom.injected).toBe(0);
    expect(seen.violations).toEqual([]);
    await recipient.close();
  });

  test('one byte past the cap is refused and no link is offered', async ({ page }) => {
    await page.goto('/');
    await page.fill('#secret', 'x'.repeat(MAX_PLAINTEXT_BYTES + 1));
    await page.click('#create');

    await expect(page.locator('#error')).toBeVisible();
    await expect(page.locator('#result')).toBeHidden();
  });
});

// Every test above asserts zero CSP violations. That assertion is worth nothing unless a violation would
// actually be reported, so these two prove the policy is live and the listener sees it.
test.describe('[T7] the CSP blocks script the page did not ship with', () => {
  test('an inline script appended to the reveal page never runs', async ({ page }) => {
    const { link, key } = await createSecret(page, 'csp-inline-control');
    const seen = await watch(page);
    await openRevealPage(page, link, key);

    await page.evaluate(() => {
      const script = document.createElement('script');
      script.textContent = 'window.__inline = 1;';
      document.body.appendChild(script);
    });

    expect(await page.evaluate(() => (window as unknown as { __inline?: unknown }).__inline)).toBeUndefined();
    // Chromium reports the effective directive, which for a script element is script-src-elem.
    await expect.poll(() => seen.violations.join(',')).toMatch(/^script-src/);
  });

  test('a script element pointing at another origin never loads', async ({ page }) => {
    const { link, key } = await createSecret(page, 'csp-external-control');
    const seen = await watch(page);
    await openRevealPage(page, link, key);

    await page.evaluate(async () => {
      const script = document.createElement('script');
      script.src = 'https://cdn.example.invalid/x.js';
      document.body.appendChild(script);
      await new Promise((resolve) => setTimeout(resolve, 100));
    });

    // Chromium reports the effective directive, which for a script element is script-src-elem.
    await expect.poll(() => seen.violations.join(',')).toMatch(/^script-src/);
  });
});
