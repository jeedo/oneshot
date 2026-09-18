import { type Page, expect, test } from '@playwright/test';

import { SPLIT_KEY_PROJECT } from '../playwright.config';

// The single first-party script, pinned by both the integrity attribute and the CSP script-src hash (T7).
export const ClientBundlePath = '/js/oneshot.js';

// The suite runs under two projects, one per Features:SplitKeyDelivery setting (issue #77 follow-up). A test
// that is specifically about the key riding in the link's fragment has nothing to assert under split-channel
// delivery, since there is no fragment at all — call this first so the rest of the test never runs there.
export function requireClassicLink(reason = 'fragment-specific: there is no fragment under split-channel delivery'): void {
  test.skip(test.info().project.name === SPLIT_KEY_PROJECT, reason);
}

// The inverse: a test about split-channel delivery itself has nothing to assert when the link always carries
// the key in its fragment.
export function requireSplitKeyDelivery(reason = 'requires Features:SplitKeyDelivery to be on'): void {
  test.skip(test.info().project.name !== SPLIT_KEY_PROJECT, reason);
}

export interface ShareLink {
  link: string;
  id: string;
  // '' when the deployment withholds the key from the link (Features:SplitKeyDelivery, issue #77) — the key
  // then lives only in `key`, shown as a separate value on the create page instead of riding in the fragment.
  fragment: string;
  key: string;
}

// Drives the real create page rather than the API, so every spec exercises the browser crypto path. Works
// under either Features:SplitKeyDelivery setting: `key` is always the base64url key needed to reveal, whether
// it came from the link's own fragment or from the separate key field split-channel delivery shows instead.
export async function createSecret(page: Page, plaintext: string, ttlSeconds?: number): Promise<ShareLink> {
  await page.goto('/');
  await page.fill('#secret', plaintext);
  if (ttlSeconds !== undefined) {
    await page.selectOption('#ttl', String(ttlSeconds));
  }
  await page.click('#create');
  await expect(page.locator('#result')).toBeVisible();

  const link = await page.inputValue('#link');
  const [prefix, fragment] = link.split('#');
  const keyField = page.locator('#keyField');
  const split = (await keyField.count()) > 0 && (await keyField.isVisible());
  const key = split ? await page.inputValue('#key') : (fragment ?? '');
  return { link, id: prefix!.split('/s/')[1]!, fragment: fragment ?? '', key };
}

// Opens a reveal link and, when it carries no fragment (split-channel delivery) and a key is given, types the
// key into the manual-entry field the page prompts for instead — so the page is ready for revealSecret()
// either way. A caller that knows its link always carries a fragment (guarded by requireClassicLink) can omit
// `key` entirely, exactly as before this helper knew about split-channel delivery.
export async function openRevealPage(page: Page, link: string, key?: string): Promise<void> {
  await page.goto(link);
  await expect(page.locator('#status')).toBeVisible();
  if (!link.includes('#') && key !== undefined) {
    await expect(page.locator('#keyEntry')).toBeVisible();
    await page.fill('#manualKey', key);
  }
}

// Waits for the reveal page's initial load (whoami + peek) to settle on an available secret, regardless of
// Features:SplitKeyDelivery — the two ways that settling shows up are Reveal becoming enabled (classic) or the
// manual key prompt appearing (split-channel delivery). Neither happens if the secret was already consumed, so
// this still fails exactly when a pre-burn test needs it to.
export async function waitForRevealPageLoaded(page: Page): Promise<void> {
  await Promise.race([page.locator('#reveal:not([disabled])').waitFor(), page.locator('#keyEntry:not([hidden])').waitFor()]);
}

export async function revealSecret(page: Page): Promise<string> {
  await expect(page.locator('#reveal')).toBeEnabled();
  await page.click('#reveal');
  await expect(page.locator('#result')).toBeVisible();
  return (await page.textContent('#plaintext')) ?? '';
}
