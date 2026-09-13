import { type Page, expect } from '@playwright/test';

// The single first-party script, pinned by both the integrity attribute and the CSP script-src hash (T7).
export const ClientBundlePath = '/js/oneshot.js';

export interface ShareLink {
  link: string;
  id: string;
  fragment: string;
}

// Drives the real create page rather than the API, so every spec exercises the browser crypto path.
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
  return { link, id: prefix!.split('/s/')[1]!, fragment: fragment ?? '' };
}

export async function openRevealPage(page: Page, link: string): Promise<void> {
  await page.goto(link);
  await expect(page.locator('#status')).toBeVisible();
}

export async function revealSecret(page: Page): Promise<string> {
  await expect(page.locator('#reveal')).toBeEnabled();
  await page.click('#reveal');
  await expect(page.locator('#result')).toBeVisible();
  return (await page.textContent('#plaintext')) ?? '';
}
