import { expect, test } from '@playwright/test';

// Kestrel's MaxRequestBodySize (128 KiB, task 5) is enforced by the listener, and TestServer does not have
// one — so the in-process corpus in InputFuzzingTests reaches the decoder instead of the limit. Only a real
// listener can show what an oversized body actually gets back.
const LIMIT_BYTES = 128 * 1024;

// A relative path resolves against the current project's own baseURL (this suite runs under two, one per
// Features:SplitKeyDelivery setting, issue #77 follow-up) — this endpoint's behavior is unaffected by that
// flag either way, so the same test body runs unchanged under both.
async function post(request: import('@playwright/test').APIRequestContext, ciphertextChars: number) {
  return request.post('/api/secrets', {
    headers: { 'Content-Type': 'application/json' },
    data: JSON.stringify({ ciphertext: 'A'.repeat(ciphertextChars), nonce: 'AAAAAAAAAAAAAAAA' }),
    failOnStatusCode: false,
  });
}

test.describe('[T12] [T6] the listener refuses an oversized body without calling it our fault', () => {
  test('a body under the limit is still accepted, so the limit is what rejects the rest', async ({ request }) => {
    // 64 KiB of base64url decodes to 48 KiB of ciphertext: within both the body limit and the store's cap.
    const response = await post(request, 64 * 1024);

    expect(response.status()).toBe(201);
  });

  test('a body over the limit is 413, not 500', async ({ request }) => {
    const response = await post(request, LIMIT_BYTES + 1024);

    // Answering 500 would report a client mistake as a server fault and log a stack for every one of them.
    expect(response.status()).toBe(413);
    const problem = await response.json();
    expect(problem.code).toBe('payloadTooLarge');
    expect(response.headers()['content-type']).toContain('application/problem+json');
  });

  test('the rejection says nothing about the limit it hit', async ({ request }) => {
    const response = await post(request, LIMIT_BYTES + 1024);
    const body = await response.text();

    // Kestrel's own message names the exact byte limit; that must not reach the caller (T13).
    expect(body).not.toContain('131072');
    expect(body).not.toContain('bytes');
    expect(body).not.toMatch(/Kestrel|Exception|   at /);
  });

  test('an oversized body still carries the hardening headers', async ({ request }) => {
    const response = await post(request, LIMIT_BYTES + 1024);
    const headers = response.headers();

    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['content-security-policy']).toContain("default-src 'none'");
    expect(headers['server']).toBeUndefined();
  });

  test('repeated oversized bodies keep being refused the same way', async ({ request }) => {
    // A limit that leaks a fault on every hit is a log-flooding lever; this is the shape of that attack.
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      statuses.push((await post(request, LIMIT_BYTES + 1024)).status());
    }

    expect(statuses).toEqual([413, 413, 413, 413, 413]);
  });
});
