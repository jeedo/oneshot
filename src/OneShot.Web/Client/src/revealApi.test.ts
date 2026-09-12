import { describe, expect, it, vi } from 'vitest';

import { ApiError, peekSecret, whoami } from './api';

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('[T4] peek api client', () => {
  it('reads the state with a plain uncached same-origin GET', async () => {
    const fetchFn = vi.fn(async () => json(200, { state: 'available', expiresAt: '2026-09-12T13:00:00Z' }));

    const peek = await peekSecret('abcdefghijklmnopqrstuA', fetchFn);

    expect(peek).toEqual({ state: 'available', expiresAt: '2026-09-12T13:00:00Z' });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/secrets/abcdefghijklmnopqrstuA');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.cache).toBe('no-store');
    expect(init.credentials).toBe('same-origin');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(init.body).toBeUndefined();
    expect(new Headers(init.headers).get('X-OneShot-Reveal')).toBeNull();
  });

  it('treats a 404 as the unknown state rather than an error', async () => {
    const fetchFn = vi.fn(async () => json(404, { state: 'unknown', expiresAt: null }));

    await expect(peekSecret('abcdefghijklmnopqrstuA', fetchFn)).resolves.toEqual({ state: 'unknown', expiresAt: null });
  });

  it('raises an ApiError for any other status', async () => {
    const fetchFn = vi.fn(async () => json(429, { status: 429, code: 'rateLimited' }));

    await expect(peekSecret('abcdefghijklmnopqrstuA', fetchFn)).rejects.toMatchObject({ status: 429, code: 'rateLimited' });
  });

  it('rejects an unrecognised state', async () => {
    const fetchFn = vi.fn(async () => json(200, { state: 'weird', expiresAt: null }));

    await expect(peekSecret('abcdefghijklmnopqrstuA', fetchFn)).rejects.toBeInstanceOf(ApiError);
  });
});

describe('[T10] whoami api client', () => {
  it('returns the account name and sends credentials with a bounded timeout', async () => {
    const fetchFn = vi.fn(async () => json(200, { windowsUser: 'CORP\\alice' }));

    const user = await whoami(fetchFn);

    expect(user).toBe('CORP\\alice');
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/whoami');
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('treats a 401 challenge as anonymous', async () => {
    const fetchFn = vi.fn(async () => new Response('', { status: 401, headers: { 'WWW-Authenticate': 'Negotiate' } }));

    await expect(whoami(fetchFn)).resolves.toBeNull();
  });

  it('treats a timeout or network failure as anonymous', async () => {
    const aborted = vi.fn(async () => {
      throw new DOMException('The operation was aborted.', 'TimeoutError');
    });

    await expect(whoami(aborted)).resolves.toBeNull();
  });

  it('treats a malformed body as anonymous', async () => {
    const fetchFn = vi.fn(async () => new Response('not json', { status: 200 }));

    await expect(whoami(fetchFn)).resolves.toBeNull();
  });
});
