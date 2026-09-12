import { describe, expect, it, vi } from 'vitest';

import { ApiError, createSecret } from './api';

function response(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('[T1] create api client', () => {
  it('posts base64url ciphertext and nonce as same-origin JSON with no referrer and no caching', async () => {
    const fetchFn = vi.fn(async () => response(201, { id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' }));

    const created = await createSecret(new Uint8Array([251, 255, 191, 1]), new Uint8Array(12), 300, fetchFn);

    expect(created).toEqual({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/secrets');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/json');
    expect(JSON.parse(init.body as string)).toEqual({ ciphertext: '-_-_AQ', nonce: 'AAAAAAAAAAAAAAAA', ttlSeconds: 300 });
  });

  it('turns a problem response into an ApiError carrying the code', async () => {
    const fetchFn = vi.fn(async () => response(503, { status: 503, code: 'capacityExceeded' }));

    await expect(createSecret(new Uint8Array(16), new Uint8Array(12), 300, fetchFn)).rejects.toMatchObject({ status: 503, code: 'capacityExceeded' });
  });

  it('copes with a non-JSON failure body', async () => {
    const fetchFn = vi.fn(async () => new Response('gateway', { status: 502 }));

    const error = await createSecret(new Uint8Array(16), new Uint8Array(12), 300, fetchFn).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe('unknown');
  });
});
