import { describe, expect, it, vi } from 'vitest';

import { ApiError, type CreatedSecret } from './api';
import { decode } from './base64url';
import { MAX_PLAINTEXT_BYTES } from './crypto';
import { type CreateView, runCreate } from './createFlow';

interface Call {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  ttlSeconds: number;
}

function view(secret: string, ttlSeconds = 3600) {
  const events: string[] = [];
  let current = secret;
  const v: CreateView = {
    readSecret: () => current,
    ttlSeconds: () => ttlSeconds,
    clearSecret: () => {
      current = '';
      events.push('clear');
    },
    showLink: (link) => events.push(`link:${link}`),
    showError: (code) => events.push(`error:${code}`),
  };
  return { v, events, secret: () => current };
}

function api(result: CreatedSecret | Error) {
  const calls: Call[] = [];
  const fn = vi.fn(async (ciphertext: Uint8Array, nonce: Uint8Array, ttlSeconds: number) => {
    calls.push({ ciphertext: ciphertext.slice(), nonce: nonce.slice(), ttlSeconds });
    if (result instanceof Error) {
      throw result;
    }
    return result;
  });
  return { fn, calls };
}

describe('[T1] create flow', () => {
  it('encrypts, posts only ciphertext and nonce, shows the fragment link, then clears the secret', async () => {
    const { v, events, secret } = view('my password', 900);
    const { fn, calls } = api({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });

    await runCreate(v, { origin: 'https://oneshot.example', api: fn });

    expect(calls).toHaveLength(1);
    expect(calls[0]!.ciphertext).toHaveLength(new TextEncoder().encode('my password').byteLength + 16);
    expect(calls[0]!.nonce).toHaveLength(12);
    expect(calls[0]!.ttlSeconds).toBe(900);
    expect(events).toHaveLength(2);
    expect(events[0]).toMatch(/^link:https:\/\/oneshot\.example\/s\/abcdefghijklmnopqrstuA#[A-Za-z0-9_-]{43}$/);
    expect(events[1]).toBe('clear');
    expect(secret()).toBe('');
  });

  it('never lets the key reach the request', async () => {
    const { v, events } = view('my password');
    const { fn, calls } = api({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });

    await runCreate(v, { origin: 'https://oneshot.example', api: fn });

    const fragment = events[0]!.slice(events[0]!.indexOf('#') + 1);
    const key = decode(fragment);
    const request = JSON.stringify({ c: Array.from(calls[0]!.ciphertext), n: Array.from(calls[0]!.nonce), t: calls[0]!.ttlSeconds });
    expect(request).not.toContain(fragment);
    expect(request).not.toContain(Array.from(key).join(','));
    expect(Array.from(calls[0]!.ciphertext).join(',')).not.toContain(Array.from(key).join(','));
  });

  it('rejects an empty secret without calling the api', async () => {
    const { v, events } = view('');
    const { fn } = api({ id: 'x', expiresAt: '' });

    await runCreate(v, { origin: 'https://h', api: fn });

    expect(events).toEqual(['error:empty']);
    expect(fn).not.toHaveBeenCalled();
  });

  it('rejects a secret whose bytes exceed the ciphertext limit without calling the api', async () => {
    const { v, events } = view('é'.repeat(MAX_PLAINTEXT_BYTES / 2 + 1));
    const { fn } = api({ id: 'x', expiresAt: '' });

    await runCreate(v, { origin: 'https://h', api: fn });

    expect(events).toEqual(['error:tooLong']);
    expect(fn).not.toHaveBeenCalled();
  });

  it('surfaces the api error code and keeps the secret for a retry', async () => {
    const { v, events, secret } = view('my password');
    const { fn } = api(new ApiError(503, 'capacityExceeded'));

    await runCreate(v, { origin: 'https://h', api: fn });

    expect(events).toEqual(['error:capacityExceeded']);
    expect(secret()).toBe('my password');
  });

  it('maps unexpected failures to a generic error', async () => {
    const { v, events } = view('my password');
    const { fn } = api(new TypeError('network down'));

    await runCreate(v, { origin: 'https://h', api: fn });

    expect(events).toEqual(['error:failed']);
  });
});
