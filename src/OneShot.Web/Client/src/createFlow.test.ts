import { describe, expect, it, vi } from 'vitest';

import { ApiError, type CreatedSecret } from './api';
import { decode } from './base64url';
import { MAX_PLAINTEXT_BYTES, decrypt } from './crypto';
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
    showLink: (link, key) => events.push(`link:${link}|${key ?? ''}`),
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
    expect(events[0]).toMatch(/^link:https:\/\/oneshot\.example\/s\/abcdefghijklmnopqrstuA#[A-Za-z0-9_-]{43}\|$/);
    expect(events[1]).toBe('clear');
    expect(secret()).toBe('');
  });

  it('never lets the key reach the request', async () => {
    const { v, events } = view('my password');
    const { fn, calls } = api({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });

    await runCreate(v, { origin: 'https://oneshot.example', api: fn });

    const link = events[0]!.slice('link:'.length, events[0]!.indexOf('|'));
    const fragment = link.slice(link.indexOf('#') + 1);
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

// Issue #77: a deployment-wide default (Features:SplitKeyDelivery) that withholds the key from the link for
// split-channel delivery. Nothing about the server request changes — only what the create page is handed to
// display, driven by CreateDeps.splitKey rather than a per-secret choice.
describe('[T1] create flow — split-channel key', () => {
  it('shows a bare link and the raw key separately, and the key still decrypts the ciphertext that was sent', async () => {
    const { v, events, secret } = view('my password', 900);
    const { fn, calls } = api({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });

    await runCreate(v, { origin: 'https://oneshot.example', splitKey: true, api: fn });

    expect(events).toHaveLength(2);
    const [, link, key] = events[0]!.match(/^link:(.*)\|(.*)$/) ?? [];
    expect(link).toBe('https://oneshot.example/s/abcdefghijklmnopqrstuA');
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const rawKey = decode(key!);
    const plaintext = await decrypt(calls[0]!.ciphertext as Uint8Array<ArrayBuffer>, rawKey, calls[0]!.nonce as Uint8Array<ArrayBuffer>);
    expect(new TextDecoder().decode(plaintext)).toBe('my password');
    expect(events[1]).toBe('clear');
    expect(secret()).toBe('');
  });

  it('never posts the key, split or not', async () => {
    const { v, events } = view('my password', 3600);
    const { fn, calls } = api({ id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' });

    await runCreate(v, { origin: 'https://oneshot.example', splitKey: true, api: fn });

    const key = events[0]!.slice(events[0]!.lastIndexOf('|') + 1);
    const request = JSON.stringify({ c: Array.from(calls[0]!.ciphertext), n: Array.from(calls[0]!.nonce) });
    expect(request).not.toContain(key);
  });
});
