import { describe, expect, it, vi } from 'vitest';

import { ApiError, type RevealedSecret, revealSecret } from './api';
import { encode } from './base64url';
import { encrypt, generateKey, generateNonce } from './crypto';
import { type RevealView, runReveal } from './revealFlow';

const ID = 'abcdefghijklmnopqrstuA';

function harness() {
  const events: string[] = [];
  const view: RevealView = {
    stripFragment: () => events.push('strip'),
    showState: (state) => events.push(`state:${state}`),
    showError: (code) => events.push(`error:${code}`),
    enableReveal: () => events.push('enable'),
    setIdentity: () => events.push('identity'),
    disableReveal: () => events.push('disable'),
    showSecret: (plaintext) => events.push(`secret:${plaintext}`),
  };
  return { view, events };
}

async function sealedSecret(text: string) {
  const key = generateKey();
  const nonce = generateNonce();
  const ciphertext = await encrypt(new TextEncoder().encode(text), key, nonce);
  return { key, nonce, ciphertext };
}

describe('[T9] reveal action', () => {
  it('disables reveal first, then decrypts and shows the plaintext', async () => {
    const { view, events } = harness();
    const { key, nonce, ciphertext } = await sealedSecret('hunter2 — ünïcödé');
    const reveal = vi.fn(async () => ({ ciphertext, nonce }) as RevealedSecret);

    await runReveal(view, { id: ID, key, reveal });

    expect(events).toEqual(['disable', 'secret:hunter2 — ünïcödé']);
    expect(reveal).toHaveBeenCalledWith(ID);
  });

  it('zeroes the key after a successful reveal so it cannot be reused', async () => {
    const { view } = harness();
    const { key, nonce, ciphertext } = await sealedSecret('secret');

    await runReveal(view, { id: ID, key, reveal: async () => ({ ciphertext, nonce }) });

    expect(Array.from(key)).toEqual(Array.from(new Uint8Array(32)));
  });

  it('zeroes the key even when the reveal fails', async () => {
    const { view } = harness();
    const { key } = await sealedSecret('secret');

    await runReveal(view, {
      id: ID,
      key,
      reveal: () => {
        throw new ApiError(410, 'consumed');
      },
    });

    expect(Array.from(key)).toEqual(Array.from(new Uint8Array(32)));
  });

  it('reports tampered ciphertext distinctly from a transport failure', async () => {
    const { view, events } = harness();
    const { key, nonce, ciphertext } = await sealedSecret('secret');
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;

    await runReveal(view, { id: ID, key, reveal: async () => ({ ciphertext, nonce }) });

    expect(events).toEqual(['disable', 'error:tampered']);
  });

  it('reports a nonce of the wrong length as a corrupt payload', async () => {
    const { view, events } = harness();
    const { key, ciphertext } = await sealedSecret('secret');

    await runReveal(view, { id: ID, key, reveal: async () => ({ ciphertext, nonce: new Uint8Array(8) }) });

    expect(events).toEqual(['disable', 'error:tampered']);
  });

  it.each([
    [410, 'consumed'],
    [404, 'unknown'],
    [403, 'revealNotAllowed'],
    [429, 'rateLimited'],
  ])('surfaces the %i api failure as %s', async (status, code) => {
    const { view, events } = harness();
    const { key } = await sealedSecret('secret');

    await runReveal(view, {
      id: ID,
      key,
      reveal: () => {
        throw new ApiError(status, code);
      },
    });

    expect(events).toEqual(['disable', `error:${code}`]);
  });

  it('maps an unexpected failure to a generic error', async () => {
    const { view, events } = harness();
    const { key } = await sealedSecret('secret');

    await runReveal(view, {
      id: ID,
      key,
      reveal: () => {
        throw new TypeError('offline');
      },
    });

    expect(events).toEqual(['disable', 'error:failed']);
  });
});

describe('[T4] reveal api client', () => {
  it('posts with the custom header and same-origin JSON, and decodes the payload', async () => {
    const nonce = generateNonce();
    const ciphertext = await encrypt(new TextEncoder().encode('x'), generateKey(), nonce);
    const fetchFn = vi.fn(
      async () =>
        new Response(JSON.stringify({ ciphertext: encode(ciphertext), nonce: encode(nonce) }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    );

    const revealed = await revealSecret(ID, fetchFn);

    expect(revealed.ciphertext).toEqual(ciphertext);
    expect(revealed.nonce).toEqual(nonce);
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`/api/secrets/${ID}/reveal`);
    expect(init.method).toBe('POST');
    expect(new Headers(init.headers).get('X-OneShot-Reveal')).toBe('1');
    expect(new Headers(init.headers).get('Content-Type')).toBe('application/json');
    expect(init.credentials).toBe('same-origin');
    expect(init.cache).toBe('no-store');
    expect(init.referrerPolicy).toBe('no-referrer');
  });

  it('raises the typed code for a tombstone', async () => {
    const fetchFn = vi.fn(
      async () => new Response(JSON.stringify({ status: 410, code: 'consumed' }), { status: 410, headers: { 'Content-Type': 'application/json' } }),
    );

    await expect(revealSecret(ID, fetchFn)).rejects.toMatchObject({ status: 410, code: 'consumed' });
  });

  it('rejects a payload that is not valid base64url', async () => {
    const fetchFn = vi.fn(async () => new Response(JSON.stringify({ ciphertext: 'not base64!', nonce: 'x' }), { status: 200 }));

    await expect(revealSecret(ID, fetchFn)).rejects.toBeInstanceOf(ApiError);
  });
});
