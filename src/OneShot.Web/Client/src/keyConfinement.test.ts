import { describe, expect, it } from 'vitest';

import { createSecret, peekSecret, revealSecret, whoami } from './api';
import { decode, encode } from './base64url';
import { type CreateView, runCreate } from './createFlow';
import { encrypt, generateKey, generateNonce } from './crypto';

// createFlow.test.ts already checks the arguments handed to the api function. This sits one level lower, on
// what is actually serialised: the URL, the headers and the body that reach fetch. That is where a key would
// slip out — appended to a path, added to a header, or folded into the JSON — and the layer above cannot see it.
interface Sent {
  url: string;
  init: RequestInit | undefined;
}

function spyFetch(response: () => Response): { fetchFn: typeof fetch; sent: Sent[] } {
  const sent: Sent[] = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push({ url: String(input), init });
    return response();
  }) as typeof fetch;
  return { fetchFn, sent };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

// The client ships with no dependencies and runs in a browser, so its tests use browser APIs too: no Buffer.
function toBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return hex;
}

// Every shape the same key bytes could take on the wire.
function keyEncodings(key: Uint8Array): string[] {
  return [encode(key), btoa(toBinary(key)), toHex(key), toHex(key).toUpperCase(), Array.from(key).join(','), Array.from(key).join(' ')];
}

function flatten(sent: Sent[]): string {
  return sent
    .map((request) => {
      const headers = Object.entries((request.init?.headers ?? {}) as Record<string, string>)
        .map(([name, value]) => `${name}: ${value}`)
        .join('\n');
      return [request.url, headers, String(request.init?.body ?? '')].join('\n');
    })
    .join('\n----\n');
}

function assertConfined(sent: Sent[], key: Uint8Array, plaintext?: string): void {
  expect(sent.length, 'nothing was sent, so this would assert nothing').toBeGreaterThan(0);
  const wire = flatten(sent);

  for (const encoding of keyEncodings(key)) {
    expect(wire).not.toContain(encoding);
  }
  if (plaintext !== undefined) {
    expect(wire).not.toContain(plaintext);
  }
}

describe('[T9] the key never reaches fetch', () => {
  it('create sends the ciphertext and nonce, and no encoding of the key', async () => {
    const key = generateKey();
    const nonce = generateNonce();
    const plaintext = 'CANARY-PLAINTEXT-c1d4';
    const ciphertext = await encrypt(new TextEncoder().encode(plaintext), key, nonce);
    const { fetchFn, sent } = spyFetch(() => json(201, { id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' }));

    await createSecret(ciphertext, nonce, 3600, fetchFn);

    // The request really did carry the payload, so the sweep below is not passing over an empty body.
    expect(String(sent[0]!.init!.body)).toContain(encode(ciphertext));
    expect(String(sent[0]!.init!.body)).toContain(encode(nonce));
    assertConfined(sent, key, plaintext);
  });

  it('peek, reveal and whoami send only the id, and no encoding of the key', async () => {
    const key = generateKey();
    const nonce = generateNonce();
    const ciphertext = await encrypt(new TextEncoder().encode('x'), key, nonce);
    const id = 'abcdefghijklmnopqrstuA';

    const peek = spyFetch(() => json(200, { state: 'available', expiresAt: '2026-09-12T13:00:00Z' }));
    await peekSecret(id, peek.fetchFn);

    const reveal = spyFetch(() => json(200, { ciphertext: encode(ciphertext), nonce: encode(nonce) }));
    await revealSecret(id, reveal.fetchFn);

    const who = spyFetch(() => json(200, { windowsUser: 'CONTOSO\\alice' }));
    await whoami(who.fetchFn);

    const all = [...peek.sent, ...reveal.sent, ...who.sent];
    expect(all.map((request) => request.url)).toEqual([`/api/secrets/${id}`, `/api/secrets/${id}/reveal`, '/api/whoami']);
    assertConfined(all, key);
  });

  it('the whole create flow, driven through the real api, leaks no key to fetch', async () => {
    const plaintext = 'CANARY-FLOW-9be2';
    let link = '';
    const view: CreateView = {
      readSecret: () => plaintext,
      ttlSeconds: () => 900,
      clearSecret: () => undefined,
      showLink: (value) => {
        link = value;
      },
      showError: (code) => expect.unreachable(`create failed: ${code}`),
    };
    const { fetchFn, sent } = spyFetch(() => json(201, { id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' }));

    await runCreate(view, {
      origin: 'https://oneshot.example',
      api: (ciphertext, nonce, ttlSeconds) => createSecret(ciphertext, nonce, ttlSeconds, fetchFn),
    });

    // The key the flow actually generated, recovered from the link it produced rather than supplied by the test.
    const fragment = link.slice(link.indexOf('#') + 1);
    expect(fragment).toHaveLength(43);
    assertConfined(sent, decode(fragment), plaintext);
  });

  // Issue #77: the split-channel default (CreateDeps.splitKey, driven by Features:SplitKeyDelivery) changes
  // only what the create page displays, never what reaches the server. The key here comes back to the test via
  // showLink's own second argument rather than a link fragment.
  it('the split-channel create flow leaks no key to fetch either', async () => {
    const plaintext = 'CANARY-SPLIT-4f1a';
    let shownKey = '';
    const view: CreateView = {
      readSecret: () => plaintext,
      ttlSeconds: () => 900,
      clearSecret: () => undefined,
      showLink: (_value, key) => {
        shownKey = key ?? '';
      },
      showError: (code) => expect.unreachable(`create failed: ${code}`),
    };
    const { fetchFn, sent } = spyFetch(() => json(201, { id: 'abcdefghijklmnopqrstuA', expiresAt: '2026-09-12T13:00:00Z' }));

    await runCreate(view, {
      origin: 'https://oneshot.example',
      splitKey: true,
      api: (ciphertext, nonce, ttlSeconds) => createSecret(ciphertext, nonce, ttlSeconds, fetchFn),
    });

    expect(shownKey).toHaveLength(43);
    assertConfined(sent, decode(shownKey), plaintext);
  });

  it('the sweep catches a key that is smuggled out', async () => {
    // Without this, an encoding list that matched nothing would let every test above pass while checking nothing.
    const key = generateKey();
    const leaky: Sent[] = [{ url: `/api/secrets/abc?k=${encode(key)}`, init: { method: 'GET' } }];

    expect(() => assertConfined(leaky, key)).toThrow();
  });
});
