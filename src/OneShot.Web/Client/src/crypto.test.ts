import { describe, expect, it } from 'vitest';

import { KEY_BYTES, MAX_PLAINTEXT_BYTES, NONCE_BYTES, TAG_BYTES, encrypt, generateKey, generateNonce } from './crypto';

async function subtleDecrypt(ciphertext: Uint8Array<ArrayBuffer>, rawKey: Uint8Array<ArrayBuffer>, nonce: Uint8Array<ArrayBuffer>): Promise<string> {
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext));
}

describe('[T9] client crypto', () => {
  it('generates 32-byte keys and 12-byte nonces from the CSPRNG', () => {
    expect(KEY_BYTES).toBe(32);
    expect(NONCE_BYTES).toBe(12);
    expect(generateKey()).toHaveLength(32);
    expect(generateNonce()).toHaveLength(12);
  });

  it('never repeats a key or a nonce', () => {
    const keys = new Set<string>();
    const nonces = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      keys.add(generateKey().join(','));
      nonces.add(generateNonce().join(','));
    }
    expect(keys.size).toBe(1000);
    expect(nonces.size).toBe(1000);
  });

  it('encrypts with AES-256-GCM so Web Crypto can decrypt it, appending the 16-byte tag', async () => {
    const rawKey = generateKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('hunter2 — ünïcödé ✓');

    const ciphertext = await encrypt(plaintext, rawKey, nonce);

    expect(TAG_BYTES).toBe(16);
    expect(ciphertext).toHaveLength(plaintext.byteLength + 16);
    expect(await subtleDecrypt(ciphertext, rawKey, nonce)).toBe('hunter2 — ünïcödé ✓');
  });

  it('produces different ciphertext for the same plaintext under fresh keys and nonces', async () => {
    const plaintext = new TextEncoder().encode('same secret');

    const first = await encrypt(plaintext, generateKey(), generateNonce());
    const second = await encrypt(plaintext, generateKey(), generateNonce());

    expect(first).not.toEqual(second);
  });

  it('refuses keys and nonces of the wrong length', async () => {
    const plaintext = new TextEncoder().encode('x');

    await expect(encrypt(plaintext, new Uint8Array(16), generateNonce())).rejects.toThrow(RangeError);
    await expect(encrypt(plaintext, generateKey(), new Uint8Array(16))).rejects.toThrow(RangeError);
  });

  it('bounds the plaintext so the ciphertext fits the server limit', () => {
    expect(MAX_PLAINTEXT_BYTES).toBe(64 * 1024 - 16);
  });
});
