import { describe, expect, it } from 'vitest';

import { decrypt, encrypt, generateKey, generateNonce } from './crypto';

const plaintext = new TextEncoder().encode('correct horse battery staple');

async function sealed() {
  const rawKey = generateKey();
  const nonce = generateNonce();
  return { rawKey, nonce, ciphertext: await encrypt(plaintext, rawKey, nonce) };
}

// Every bit, not just the lowest one of each byte: a check that only ever flips bit 0 would miss an
// implementation that authenticated part of each byte.
function flip(bytes: Uint8Array<ArrayBuffer>, index: number, bit = 0): Uint8Array<ArrayBuffer> {
  const copy = bytes.slice();
  copy[index] = (copy[index] ?? 0) ^ (1 << bit);
  return copy;
}

describe('[T9] client decryption', () => {
  it('round-trips what encrypt produced', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();

    expect(new TextDecoder().decode(await decrypt(ciphertext, rawKey, nonce))).toBe('correct horse battery staple');
  });

  it('fails closed for the wrong key', async () => {
    const { nonce, ciphertext } = await sealed();

    await expect(decrypt(ciphertext, generateKey(), nonce)).rejects.toBeInstanceOf(Error);
  });

  it('fails closed for every single-bit flip anywhere in the ciphertext or its tag', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();
    let attempts = 0;

    for (let i = 0; i < ciphertext.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        await expect(decrypt(flip(ciphertext, i, bit), rawKey, nonce)).rejects.toBeInstanceOf(Error);
        attempts++;
      }
    }

    // The message is 28 bytes and the tag 16, so every bit of both was tried.
    expect(attempts).toBe((28 + 16) * 8);
  });

  it('fails closed for every single-bit flip in the nonce', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();
    let attempts = 0;

    for (let i = 0; i < nonce.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        await expect(decrypt(ciphertext, rawKey, flip(nonce, i, bit))).rejects.toBeInstanceOf(Error);
        attempts++;
      }
    }

    expect(attempts).toBe(12 * 8);
  });

  it('reports authentication failure as an OperationError, not a generic fault', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();

    const error = await decrypt(flip(ciphertext, 0), rawKey, nonce).catch((e: unknown) => e);

    expect((error as DOMException).name).toBe('OperationError');
  });

  it('refuses keys and nonces of the wrong length', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();

    await expect(decrypt(ciphertext, new Uint8Array(16), nonce)).rejects.toBeInstanceOf(RangeError);
    await expect(decrypt(ciphertext, rawKey, new Uint8Array(16))).rejects.toBeInstanceOf(RangeError);
  });
});
