import { describe, expect, it } from 'vitest';

import { decrypt, encrypt, generateKey, generateNonce } from './crypto';

const plaintext = new TextEncoder().encode('correct horse battery staple');

async function sealed() {
  const rawKey = generateKey();
  const nonce = generateNonce();
  return { rawKey, nonce, ciphertext: await encrypt(plaintext, rawKey, nonce) };
}

function flip(bytes: Uint8Array<ArrayBuffer>, index: number): Uint8Array<ArrayBuffer> {
  const copy = bytes.slice();
  copy[index] = (copy[index] ?? 0) ^ 1;
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

  it('fails closed for a single flipped bit anywhere in the ciphertext or its tag', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();

    for (let i = 0; i < ciphertext.length; i++) {
      await expect(decrypt(flip(ciphertext, i), rawKey, nonce)).rejects.toBeInstanceOf(Error);
    }
  });

  it('fails closed for a single flipped bit in the nonce', async () => {
    const { rawKey, nonce, ciphertext } = await sealed();

    for (let i = 0; i < nonce.length; i++) {
      await expect(decrypt(ciphertext, rawKey, flip(nonce, i))).rejects.toBeInstanceOf(Error);
    }
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
