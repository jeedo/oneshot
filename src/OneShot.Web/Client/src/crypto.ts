export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const MAX_CIPHERTEXT_BYTES = 64 * 1024;
export const MAX_PLAINTEXT_BYTES = MAX_CIPHERTEXT_BYTES - TAG_BYTES;

export function generateKey(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

export function generateNonce(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
}

export async function encrypt(
  plaintext: Uint8Array<ArrayBuffer>,
  rawKey: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (rawKey.length !== KEY_BYTES) {
    throw new RangeError('The key must be 32 bytes.');
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new RangeError('The nonce must be 12 bytes.');
  }
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext);
  return new Uint8Array(ciphertext);
}
