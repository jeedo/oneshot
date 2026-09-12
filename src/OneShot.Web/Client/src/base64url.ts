const VALID = /^[A-Za-z0-9_-]*$/;

export function encode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decode(text: string): Uint8Array<ArrayBuffer> {
  if (!VALID.test(text) || text.length % 4 === 1) {
    throw new RangeError('Invalid base64url input.');
  }
  const base64 = text.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  if (encode(bytes) !== text) {
    throw new RangeError('Invalid base64url input.');
  }
  return bytes;
}
