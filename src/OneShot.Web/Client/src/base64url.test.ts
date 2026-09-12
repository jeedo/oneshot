import { describe, expect, it } from 'vitest';

import { decode, encode } from './base64url';

describe('base64url', () => {
  it('round-trips byte arrays of every length up to 64', () => {
    for (let length = 0; length <= 64; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(decode(encode(bytes))).toEqual(bytes);
    }
  });

  it('uses the URL-safe alphabet with no padding', () => {
    expect(encode(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
    expect(encode(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
    const encoded = encode(crypto.getRandomValues(new Uint8Array(200)));
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('encodes 16 bytes to exactly 22 characters', () => {
    expect(encode(new Uint8Array(16))).toHaveLength(22);
  });

  it('decodes an empty string to an empty array', () => {
    expect(decode('')).toEqual(new Uint8Array(0));
  });

  it('rejects standard base64 characters, padding, whitespace and bad lengths', () => {
    for (const bad of ['+_8', '-/8', '-_8=', ' -_8', '-_8\n', 'A', 'AAAAA']) {
      expect(() => decode(bad)).toThrow(RangeError);
    }
  });

  it('rejects non-canonical encodings with stray trailing bits', () => {
    expect(() => decode('AR')).toThrow(RangeError);
    expect(() => decode('AAB')).toThrow(RangeError);
  });
});
