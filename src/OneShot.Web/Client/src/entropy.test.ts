import { describe, expect, it } from 'vitest';

import { KEY_BYTES, NONCE_BYTES, generateKey, generateNonce } from './crypto';

const SAMPLES = 100_000;

// Chi-squared over 256 buckets has 255 degrees of freedom: mean 255, standard deviation sqrt(2 * 255) ~= 22.6.
// 500 is more than ten standard deviations out, so a healthy generator effectively never trips it, while a
// generator that is constant, low-entropy, or biased in even one byte position is far beyond it.
const CHI_SQUARED_LIMIT = 500;

// The client ships with no dependencies and runs in a browser, so its tests use browser APIs too: no Buffer.
function toBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

interface Sampled {
  unique: number;
  lengths: Set<number>;
  // counts[position][value] — a per-position histogram, because a generator that randomised only some of the
  // bytes would still produce unique outputs and pass a uniqueness check alone.
  counts: Uint32Array[];
}

function sample(generate: () => Uint8Array, size: number, count: number): Sampled {
  const seen = new Set<string>();
  const lengths = new Set<number>();
  const counts = Array.from({ length: size }, () => new Uint32Array(256));

  for (let i = 0; i < count; i++) {
    const bytes = generate();
    lengths.add(bytes.length);
    seen.add(toBinary(bytes));
    for (let position = 0; position < bytes.length && position < size; position++) {
      const histogram = counts[position]!;
      const value = bytes[position]!;
      histogram[value] = (histogram[value] ?? 0) + 1;
    }
  }

  return { unique: seen.size, lengths, counts };
}

function chiSquared(observed: Uint32Array, total: number): number {
  const expected = total / observed.length;
  let sum = 0;
  for (const value of observed) {
    sum += ((value - expected) * (value - expected)) / expected;
  }
  return sum;
}

describe('[T9] key and nonce entropy', () => {
  it(`generates ${SAMPLES.toLocaleString('en-GB')} nonces that are all 12 bytes, all distinct, and uniform in every byte`, () => {
    const { unique, lengths, counts } = sample(generateNonce, NONCE_BYTES, SAMPLES);

    expect([...lengths]).toEqual([NONCE_BYTES]);
    // GCM's whole security argument is that a nonce is never reused under one key. Here each nonce also has a
    // fresh key, but a generator that repeated at this scale would be broken however it is used.
    expect(unique).toBe(SAMPLES);
    for (let position = 0; position < NONCE_BYTES; position++) {
      expect(chiSquared(counts[position]!, SAMPLES), `nonce byte ${position} is not uniform`).toBeLessThan(CHI_SQUARED_LIMIT);
    }
  });

  it(`generates ${SAMPLES.toLocaleString('en-GB')} keys that are all 32 bytes, all distinct, and uniform in every byte`, () => {
    const { unique, lengths, counts } = sample(generateKey, KEY_BYTES, SAMPLES);

    expect([...lengths]).toEqual([KEY_BYTES]);
    expect(unique).toBe(SAMPLES);
    for (let position = 0; position < KEY_BYTES; position++) {
      expect(chiSquared(counts[position]!, SAMPLES), `key byte ${position} is not uniform`).toBeLessThan(CHI_SQUARED_LIMIT);
    }
  });

  it('the uniformity check rejects a generator that is constant in one byte', () => {
    // Without this, a chi-squared that never fires would let the two tests above pass while proving nothing.
    const biased = (): Uint8Array => {
      const bytes = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
      bytes[4] = 0x2a;
      return bytes;
    };

    const { counts } = sample(biased, NONCE_BYTES, 10_000);

    expect(chiSquared(counts[3]!, 10_000)).toBeLessThan(CHI_SQUARED_LIMIT);
    expect(chiSquared(counts[4]!, 10_000)).toBeGreaterThan(CHI_SQUARED_LIMIT);
  });
});
