import { describe, expect, it } from 'vitest';

import { decode } from './base64url';
import { generateKey } from './crypto';
import { buildShareLink } from './link';

describe('[T1] share link', () => {
  it('puts the id in the path and the key only in the fragment', () => {
    const rawKey = generateKey();

    const link = buildShareLink('https://oneshot.example', 'abcdefghijklmnopqrstuA', rawKey);
    const url = new URL(link);

    expect(url.origin).toBe('https://oneshot.example');
    expect(url.pathname).toBe('/s/abcdefghijklmnopqrstuA');
    expect(url.search).toBe('');
    expect(decode(url.hash.slice(1))).toEqual(rawKey);
    expect(link).toBe(`https://oneshot.example/s/abcdefghijklmnopqrstuA#${url.hash.slice(1)}`);
  });

  it('encodes the key without padding or URL-hostile characters', () => {
    const link = buildShareLink('https://h', 'abcdefghijklmnopqrstuA', new Uint8Array(32).fill(0xff));

    expect(link.endsWith('#' + '_'.repeat(42) + '8')).toBe(true);
  });
});
