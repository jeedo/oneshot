import { encode } from './base64url';

// The key lives only in the fragment, which browsers never send to any server.
export function buildShareLink(origin: string, id: string, rawKey: Uint8Array): string {
  return `${origin}/s/${id}#${encode(rawKey)}`;
}

// Issue #77: withholds the key from the link entirely (no fragment, not an empty one) so it can be delivered
// over a second channel. The reveal page tells this apart from a malformed fragment by the fragment's absence.
export function buildBareLink(origin: string, id: string): string {
  return `${origin}/s/${id}`;
}
