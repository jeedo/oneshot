import { encode } from './base64url';

// The key lives only in the fragment, which browsers never send to any server.
export function buildShareLink(origin: string, id: string, rawKey: Uint8Array): string {
  return `${origin}/s/${id}#${encode(rawKey)}`;
}
