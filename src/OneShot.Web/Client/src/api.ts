import { decode, encode } from './base64url';

export interface CreatedSecret {
  id: string;
  expiresAt: string;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
  ) {
    super(`${status} ${code}`);
    this.name = 'ApiError';
  }
}

export type CreateSecretFn = (ciphertext: Uint8Array, nonce: Uint8Array, ttlSeconds: number) => Promise<CreatedSecret>;

export type SecretState = 'available' | 'consumed' | 'unknown';

export interface SecretPeek {
  state: SecretState;
  expiresAt: string | null;
}

export type PeekSecretFn = (id: string) => Promise<SecretPeek>;

export type WhoAmIFn = () => Promise<string | null>;

export interface RevealedSecret {
  ciphertext: Uint8Array<ArrayBuffer>;
  nonce: Uint8Array<ArrayBuffer>;
}

export type RevealSecretFn = (id: string) => Promise<RevealedSecret>;

// The only call that consumes a secret; the custom header is what no form or prefetch can send.
export async function revealSecret(id: string, fetchFn: typeof fetch = fetch): Promise<RevealedSecret> {
  const response = await fetchFn(`/api/secrets/${id}/reveal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-OneShot-Reveal': '1' },
    body: '{}',
    credentials: 'same-origin',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 200) {
    throw new ApiError(response.status, await problemCode(response));
  }

  const body = (await response.json().catch(() => ({}))) as { ciphertext?: unknown; nonce?: unknown };
  if (typeof body.ciphertext !== 'string' || typeof body.nonce !== 'string') {
    throw new ApiError(response.status, 'malformedPayload');
  }

  try {
    return { ciphertext: decode(body.ciphertext), nonce: decode(body.nonce) };
  } catch {
    throw new ApiError(response.status, 'malformedPayload');
  }
}

const WHOAMI_TIMEOUT_MS = 2000;

// A plain GET with no custom header: it can never consume a secret.
export async function peekSecret(id: string, fetchFn: typeof fetch = fetch): Promise<SecretPeek> {
  const response = await fetchFn(`/api/secrets/${id}`, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 200 && response.status !== 404) {
    throw new ApiError(response.status, await problemCode(response));
  }

  const peek = (await response.json().catch(() => ({}))) as { state?: unknown; expiresAt?: unknown };
  if (peek.state !== 'available' && peek.state !== 'consumed' && peek.state !== 'unknown') {
    throw new ApiError(response.status, 'unknown');
  }
  return { state: peek.state, expiresAt: typeof peek.expiresAt === 'string' ? peek.expiresAt : null };
}

// Best effort: any failure, challenge, or timeout simply means anonymous.
export async function whoami(fetchFn: typeof fetch = fetch): Promise<string | null> {
  try {
    const response = await fetchFn('/api/whoami', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(WHOAMI_TIMEOUT_MS),
    });
    if (response.status !== 200) {
      return null;
    }
    const body = (await response.json()) as { windowsUser?: unknown };
    return typeof body.windowsUser === 'string' && body.windowsUser.length > 0 ? body.windowsUser : null;
  } catch {
    return null;
  }
}

export async function createSecret(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  ttlSeconds: number,
  fetchFn: typeof fetch = fetch,
): Promise<CreatedSecret> {
  const response = await fetchFn('/api/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ciphertext: encode(ciphertext), nonce: encode(nonce), ttlSeconds }),
    credentials: 'same-origin',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  if (response.status !== 201) {
    throw new ApiError(response.status, await problemCode(response));
  }
  return (await response.json()) as CreatedSecret;
}

async function problemCode(response: Response): Promise<string> {
  try {
    const problem = (await response.json()) as { code?: unknown };
    return typeof problem.code === 'string' ? problem.code : 'unknown';
  } catch {
    return 'unknown';
  }
}
