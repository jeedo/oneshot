import { encode } from './base64url';

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
