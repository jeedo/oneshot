import { ApiError, type CreateSecretFn, createSecret } from './api';
import { MAX_PLAINTEXT_BYTES, encrypt, generateKey, generateNonce } from './crypto';
import { buildShareLink } from './link';

export interface CreateView {
  readSecret(): string;
  ttlSeconds(): number;
  clearSecret(): void;
  showLink(link: string): void;
  showError(code: string): void;
}

export interface CreateDeps {
  origin: string;
  api?: CreateSecretFn;
}

export async function runCreate(view: CreateView, deps: CreateDeps): Promise<void> {
  const text = view.readSecret();
  if (text.length === 0) {
    view.showError('empty');
    return;
  }

  const plaintext = new TextEncoder().encode(text);
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    plaintext.fill(0);
    view.showError('tooLong');
    return;
  }

  const rawKey = generateKey();
  const nonce = generateNonce();
  try {
    const ciphertext = await encrypt(plaintext, rawKey, nonce);
    const created = await (deps.api ?? createSecret)(ciphertext, nonce, view.ttlSeconds());
    view.showLink(buildShareLink(deps.origin, created.id, rawKey));
    view.clearSecret();
  } catch (error) {
    view.showError(error instanceof ApiError ? error.code : 'failed');
  } finally {
    plaintext.fill(0);
    rawKey.fill(0);
  }
}
