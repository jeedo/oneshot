import { ApiError, type CreateSecretFn, createSecret } from './api';
import { encode } from './base64url';
import { MAX_PLAINTEXT_BYTES, encrypt, generateKey, generateNonce } from './crypto';
import { buildBareLink, buildShareLink } from './link';

export interface CreateView {
  readSecret(): string;
  ttlSeconds(): number;
  clearSecret(): void;
  showLink(link: string, key: string | null): void;
  showError(code: string): void;
}

export interface CreateDeps {
  origin: string;
  // Issue #77: a deployment-wide default (Features:SplitKeyDelivery), not a per-secret choice. When true, the
  // key is withheld from the link (buildBareLink) and shown separately (showLink's second argument) instead
  // of riding in the fragment (buildShareLink).
  splitKey?: boolean;
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
    if (deps.splitKey) {
      view.showLink(buildBareLink(deps.origin, created.id), encode(rawKey));
    } else {
      view.showLink(buildShareLink(deps.origin, created.id, rawKey), null);
    }
    view.clearSecret();
  } catch (error) {
    view.showError(error instanceof ApiError ? error.code : 'failed');
  } finally {
    plaintext.fill(0);
    rawKey.fill(0);
  }
}
