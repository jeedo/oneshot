import { ApiError, type PeekSecretFn, type SecretState, type WhoAmIFn } from './api';
import { decode } from './base64url';
import { KEY_BYTES } from './crypto';

const ID_BYTES = 16;

export interface RevealView {
  stripFragment(): void;
  showState(state: SecretState, expiresAt: string | null): void;
  showError(code: string): void;
  enableReveal(key: Uint8Array): void;
  setIdentity(user: string | null): void;
}

export interface RevealDeps {
  id: string;
  fragment: string;
  peek: PeekSecretFn;
  whoami: WhoAmIFn;
}

// The fragment is validated and dropped from the address bar before anything touches the network, so a bad
// link never reaches the server and the key never survives in browser history (T8).
export async function runRevealLoad(view: RevealView, deps: RevealDeps): Promise<void> {
  const key = decodeExactly(deps.fragment, KEY_BYTES);
  view.stripFragment();

  if (!key) {
    view.showError('invalidKey');
    return;
  }

  if (!decodeExactly(deps.id, ID_BYTES)) {
    view.showError('invalidLink');
    return;
  }

  view.setIdentity(await deps.whoami());

  try {
    const peek = await deps.peek(deps.id);
    view.showState(peek.state, peek.expiresAt);
    if (peek.state === 'available') {
      view.enableReveal(key);
    }
  } catch (error) {
    view.showError(error instanceof ApiError ? error.code : 'failed');
  }
}

function decodeExactly(text: string, length: number): Uint8Array | null {
  try {
    const bytes = decode(text);
    return bytes.length === length ? bytes : null;
  } catch {
    return null;
  }
}
