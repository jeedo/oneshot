import { ApiError, type PeekSecretFn, type RevealSecretFn, type SecretState, type WhoAmIFn } from './api';
import { decode } from './base64url';
import { KEY_BYTES, decrypt } from './crypto';

const ID_BYTES = 16;

export interface RevealView {
  stripFragment(): void;
  showState(state: SecretState, expiresAt: string | null): void;
  showError(code: string): void;
  enableReveal(key: Uint8Array): void;
  // Issue #77: called instead of enableReveal when the link carries no fragment at all (the sender withheld
  // the key on purpose) and the secret is still available — the view shows a manual key-entry field.
  promptForKey(): void;
  setIdentity(user: string | null): void;
  disableReveal(): void;
  showSecret(plaintext: string): void;
}

export interface RevealActionDeps {
  id: string;
  key: Uint8Array<ArrayBuffer>;
  reveal: RevealSecretFn;
}

export interface RevealDeps {
  id: string;
  fragment: string;
  peek: PeekSecretFn;
  whoami: WhoAmIFn;
}

// The fragment is validated and dropped from the address bar before anything touches the network, so a bad
// link never reaches the server and the key never survives in browser history (T8).
//
// Issue #77: an empty fragment means no key was ever attached to the link (a split-channel share, on purpose)
// and is not the same failure as a fragment that is present but malformed — that keeps today's invalidKey
// error exactly as before. An empty fragment instead proceeds like a normal load and, only once the secret is
// confirmed available, prompts for the key to be entered separately rather than enabling Reveal outright.
export async function runRevealLoad(view: RevealView, deps: RevealDeps): Promise<void> {
  const hasFragment = deps.fragment.length > 0;
  const key = hasFragment ? decodeExactly(deps.fragment, KEY_BYTES) : null;
  view.stripFragment();

  if (hasFragment && !key) {
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
      if (key) {
        view.enableReveal(key);
      } else {
        view.promptForKey();
      }
    }
  } catch (error) {
    view.showError(error instanceof ApiError ? error.code : 'failed');
  }
}

// Reveal is disabled before the request so a double click cannot consume twice, and the key is zeroed
// whatever happens: it is single-use and must not survive the click that spent it.
export async function runReveal(view: RevealView, deps: RevealActionDeps): Promise<void> {
  view.disableReveal();

  let plaintext: Uint8Array<ArrayBuffer> | null = null;
  try {
    const payload = await deps.reveal(deps.id);
    plaintext = await decrypt(payload.ciphertext, deps.key, payload.nonce);
    payload.ciphertext.fill(0);
    payload.nonce.fill(0);
    view.showSecret(new TextDecoder().decode(plaintext));
  } catch (error) {
    view.showError(revealErrorCode(error));
  } finally {
    deps.key.fill(0);
    plaintext?.fill(0);
  }
}

function revealErrorCode(error: unknown): string {
  if (error instanceof ApiError) {
    return error.code;
  }
  // GCM authentication failure surfaces as OperationError; a bad nonce length as RangeError. Both mean the
  // payload cannot be trusted rather than that the transport failed.
  if ((error instanceof DOMException && error.name === 'OperationError') || error instanceof RangeError) {
    return 'tampered';
  }
  return 'failed';
}

function decodeExactly(text: string, length: number): Uint8Array | null {
  try {
    const bytes = decode(text);
    return bytes.length === length ? bytes : null;
  } catch {
    return null;
  }
}
