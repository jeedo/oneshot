import { peekSecret, revealSecret, whoami } from './api';
import { decode } from './base64url';
import { KEY_BYTES } from './crypto';
import { type RevealView, runReveal, runRevealLoad } from './revealFlow';

const errors: Record<string, string> = {
  invalidKey: 'This link is incomplete, so the secret cannot be decrypted. Ask the sender for a new link.',
  invalidLink: 'This link is not a valid OneShot link.',
  consumed: 'This secret has already been revealed. If that was not you, treat the secret as compromised.',
  unknown: 'This secret does not exist, or it has expired.',
  tampered: 'This secret was corrupted or tampered with, so it cannot be trusted. Ask the sender for a new link.',
  revealNotAllowed: 'This reveal was blocked. Open the link directly in your browser and try again.',
  rateLimited: 'Too many attempts from this network. Wait a minute and reload.',
  insecureContext: 'This page must be opened over HTTPS to decrypt secrets.',
  failed: 'The secret could not be revealed. Reload to try again.',
};

const states: Record<string, string> = {
  available: 'This secret is still sealed. Reveal it when you are ready — it can only be opened once.',
  consumed: 'This secret has already been revealed. If that was not you, treat the secret as compromised.',
  unknown: 'This secret does not exist, or it has expired.',
};

export function initRevealPage(root: Document): void {
  const status = root.querySelector<HTMLElement>('#status');
  const expiry = root.querySelector<HTMLElement>('#expiry');
  const identity = root.querySelector<HTMLElement>('#identity');
  const error = root.querySelector<HTMLElement>('#error');
  const reveal = root.querySelector<HTMLButtonElement>('#reveal');
  const result = root.querySelector<HTMLElement>('#result');
  const plaintext = root.querySelector<HTMLPreElement>('#plaintext');
  const copy = root.querySelector<HTMLButtonElement>('#copy');
  const keyEntry = root.querySelector<HTMLElement>('#keyEntry');
  const manualKey = root.querySelector<HTMLInputElement>('#manualKey');
  if (!status || !expiry || !identity || !error || !reveal || !result || !plaintext || !copy || !keyEntry || !manualKey) {
    return;
  }

  const showError = (code: string): void => {
    error.textContent = errors[code] ?? errors['failed']!;
    error.hidden = false;
    status.hidden = true;
  };

  if (!globalThis.crypto?.subtle) {
    showError('insecureContext');
    return;
  }

  let revealKey: Uint8Array<ArrayBuffer> | null = null;

  const view: RevealView = {
    stripFragment: () => root.defaultView?.history.replaceState(null, '', root.location.pathname),
    showState: (state, expiresAt) => {
      status.textContent = states[state]!;
      status.hidden = false;
      if (state !== 'unknown' && expiresAt) {
        expiry.textContent = `Expires ${new Date(expiresAt).toLocaleString()}.`;
        expiry.hidden = false;
      }
    },
    showError,
    enableReveal: (key) => {
      // Held only in this closure — never on the DOM, never in storage — and zeroed by the reveal itself.
      revealKey = key as Uint8Array<ArrayBuffer>;
      reveal.disabled = false;
    },
    promptForKey: () => {
      keyEntry.hidden = false;
      manualKey.focus();
    },
    setIdentity: (user) => {
      if (user) {
        identity.textContent = `Signed in as ${user}.`;
        identity.hidden = false;
      }
    },
    disableReveal: () => {
      reveal.disabled = true;
    },
    showSecret: (text) => {
      // textContent, never an HTML sink: revealed content is data, never markup (T7).
      plaintext.textContent = text;
      status.hidden = true;
      expiry.hidden = true;
      error.hidden = true;
      result.hidden = false;
      copy.focus();
    },
  };

  reveal.addEventListener('click', () => {
    const key = revealKey;
    revealKey = null;
    if (!key) {
      return;
    }
    void runReveal(view, { id: pathId(root), key, reveal: (id) => revealSecret(id) });
  });

  copy.addEventListener('click', () => {
    void navigator.clipboard.writeText(plaintext.textContent ?? '');
  });

  // Same gate the fragment path already enforces (T4, issue #77): Reveal stays disabled until the manually
  // entered key decodes to exactly 32 bytes, so a click here is exactly as guaranteed to carry a
  // syntactically valid key as a click driven by a fragment ever was — a shorter or malformed key cannot
  // reach POST /reveal and consume the secret before it has the right shape.
  manualKey.addEventListener('input', () => {
    let key: Uint8Array | null = null;
    try {
      const decoded = decode(manualKey.value.trim());
      key = decoded.length === KEY_BYTES ? decoded : null;
    } catch {
      key = null;
    }
    revealKey = key as Uint8Array<ArrayBuffer> | null;
    reveal.disabled = key === null;
  });

  void runRevealLoad(view, {
    id: pathId(root),
    fragment: root.location.hash.slice(1),
    peek: (id) => peekSecret(id),
    whoami: () => whoami(),
  });
}

function pathId(root: Document): string {
  return root.location.pathname.split('/').pop() ?? '';
}
