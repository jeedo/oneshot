import { peekSecret, whoami } from './api';
import { type RevealView, runRevealLoad } from './revealFlow';

const errors: Record<string, string> = {
  invalidKey: 'This link is incomplete, so the secret cannot be decrypted. Ask the sender for a new link.',
  invalidLink: 'This link is not a valid OneShot link.',
  rateLimited: 'Too many attempts from this network. Wait a minute and reload.',
  insecureContext: 'This page must be opened over HTTPS to decrypt secrets.',
  failed: 'The secret could not be checked. Reload to try again.',
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
  if (!status || !expiry || !identity || !error || !reveal) {
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

  let revealKey: Uint8Array | null = null;

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
      // Held only in this closure — never on the DOM, never in storage. Task 23 decrypts with it.
      revealKey = key;
      reveal.disabled = false;
    },
    setIdentity: (user) => {
      if (user) {
        identity.textContent = `Signed in as ${user}.`;
        identity.hidden = false;
      }
    },
  };

  void runRevealLoad(view, {
    id: root.location.pathname.split('/').pop() ?? '',
    fragment: root.location.hash.slice(1),
    peek: (id) => peekSecret(id),
    whoami: () => whoami(),
  });
}
