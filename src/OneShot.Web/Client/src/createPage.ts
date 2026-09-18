import { type CreateView, runCreate } from './createFlow';

const messages: Record<string, string> = {
  empty: 'Enter a secret first.',
  tooLong: 'The secret is too long. Shorten it and try again.',
  capacityExceeded: 'The service is full right now. Try again in a minute.',
  rateLimited: 'Too many links created. Wait a minute and try again.',
  insecureContext: 'This page must be opened over HTTPS to encrypt secrets.',
  failed: 'The link could not be created. Try again.',
};

interface KeyFieldElements {
  field: HTMLElement;
  value: HTMLInputElement;
  copyButton: HTMLButtonElement;
}

// Issue #77's split-channel key delivery is a deployment-wide default (Features:SplitKeyDelivery, task 57),
// not a per-secret choice, so this markup — all three elements together, or none of them — may legitimately
// be absent from the page. Its presence is also the page's only signal that the deployment wants every secret
// created here to withhold the key from the link; there is no separate UI opt-in any more.
function findKeyFieldElements(root: Document): KeyFieldElements | null {
  const field = root.querySelector<HTMLElement>('#keyField');
  const value = root.querySelector<HTMLInputElement>('#key');
  const copyButton = root.querySelector<HTMLButtonElement>('#copyKey');
  return field && value && copyButton ? { field, value, copyButton } : null;
}

export function initCreatePage(root: Document): void {
  const secret = root.querySelector<HTMLTextAreaElement>('#secret');
  const ttl = root.querySelector<HTMLSelectElement>('#ttl');
  const create = root.querySelector<HTMLButtonElement>('#create');
  const error = root.querySelector<HTMLElement>('#error');
  const result = root.querySelector<HTMLElement>('#result');
  const link = root.querySelector<HTMLInputElement>('#link');
  const copy = root.querySelector<HTMLButtonElement>('#copy');
  if (!secret || !ttl || !create || !error || !result || !link || !copy) {
    return;
  }

  const keyField = findKeyFieldElements(root);

  const showError = (code: string): void => {
    error.textContent = messages[code] ?? messages['failed']!;
    error.hidden = false;
    result.hidden = true;
  };

  if (!globalThis.crypto?.subtle) {
    create.disabled = true;
    showError('insecureContext');
    return;
  }

  const view: CreateView = {
    readSecret: () => secret.value,
    ttlSeconds: () => Number.parseInt(ttl.value, 10),
    clearSecret: () => {
      secret.value = '';
    },
    showLink: (url, shownKey) => {
      link.value = url;
      if (keyField) {
        keyField.value.value = shownKey ?? '';
        keyField.field.hidden = shownKey === null;
      }
      error.hidden = true;
      result.hidden = false;
      link.focus();
      link.select();
    },
    showError,
  };

  create.addEventListener('click', () => {
    create.disabled = true;
    void runCreate(view, { origin: root.location.origin, splitKey: !!keyField }).finally(() => {
      create.disabled = false;
    });
  });

  copy.addEventListener('click', () => {
    void navigator.clipboard.writeText(link.value);
  });

  keyField?.copyButton.addEventListener('click', () => {
    void navigator.clipboard.writeText(keyField.value.value);
  });
}
