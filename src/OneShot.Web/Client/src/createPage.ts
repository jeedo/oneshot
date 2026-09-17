import { type CreateView, runCreate } from './createFlow';

const messages: Record<string, string> = {
  empty: 'Enter a secret first.',
  tooLong: 'The secret is too long. Shorten it and try again.',
  capacityExceeded: 'The service is full right now. Try again in a minute.',
  rateLimited: 'Too many links created. Wait a minute and try again.',
  insecureContext: 'This page must be opened over HTTPS to encrypt secrets.',
  failed: 'The link could not be created. Try again.',
};

interface SplitKeyElements {
  checkbox: HTMLInputElement;
  field: HTMLElement;
  value: HTMLInputElement;
  copyButton: HTMLButtonElement;
}

// Issue #77's split-channel option is gated behind an operator flag (Features:SplitKeyDelivery, task 57 follow
// up) checked at startup, so its markup — all four elements together, or none of them — may legitimately be
// absent from the page. Nothing else on this page depends on it.
function findSplitKeyElements(root: Document): SplitKeyElements | null {
  const checkbox = root.querySelector<HTMLInputElement>('#splitKey');
  const field = root.querySelector<HTMLElement>('#keyField');
  const value = root.querySelector<HTMLInputElement>('#key');
  const copyButton = root.querySelector<HTMLButtonElement>('#copyKey');
  return checkbox && field && value && copyButton ? { checkbox, field, value, copyButton } : null;
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

  const splitKey = findSplitKeyElements(root);

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
    splitKey: () => splitKey?.checkbox.checked ?? false,
    clearSecret: () => {
      secret.value = '';
    },
    showLink: (url, shownKey) => {
      link.value = url;
      if (splitKey) {
        if (shownKey !== null) {
          splitKey.value.value = shownKey;
          splitKey.field.hidden = false;
        } else {
          splitKey.value.value = '';
          splitKey.field.hidden = true;
        }
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
    void runCreate(view, { origin: root.location.origin }).finally(() => {
      create.disabled = false;
    });
  });

  copy.addEventListener('click', () => {
    void navigator.clipboard.writeText(link.value);
  });

  splitKey?.copyButton.addEventListener('click', () => {
    void navigator.clipboard.writeText(splitKey.value.value);
  });
}
