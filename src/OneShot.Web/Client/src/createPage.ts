import { type CreateView, runCreate } from './createFlow';

const messages: Record<string, string> = {
  empty: 'Enter a secret first.',
  tooLong: 'The secret is too long. Shorten it and try again.',
  capacityExceeded: 'The service is full right now. Try again in a minute.',
  rateLimited: 'Too many links created. Wait a minute and try again.',
  insecureContext: 'This page must be opened over HTTPS to encrypt secrets.',
  failed: 'The link could not be created. Try again.',
};

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
    showLink: (url) => {
      link.value = url;
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
}
