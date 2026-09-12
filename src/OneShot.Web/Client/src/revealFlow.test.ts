import { describe, expect, it, vi } from 'vitest';

import { ApiError, type SecretPeek } from './api';
import { encode } from './base64url';
import { type RevealView, runRevealLoad } from './revealFlow';

const ID = 'abcdefghijklmnopqrstuA';

function harness() {
  const events: string[] = [];
  let enabledKey: Uint8Array | null = null;
  const view: RevealView = {
    stripFragment: () => events.push('strip'),
    showState: (state, expiresAt) => events.push(`state:${state}:${expiresAt ?? ''}`),
    showError: (code) => events.push(`error:${code}`),
    enableReveal: (key) => {
      enabledKey = key;
      events.push('enable');
    },
    setIdentity: (user) => events.push(`identity:${user ?? 'anonymous'}`),
    disableReveal: () => events.push('disable'),
    showSecret: (plaintext) => events.push(`secret:${plaintext}`),
  };
  return { view, events, key: () => enabledKey };
}

function deps(overrides: {
  id?: string;
  fragment?: string;
  peek?: () => Promise<SecretPeek>;
  whoami?: () => Promise<string | null>;
}) {
  const peek = vi.fn(overrides.peek ?? (async () => ({ state: 'available', expiresAt: '2026-09-12T13:00:00Z' }) as SecretPeek));
  const whoami = vi.fn(overrides.whoami ?? (async () => null));
  return {
    deps: { id: overrides.id ?? ID, fragment: overrides.fragment ?? encode(new Uint8Array(32).fill(7)), peek, whoami },
    peek,
    whoami,
  };
}

describe('[T8] reveal page load', () => {
  it('strips the fragment before any network call and renders an available secret', async () => {
    const { view, events, key } = harness();
    const { deps: d, peek, whoami } = deps({});

    await runRevealLoad(view, d);

    expect(events).toEqual(['strip', 'identity:anonymous', 'state:available:2026-09-12T13:00:00Z', 'enable']);
    expect(events.indexOf('strip')).toBeLessThan(events.indexOf('identity:anonymous'));
    expect(whoami).toHaveBeenCalledOnce();
    expect(peek).toHaveBeenCalledWith(ID);
    expect(key()).toEqual(new Uint8Array(32).fill(7));
  });

  it.each([
    ['empty', ''],
    ['too short', encode(new Uint8Array(31))],
    ['too long', encode(new Uint8Array(33))],
    ['not base64url', '!!!!'],
    ['padded', `${encode(new Uint8Array(32))}=`],
    ['truncated', encode(new Uint8Array(32)).slice(0, 40)],
  ])('%s fragment shows an error, makes no network call, and never enables reveal', async (_name, fragment) => {
    const { view, events, key } = harness();
    const { deps: d, peek, whoami } = deps({ fragment });

    await runRevealLoad(view, d);

    expect(events).toEqual(['strip', 'error:invalidKey']);
    expect(peek).not.toHaveBeenCalled();
    expect(whoami).not.toHaveBeenCalled();
    expect(key()).toBeNull();
  });

  it('rejects a malformed id in the path without any network call', async () => {
    const { view, events } = harness();
    const { deps: d, peek } = deps({ id: 'abcdefghijklmnopqrstuB' });

    await runRevealLoad(view, d);

    expect(events).toEqual(['strip', 'error:invalidLink']);
    expect(peek).not.toHaveBeenCalled();
  });

  it('shows the already-revealed state without enabling reveal', async () => {
    const { view, events, key } = harness();
    const { deps: d } = deps({ peek: async () => ({ state: 'consumed', expiresAt: '2026-09-12T13:00:00Z' }) });

    await runRevealLoad(view, d);

    expect(events).toContain('state:consumed:2026-09-12T13:00:00Z');
    expect(events).not.toContain('enable');
    expect(key()).toBeNull();
  });

  it('shows the unknown state without enabling reveal', async () => {
    const { view, events, key } = harness();
    const { deps: d } = deps({ peek: async () => ({ state: 'unknown', expiresAt: null }) });

    await runRevealLoad(view, d);

    expect(events).toContain('state:unknown:');
    expect(events).not.toContain('enable');
    expect(key()).toBeNull();
  });

  it('reports the identity when whoami succeeds', async () => {
    const { view, events } = harness();
    const { deps: d } = deps({ whoami: async () => 'CORP\\alice' });

    await runRevealLoad(view, d);

    expect(events).toContain('identity:CORP\\alice');
  });

  it('still checks the secret when whoami fails', async () => {
    const { view, events } = harness();
    const { deps: d, peek } = deps({ whoami: async () => null });

    await runRevealLoad(view, d);

    expect(peek).toHaveBeenCalledOnce();
    expect(events).toContain('state:available:2026-09-12T13:00:00Z');
  });

  it('surfaces an api error code and leaves reveal disabled', async () => {
    const { view, events, key } = harness();
    const { deps: d } = deps({
      peek: () => {
        throw new ApiError(429, 'rateLimited');
      },
    });

    await runRevealLoad(view, d);

    expect(events).toContain('error:rateLimited');
    expect(key()).toBeNull();
  });

  it('maps an unexpected failure to a generic error', async () => {
    const { view, events } = harness();
    const { deps: d } = deps({
      peek: () => {
        throw new TypeError('offline');
      },
    });

    await runRevealLoad(view, d);

    expect(events).toContain('error:failed');
  });
});
