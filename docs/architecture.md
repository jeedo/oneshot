# Architecture: OneShot — Secure One-Time Secret Sharing

> **Status**: Draft
> **Last Updated**: 2026-09-12

## Overview & Goals

OneShot is a .NET web application that lets a user ("sharer") securely share a single secret (password, token,
note, etc.) with another user ("recipient") via a link. The secret is never written to disk anywhere in the
system — it is held encrypted, in memory only, for a bounded lifetime — and can be decrypted and viewed **exactly
once**, after which it is permanently and irrecoverably deleted.

The design follows the zero-knowledge pattern used by established tools such as Yopass, PrivateBin, and
OneTimeSecret (see [`docs/research.md`](research.md)): the secret is encrypted **in the sharer's browser**
before it is transmitted, the server only ever sees and stores ciphertext, and the decryption key travels to the
recipient inside the share link's URL fragment, which browsers never transmit to any server.

**Problem Statement**: Sharing sensitive one-off values (credentials, tokens, keys) over chat/email is insecure
because those channels persist copies indefinitely and are readable by anyone with access to the channel or its
backups. OneShot needs to give the sharer a link that (a) can be opened successfully only once, (b) expires
automatically even if unopened, and (c) cannot be read by the server operator, since the server never has the
decryption key or the plaintext.

**Success Criteria**:
- The server process/store never has both the ciphertext and the decryption key at the same time; the server can
  never reconstruct the plaintext secret.
- The encrypted secret is held only in memory (`ConcurrentDictionary`-backed store, single instance) and is never
  written to disk, a database, or a log.
- A secret can be successfully revealed at most once; a second retrieval attempt (concurrent or sequential)
  always fails, with no race window that allows two callers to both succeed (atomic consume).
- A secret that is never retrieved is purged automatically once its TTL elapses.
- An automated link scanner/prefetcher opening the link does not consume the secret before the human recipient
  does (two-step reveal, see System Components).
- All secret transport happens over TLS; no secret material appears in a URL query string, referrer, or server
  log.

## Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Backend runtime | ASP.NET Core 8, Minimal APIs | Modern, first-class .NET web framework; Minimal APIs keep the small surface area (3 endpoints) simple with no MVC ceremony |
| Secret storage | In-process `ConcurrentDictionary<Guid, SecretRecord>` behind an `ISecretStore` abstraction | Satisfies "never to disk" by construction; `TryRemove` gives the atomic get-and-delete needed for one-time consumption (see research §4) |
| Background expiry | `IHostedService` timer sweep | Purges expired, unread ciphertext from memory even if the recipient never opens the link |
| Client-side cryptography | Web Crypto API (`SubtleCrypto`), AES-256-GCM, vanilla TypeScript | Runs in the sharer's and recipient's browsers so the server never sees plaintext or the key (zero-knowledge design, research §1) |
| Frontend | Razor Pages + a small TypeScript module (no SPA framework) | Only two real pages (create secret, reveal secret) — a full SPA framework is unjustified complexity |
| Transport security | TLS 1.2+, HSTS, `Cache-Control: no-store` on all secret endpoints | Prevents downgrade, browser/proxy caching of ciphertext or the reveal page |
| Rate limiting | ASP.NET Core built-in `Microsoft.AspNetCore.RateLimiting` | Defense in depth against brute-force enumeration of secret IDs, on top of the 128-bit ID keyspace already making that infeasible |
| Testing | xUnit | Standard .NET test framework; unit-tests the atomic consume/TTL logic and integration-tests the API endpoints |
| Deployment topology | Single instance | Node-local `ConcurrentDictionary` storage; deliberate simplicity trade-off, see Open Questions |

## System Components

```
Sharer's browser                 OneShot API (ASP.NET Core)                Recipient's browser
──────────────────               ────────────────────────────              ───────────────────
1. Type secret
2. Generate random
   AES-256-GCM key (K)
   + nonce, encrypt          →   POST /api/secrets
   secret client-side             { ciphertext, nonce, ttlSeconds }
   (server never sees             ──────────────────────────────→
   plaintext or K)                                                    ISecretStore.Create()
                                                                       stores {ciphertext, nonce,
                                                                       expiresAtUtc, consumed=false}
                                                                       in the in-memory dictionary,
                                                                       keyed by a random 128-bit Id
                                  { id, expiresAt }
                              ←──────────────────────────────
3. Build share link:
   https://host/s/{id}#{K}
   (fragment never sent to
   any server)
4. Send link to recipient
   via any channel (chat,
   email, ...)
                                                                              5. Open link
                                                                              6. Extract K from
                                                                                 URL fragment (JS)
                                                            GET /api/secrets/{id}
                                                        ←──────────────────────
                                                        { exists: true,          7. Show "Reveal
                                                          expiresAt }               secret" button
                                                                                     (does NOT consume)
                                                                              8. User clicks Reveal
                                                            POST /api/secrets/{id}/reveal
                                                        ←──────────────────────
                                                            ISecretStore.TryConsume(id)
                                                            — atomic TryRemove;
                                                            second caller gets 410 Gone
                                                        { ciphertext, nonce }
                                                        or 410 Gone
                                                                              9. Decrypt with K
                                                                                 (Web Crypto),
                                                                                 display secret,
                                                                                 discard K
```

- **Web/API host (ASP.NET Core)**: hosts the two Razor pages (create, reveal) and the three API endpoints below.
  Applies `Cache-Control: no-store`, HSTS, and a strict CSP (script-src limited to the app's own hashed/SRI'd
  bundle) to reduce the XSS blast radius around the fragment key.
- **`ISecretStore` abstraction** with a default **`InMemorySecretStore`**: wraps a
  `ConcurrentDictionary<Guid, SecretRecord>`. Exposes `Create(ciphertext, nonce, ttl) -> Guid`,
  `Peek(Guid) -> SecretMetadata?` (existence/expiry check only, no consumption — used for the confirmation page),
  and `TryConsume(Guid) -> SecretRecord?` (atomic remove-and-return; the *only* way ciphertext ever leaves the
  store, and it can only succeed once per Id).
- **`ExpirySweeperService`** (`IHostedService`): runs on a timer (e.g. every 30s), scans the store, and evicts any
  record past `ExpiresAtUtc` that was never consumed, so unread secrets don't linger in memory indefinitely.
- **Client crypto module** (TypeScript, loaded on both the create and reveal pages): on create, generates a
  random AES-256-GCM key and nonce via `crypto.subtle.generateKey`/`getRandomValues`, encrypts the secret, and
  never transmits the key. On reveal, reads the key from `location.hash`, fetches ciphertext via the reveal
  endpoint, decrypts with `crypto.subtle.decrypt`, renders the plaintext, and then drops all references to the
  key and plaintext (no client-side persistence, no `localStorage`).
- **Rate-limiting middleware**: per-IP fixed-window limiter on `POST /api/secrets/{id}/reveal` and
  `GET /api/secrets/{id}`, to blunt automated enumeration attempts even though a 128-bit random Id is already
  computationally infeasible to guess.

## Data Model / API

**`SecretRecord`** (server-side, in memory only — never serialized to disk or logged):

| Field | Type | Notes |
|-------|------|-------|
| `Id` | `Guid` | Cryptographically random (128-bit); the only thing the server needs to look up a secret |
| `CiphertextBase64` | `string` | AES-256-GCM ciphertext (includes the auth tag); server can never decrypt this — it never has the key |
| `NonceBase64` | `string` | 96-bit GCM nonce used for this ciphertext |
| `CreatedAtUtc` | `DateTimeOffset` | For diagnostics/TTL bookkeeping only |
| `ExpiresAtUtc` | `DateTimeOffset` | Hard TTL backstop, independent of whether the secret is ever read |
| `Consumed` | `bool` | Set atomically by `TryConsume`; a consumed or expired record is unreachable/removed |

The decryption key is **not a field on this model** — it never exists server-side in any form.

**API endpoints** (all under `/api/secrets`, all `Cache-Control: no-store`):

| Method & Path | Purpose | Side effect |
|---|---|---|
| `POST /api/secrets` | Sharer submits `{ ciphertext, nonce, ttlSeconds }` (already encrypted client-side); returns `{ id, expiresAt }` | Creates the record |
| `GET /api/secrets/{id}` | Recipient's page checks whether the secret is still available before showing the "Reveal" button; returns `{ exists, expiresAt }` or `404` | **None** — read-only, safe for link scanners/prefetchers to hit without consuming the secret |
| `POST /api/secrets/{id}/reveal` | Recipient explicitly clicks "Reveal"; returns `{ ciphertext, nonce }` or `410 Gone` if already consumed/expired | **Atomically consumes and deletes** the record — this is the only path that ever returns ciphertext |

Share link shape: `https://<host>/s/{id}#{base64url(key)}`. The fragment (`#...`) is never sent in the HTTP
request to any server per the URL spec, which is what keeps the key out of server logs, proxy logs, and browser
history sync by default.

## Open Questions / Documented Trade-offs

- **Single-instance deployment (decided)**: OneShot runs as a single ASP.NET Core instance; the
  `InMemorySecretStore` is node-local by design, with no distributed cache or shared backing store. This is a
  deliberate simplicity trade-off — it means the app cannot be scaled horizontally or run behind a load balancer
  across multiple nodes without secrets becoming unreachable depending on which node handled `POST /api/secrets`
  versus which node later receives the reveal request. If scale-out is needed later, it requires either sticky
  sessions pinned to the creating instance, or introducing a shared `ISecretStore` backend — neither is built now.
- **Server-side encryption alternative**: research documents a simpler alternative (Password Pusher's model,
  where the server itself encrypts a plaintext secret submitted over TLS). This architecture intentionally
  chooses the stronger zero-knowledge model instead; revisit only if client-side crypto proves to be a UX
  blocker.

## Research & References

See [docs/research.md](research.md) for the full survey of existing one-time secret sharing mechanisms
(Yopass, PrivateBin, OneTimeSecret, Password Pusher, HashiCorp Vault response wrapping) and the .NET
cryptography primitives (`AesGcm`) that this design builds on.
