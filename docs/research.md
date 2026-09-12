# Research Notes

> **Topic**: Secure one-time secret sharing — existing mechanisms and applicable patterns
> **Last Updated**: 2026-09-12

## Summary

One-time secret sharing ("burn after reading") is a well-established problem with several mature open-source
implementations (Yopass, PrivateBin, OneTimeSecret/onetimesecret.com, Password Pusher) and one relevant
enterprise pattern (HashiCorp Vault response wrapping / cubbyhole). The dominant, most secure architecture is a
**zero-knowledge design**: the secret is encrypted *in the sharer's browser* before it ever reaches the server,
the server only ever stores and transmits ciphertext, and the decryption key travels to the recipient inside the
URL **fragment** (`#...`), which browsers never send to the server. Consumption must be an **atomic
get-and-delete** operation to guarantee "exactly once" semantics under concurrent requests, and the reveal step
should require explicit user action (not a bare `GET`) to avoid automated link scanners silently burning the
secret before the intended recipient opens it. These conclusions directly inform `docs/architecture.md`.

## Findings

### 1. Zero-knowledge client-side encryption (Yopass, PrivateBin, OneTimeSecret)

- **Yopass**: encrypts the secret in the browser before upload; the decryption key is embedded in the share link
  and never sent to or stored on the server. Secrets self-destruct after being viewed once or when a TTL expires.
  Lightweight, Docker-deployable, Go backend with a Redis or memory storage backend.
- **PrivateBin**: uses AES-256-GCM in the browser with PBKDF2-SHA256 key derivation; the key lives in the URL
  fragment. The server (PHP, filesystem/S3-backed) only ever stores ciphertext and cannot decrypt it — a genuine
  zero-knowledge design. An optional user-supplied passphrase can be mixed into the key derivation for defense in
  depth.
- **OneTimeSecret (onetimesecret.com)**: encryption/decryption happens entirely client-side; the server generates
  no key, sees no plaintext, and stores only ciphertext (historically backed by Redis, relying on Redis TTL for
  expiry). On retrieval, the server returns the ciphertext once and then permanently deletes it — the canonical
  "burn after reading" behavior.

**Takeaway**: the strongest privacy guarantee (server operators can never read a shared secret, even under
subpoena or a server compromise) requires the encryption key to never leave the client. This is the pattern to
copy for the "high encryption, never on disk" requirement — it also makes "never persisted" trivially true, since
the server-held ciphertext is useless without the client-held key.

### 2. Server-side encryption model (Password Pusher / pwpush)

- Password Pusher (open source, Ruby/Rails) takes the opposite trade-off: the plaintext secret is submitted to
  the server, encrypted there with AES-256 and stored only in encrypted form; it's deleted entirely once viewed
  the configured number of times or once its TTL elapses. It adds audit logging (who/when a link was viewed).
- This is simpler to build (no client-side crypto, easier to add features like audit trails or file attachments)
  but weaker: the server sees the plaintext at submission time, even if only transiently and never persisted to
  disk. It requires trusting the server operator/process memory at that instant.

**Takeaway**: a legitimate, simpler alternative architecture. Useful as a documented trade-off/alternative in the
architecture doc, but the zero-knowledge model is preferred given the "securely share" and "high encryption"
requirements.

### 3. HashiCorp Vault — Cubbyhole & response wrapping

- Vault can wrap a response in a single-use "wrapping token": the real payload is stored in that token's private
  cubbyhole, and the token can be unwrapped exactly once within a TTL; unwrapping destroys both the token and the
  cubbyhole atomically. No other token (not even root) can read another token's cubbyhole.
- This is an enterprise secret-distribution pattern (e.g., safely handing a generated credential to a new
  service) rather than a person-to-person sharing tool, and pulls in a full secrets-management system — overkill
  for this app. But the underlying idea is exactly what we want: **the act of reading destroys the thing that
  allowed reading**, atomically, with a TTL as a backstop.

**Takeaway**: validates the "one-time token → atomic consume → destroy" pattern as an industry-standard design,
independent of Vault itself being used.

### 4. Atomicity: preventing double-reads under concurrent requests

- The classic bug in "read then delete" implementations is a race: two concurrent requests both read the secret
  before either delete completes, so both recipients see it. Redis's `GETDEL` (or the pre-6.2 `GET`+`DEL`
  Lua-script workaround) exists specifically to make "fetch and consume" a single atomic operation so that only
  one caller can ever win.
- **Takeaway for .NET**: the in-memory store must expose a single atomic "try-consume" operation (e.g.
  `ConcurrentDictionary<Guid, T>.TryRemove`), never a separate read followed by a separate delete, or the same
  race applies locally.

### 5. Mitigating automated link-scanner "pre-burn"

- A widely reported failure mode for all of the above tools: corporate email security gateways (e.g. link
  "safe browsing" prescanners) automatically follow links in email, which — if the reveal endpoint is a plain
  `GET` with a side effect — silently consumes the one-time secret before the human recipient ever opens the
  link.
- **Takeaway**: separate "does this secret still exist / show a confirmation page" (safe, idempotent `GET`,
  no side effect) from "actually consume and return the ciphertext" (only triggered by an explicit user action,
  e.g. a button click resulting in a `POST`). This is reflected as a two-step reveal flow in the architecture.

### 6. Encryption primitives for .NET

- AES-256-GCM (AEAD: confidentiality + integrity in one primitive) is the consistent industry choice across all
  of the above tools and is directly available in .NET via `System.Security.Cryptography.AesGcm`.
- `AesGcm` requires a 96-bit (12-byte) nonce; the nonce must never be reused with the same key. Since this app
  generates a brand-new random key per secret (never reused across secrets), a random nonce per encryption
  operation is sufficient — there is no key-rotation or nonce-collision problem to solve, unlike long-lived KMS
  keys.
- Hybrid RSA+AES-GCM envelope encryption (as used by cloud KMS providers) is unnecessary here: that pattern
  exists to protect a *long-lived* key at rest. This app's key is single-use and never stored server-side at all,
  so envelope encryption would add complexity without a corresponding security benefit.
- Legacy `SecureString` is deprecated/obsolete guidance in modern .NET; plaintext should instead be kept in memory
  for the minimum time necessary and cleared (`Array.Clear`/`CryptographicOperations.ZeroMemory`) as soon as
  encryption or decryption completes.

## References

- [Yopass](https://yopass.se/)
- [PrivateBin vs Yopass vs OneTimeSecret comparison](https://securebin.ai/compare/)
- [How OneTimeSecret works](https://onefimesecret.com/how-it-works.php)
- [Password Pusher (OSS)](https://github.com/pglombardo/PasswordPusher)
- [HashiCorp Vault — Response Wrapping](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping)
- [Cubbyhole Response Wrapping](https://blog.nishanthkp.com/docs/devsecops/sm/vault/cubbyhole-response-wrapping/)
- [Redis GETDEL — atomic get-and-delete](https://oneuptime.com/blog/post/2026-03-31-redis-getdel-atomic/view)
- [Key storage format in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-format?view=aspnetcore-8.0)
- [Cross-platform cryptography - .NET](https://learn.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography)
- [Memory-Safe Secrets in .NET Configuration](https://dev.to/bwi/memory-safe-secrets-in-net-configuration-41bb)
