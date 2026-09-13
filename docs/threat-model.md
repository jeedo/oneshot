# Threat Model

> **Status**: Active — reviewed whenever a component is added or a trust boundary moves; walked in full by the
> pre-release security review (plan task 52).
> **Last Updated**: 2026-09-12

This document expands the threat register in [`plan.md`](plan.md) (T1–T15) into a STRIDE analysis of each
component described in [`architecture.md`](architecture.md). Every mitigation in the code and every security test
cites a register ID; the [Test Convention](#test-convention) section defines how, and plan task 26 adds the CI
check that fails when any ID has no test.

## Assets

Ranked by the damage their compromise causes. The first two are the reason the system exists.

| # | Asset | Where it lives | Compromise means |
|---|-------|----------------|------------------|
| A1 | **Plaintext secret** | Sharer's browser until encrypted; recipient's browser after decryption; never anywhere else | Total loss of confidentiality |
| A2 | **Decryption key `K`** (256-bit AES-GCM) | Sharer's browser; the share link's URL fragment; recipient's browser. Never sent to any server | Anyone holding the ciphertext can read the secret |
| A3 | **Ciphertext + nonce** | Server memory only (`InMemorySecretStore`), until consumed or expired | Useless alone; combined with A2 (e.g. a leaked link plus a memory dump) it is A1 |
| A4 | **Secret Id** (128-bit random) | Server store, share link path, audit log | Only lets someone reach the reveal flow; still needs A2 |
| A5 | **Exactly-once guarantee** | `TryConsume` atomicity + tombstone | Two parties read the same secret; the intended recipient cannot tell |
| A6 | **Windows identity / audit trail** | Identity cookie (signed, 5 min), audit log entries | Misattributed actions, PII exposure, forged accountability |
| A7 | **Client bundle integrity** | `wwwroot/js/oneshot.js` served with SRI + CSP hash | A tampered bundle can read `K` from the fragment and exfiltrate it |
| A8 | **Availability** | Single in-memory instance | Secrets cannot be created or revealed; in-flight secrets lost on restart |

## Trust Boundaries

```
 ┌──────────────────────┐   TLS    ┌───────────────────────────────────────────┐   TLS   ┌──────────────────────┐
 │  Sharer's browser    │ ───────▶ │  OneShot host (single ASP.NET Core process) │ ◀────── │  Recipient's browser │
 │  (trusted with A1,A2)│  B1      │  ┌─────────────┐ ┌──────────┐ ┌──────────┐ │   B1    │  (trusted with A1,A2)│
 └──────────┬───────────┘          │  │ Middleware  │ │ Endpoints│ │  Store   │ │         └──────────┬───────────┘
            │                      │  │ (headers,   │ │ (create, │ │ (memory  │ │                    │
            │ share link           │  │  limits,    │ │  peek,   │ │  only)   │ │                    │
            │ https://h/s/{id}#{K} │  │  rate limit)│ │  reveal, │ │          │ │                    │
            ▼  B2                  │  └─────────────┘ │  whoami) │ └──────────┘ │                    │
 ┌──────────────────────┐          │                  └──────────┘ ┌──────────┐ │                    │
 │  Link channel        │          │  ┌──────────────┐             │ Sweeper  │ │                    │
 │  (chat, e-mail, …)   │ ─ ─ ─ ─ ▶│  │ Audit logger │ ──▶ stdout  └──────────┘ │ ◀─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
 │  + link scanners     │  B3      │  └──────────────┘   B4  (JSON log lines)   │   opens link
 └──────────────────────┘          └───────────────────────────────────────────┘
                                                        │ B5
                                                        ▼
                                           Operations: log pipeline, container host, reverse proxy
```

| Boundary | Between | What crosses it | Key controls |
|----------|---------|-----------------|--------------|
| **B1** | Browser ↔ server | Ciphertext, nonce, Id, TTL, identity cookie. **Never `K` or plaintext** — the fragment is not part of the HTTP request | TLS 1.2+, HSTS, `no-store`, `no-referrer`, body/header limits, rate limits |
| **B2** | Sharer ↔ link channel | The full share link, fragment included | Out of the system's control; mitigated by one-time consumption and the tombstone's tamper evidence |
| **B3** | Link channel ↔ server | Scanner and prefetch `GET`s | Side-effect-free `GET`; reveal only via same-origin `POST` with custom header |
| **B4** | Application ↔ log pipeline | Audit events and application logs | Four-field audit events; request/body logging disabled; no query strings |
| **B5** | Process ↔ host/operations | Memory, environment, TLS termination | In-memory only, ephemeral Data Protection, read-only container FS, hardened Kestrel, startup validation |

The server process sits **outside** the trust boundary for A1 and A2 by design: the system is correct even if the
process is fully compromised, because the process never receives `K`.

## Attacker Profiles

| Attacker | Capabilities | Cannot | Primary threats |
|----------|--------------|--------|-----------------|
| **Network observer/active MITM** | Sees or alters traffic between browser and server if TLS is downgraded or terminated | Break TLS 1.2+ | T8 |
| **Link-channel reader** | Anyone with access to the chat/e-mail where the link was posted; sees Id and `K` | Read the secret if it was already revealed (tombstone) | T2 (as a race), T4 |
| **Link scanner / prefetcher** | Automatically `GET`s every link, sometimes with a headless browser; may send `Purpose: prefetch` | Send the custom reveal header or click Reveal (without a purpose-built scanner) | T4 |
| **Anonymous remote client** | Unlimited malformed and high-volume requests | Guess a 128-bit Id | T3, T6, T11, T12, T13 |
| **Compromised or malicious server process** | Reads all memory, all requests, all logs | Obtain `K` | T1, T5 |
| **Operator / log reader** | Reads logs, crash dumps, container volumes | Reconstruct plaintext from ciphertext alone | T1, T5, T10 |
| **Malicious sharer** | Submits crafted "secrets" (HTML, scripts, oversized) or forged identity | Escape the recipient's CSP-restricted page | T7, T10, T12 |
| **Supply-chain attacker** | Publishes a malicious npm/NuGet version or base image | Alter the served bundle without changing its recorded hash | T7, T14 |
| **Deployer** | Misconfigures HTTP, dev pages, proxies, limits | Bypass fail-fast startup validation | T11, T15 |

## STRIDE per Component

Each table lists the threats that apply to the component, the register ID, and where the mitigation lives
(plan task numbers). Rows marked *n/a* are categories that do not apply to that component.

### C1. Create page and client crypto (sharer's browser)

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Spoofing | n/a — no server identity is asserted to the sharer beyond TLS | — | — |
| Tampering | Tampered bundle encrypts with an attacker-known key or exfiltrates `K` | T7 | SRI `integrity` + CSP `script-src` hash from the recorded bundle SHA-256 (3, 4); `default-src 'none'` blocks any other script (4) |
| Repudiation | Sharer denies creating a secret | T10 | Best-effort verified identity on the `create` audit event (15, 19) |
| Info disclosure | Plaintext or `K` leaves the browser: form post without JS, referrer, history | T1, T8 | JS-only submission with no form `action` (21); `no-referrer` (4); `K` only in the fragment (21); textarea overwritten and key reference dropped (21) |
| Denial of service | n/a | — | — |
| Elevation | n/a | — | — |
| Crypto | Weak randomness, nonce reuse, short key | T9 | 256-bit key and 12-byte nonce from `crypto.getRandomValues`, fresh per secret (21, 37) |

### C2. Reveal page (recipient's browser)

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Spoofing | A cross-site page triggers the reveal on the recipient's behalf | T4 | Reveal requires same-origin `POST`, `X-OneShot-Reveal` header, JSON content type, `Sec-Fetch-Site` check; no CORS policy (18, 32) |
| Tampering | Ciphertext or nonce altered in transit or in store | T9 | GCM authentication fails closed with a "corrupted or tampered" message (23) |
| Repudiation | Recipient denies revealing | T10 | Verified identity on the `reveal` audit event (15, 19) |
| Info disclosure | Revealed content executes as HTML/JS; `K` persists in history, cache, or referrer | T7, T8 | `textContent` into `<pre>`, never `innerHTML` (23); strict CSP (4); fragment stripped via `history.replaceState` before any network call (22); `no-store` (4); key and plaintext references overwritten after display (23) |
| Denial of service | Scanner burns the secret before the human opens it | T4 | Two-step flow: `GET` shows state only, explicit click consumes (17, 22) |
| Elevation | n/a | — | — |

### C3. Transport (B1)

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Spoofing | Server impersonation via downgrade | T8 | TLS 1.2+ only (5); HSTS 1 year, `includeSubDomains`, `preload` (4); HTTPS redirection (4) |
| Tampering | Injected or modified responses over plain HTTP | T8 | HSTS + redirect (4); SRI on the bundle (3) |
| Info disclosure | Proxy or browser caches ciphertext or the reveal page | T8 | `Cache-Control: no-store` + `Pragma: no-cache` on `/`, `/s/*`, `/api/*` (4) |
| Denial of service | Slow-loris, oversized requests | T6 | Kestrel header/body limits and timeouts (5) |

### C4. Web host: Kestrel, middleware, error handling

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Tampering | Headers forged to bypass rate limiting | T11 | Forwarded headers honoured only from configured known proxies (20, 30) |
| Tampering | Razor page routes carry no method constraint, so `TRACE` renders the whole page and `OPTIONS` answers a bare 200 | T4 | Page endpoints constrained to `GET`/`HEAD`, so routing answers 405 with `Allow` like the API behind them (32) |
| Info disclosure | Stack traces, framework versions, `Server` header, distinguishable error bodies | T13 | `AddServerHeader = false` (5); generic RFC 7807 errors, no developer exception page in any environment (24, 41) |
| Denial of service | Body, header, and connection exhaustion | T6 | `MaxRequestBodySize` 128 KiB, header size/count caps, keep-alive and header timeouts (5) |
| Elevation | Misconfiguration enables HTTP, dev pages, or untrusted proxies | T15 | `ValidateOnStart` refuses to start outside Development when no HTTPS address and no trusted proxy are configured, when `DetailedErrors` is on, when the HSTS max-age, body/header limits, capacity caps or rate limits are absent or unusable, or when forwarded headers are configured without known proxies (49); deployment docs (50) |

### C5. API endpoints (`POST /api/secrets`, `GET /api/secrets/{id}`, `POST …/reveal`)

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Spoofing | Cross-site reveal (CSRF) | T4 | Same-origin `POST` with custom header; `GET` has no side effects (17, 18, 31, 32) |
| Tampering | Malformed or hostile input reaches the store | T12 | Strict `JsonSerializerOptions` (unknown fields rejected, depth 8), base64url/nonce/TTL validation with typed errors that never echo input (10, 16, 38) |
| Repudiation | Actions without an audit trail | T10 | `create` and `reveal` each write exactly one audit event (15, 16, 18) |
| Info disclosure | Id enumeration via differing responses or timing | T3, T13 | 128-bit CSPRNG Ids (9); uniform 404 bodies (17, 29, 41); per-IP rate limits (20) |
| Denial of service | Mass or oversized creates | T6 | Body limit (5); capacity caps returning 503 + `Retry-After` (13, 16, 39); `create` limiter 20/min (20) |
| Elevation | n/a — no privileged operations exist | — | — |

### C6. `InMemorySecretStore`

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Tampering | Race: two callers both receive the ciphertext | T2 | `TryConsume` is one `ConcurrentDictionary.TryUpdate` swapping the record for its tombstone; the second caller sees the tombstone and never a gap (11, 27) |
| Info disclosure | Ciphertext reaches disk or lingers in memory | T5 | No persistence layer of any kind; buffers zeroed on consume and evict; `ConsumedSecret` zeroes on dispose (8, 11, 12, 28, 36) |
| Info disclosure | Server can decrypt | T1, T9 | `OneShot.Web` references no `System.Security.Cryptography.Aes*` type; architecture test enforces it (36) |
| Denial of service | Memory exhaustion | T6 | Entry cap (10,000) and byte cap (64 MiB) accounted atomically (13, 39) |

### C7. `ExpirySweeperService`

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Info disclosure | Unread ciphertext outlives its TTL | T5 | 30 s `TimeProvider`-driven sweep evicts and zeroes expired records and tombstones (14, 28) |
| Denial of service | One faulty entry or a huge store stalls sweeping | T6 | Bounded per-pass scan; per-pass exception isolation (14, 39) |

### C8. Identity (`GET /api/whoami`) and audit logging

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Spoofing | Forged or replayed identity | T10 | Identity only from a Negotiate challenge; cookie is Data-Protection-signed, 5-minute, `HttpOnly; Secure; SameSite=Strict; Path=/api` (19, 40) |
| Tampering | Audit event altered or enriched with payload data | T1, T10 | `AuditLogger` has no dependency on `SecretRecord` and emits exactly four fields (15, 35, 40) |
| Repudiation | Anonymous actions | T10 | `"anonymous"` is recorded honestly; identity is best-effort and never blocks the flow (19) |
| Info disclosure | PII over-collection; ephemeral keys reaching disk | T5, T10 | Only the account name is stored; ephemeral Data Protection provider (5); retention rules in the runbook (51) |
| Denial of service | Challenge blocks non-domain recipients | — | Only `/api/whoami` ever challenges; create/reveal read the cookie only (19) |

### C9. Logging and operations (B4, B5)

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Info disclosure | Request bodies, URLs, query strings, or exceptions in logs | T1, T5 | Framework HTTP logging silenced in code; hosting diagnostics ≥ Warning; JSON console only (6, 35) |
| Info disclosure | Crash dumps, swap, container volumes | T5 | Read-only root FS, no volumes, non-root chiseled image (48); memory zeroing (36) |
| Tampering | Log lines forged by user input | T1 | Structured logging with no user-controlled free text; Ids are fixed-alphabet 22-char strings |

### C10. Build and supply chain

| STRIDE | Threat | ID | Mitigation (task) |
|--------|--------|----|-------------------|
| Tampering | Malicious dependency or base image | T14 | Zero runtime JS dependencies; exact devDependency pins; lockfiles with locked restores (2, 43); Dependabot with CI gating (47); vulnerability scans, CodeQL, Trivy, SBOM (46, 48); signed images (53) |
| Tampering | Bundle changed without review | T7 | Recorded SHA-256 verified on every build; a stale hash fails the build (3) |

## Register Cross-Reference

| ID | Threat | Mitigation tasks | Test tasks |
|----|--------|------------------|------------|
| T1 | Server-side exposure of plaintext or key | 6, 8, 15, 21 | 35, 36 |
| T2 | Double-read race | 11, 12, 18 | 27, 28 |
| T3 | Id enumeration / brute force | 9, 20 | 29 |
| T4 | Pre-burn by scanners; CSRF on reveal | 17, 18, 22 | 31, 32 |
| T5 | Secret material reaching disk | 5, 6, 12, 14, 48, 50 | 28, 35 |
| T6 | DoS / memory exhaustion | 5, 13, 14, 16 | 39 |
| T7 | XSS via content; tampered bundle | 3, 4, 23 | 33, 34 |
| T8 | Transport / browser leakage | 4, 22 | 33, 42 |
| T9 | Cryptographic weakness | 9, 21, 23 | 36, 37 |
| T10 | Forged audit identity; PII | 15, 19, 51 | 40 |
| T11 | Rate-limit bypass via proxy headers | 20 | 30 |
| T12 | Malformed input / parser abuse | 10, 16 | 38 |
| T13 | Information disclosure via errors/headers | 5, 24 | 41 |
| T14 | Vulnerable or malicious dependencies | 2, 46, 47, 48, 53 | 43 |
| T15 | Deployment misconfiguration | 49, 50 | 49 |

## Residual Risks and Accepted Trade-offs

| Risk | Why it remains | Compensating control |
|------|----------------|----------------------|
| **Anyone who sees the share link can reveal the secret** | The link *is* the credential; the channel (B2) is outside the system | Exactly-once consumption plus a tombstone, so the intended recipient learns the secret was taken and treats it as compromised |
| **Compromised endpoint (sharer's or recipient's device, browser extension)** | The browser must hold A1 and A2 to do its job | Plaintext and key references dropped as soon as possible; no client-side persistence |
| **Purpose-built scanner that executes JS and clicks Reveal** | Indistinguishable from a human | Same tombstone tamper evidence; documented in the runbook |
| **Server memory scraping, swap, or core dumps expose ciphertext** | Process memory is not under the app's control | Ciphertext is useless without `K`; buffers zeroed promptly; hardened container, no volumes; TTL bounds exposure |
| **Tombstone vs. unknown are distinguishable (410 vs. 404)** | Deliberate: the recipient must be told when a secret was already taken | Only holders of a valid Id learn anything; Ids are 128-bit random |
| **Single instance: restart loses in-flight secrets; no horizontal scale** | Decided trade-off (architecture.md) | Runbook announces maintenance windows; TTLs are short |
| **Volumetric DoS beyond application rate limits** | Needs network-level mitigation | Out of scope; deployment docs point at the reverse proxy / CDN layer |
| **Windows identity is only as trustworthy as the domain** | A compromised domain account produces a "valid" audit identity | Audit log is evidence of accountability, not proof of intent; retention and review in the runbook |
| **Explicit TLS floor may age** | See Analyzer Suppressions below | Revisited at each dependency-update review |

## Test Convention

Every security test declares the threat it verifies, so coverage can be checked mechanically (plan task 26 adds
`scripts/check_threat_coverage.py`, which fails CI when any ID in the register above has no test).

**xUnit** — apply `[Trait("Threat", "T#")]` to the test class (when every test in it addresses the threat) or to
individual `[Fact]`/`[Theory]` methods. A class may carry several traits:

```csharp
[Trait("Threat", "T7")]
[Trait("Threat", "T8")]
public sealed class SecurityHeadersTests { … }
```

Run the tests for one threat with `dotnet test --filter "Threat=T4"`.

**vitest** — prefix the `describe` title with the ID in square brackets:

```ts
describe('[T9] client crypto', () => { … });
```

Rules:

- Use only IDs from the register; adding a threat means adding a row to `plan.md`, this document, and at least one
  test in the same change.
- A test cites the threat it *verifies*, not every threat it touches — a headers test cites T7/T8, not T1.
- Non-security tests (toolchain, smoke) carry no trait.
- A mitigation with no test is a gap; the coverage check makes it a build failure.

### Coverage Exceptions

A threat may sit here only while its mitigation does not yet exist, and only with the task that will cover it
named. `scripts/check_threat_coverage.py` tolerates these rows and **fails once the threat gains a test**, so an
exception cannot outlive its reason. Anything else uncovered fails the build.

| Threat | Covered by | Why it has no test yet |
|--------|------------|------------------------|

*(none — every threat in the register has a citing test.)*

## Analyzer Suppressions

Security-category analyzer rules (CA2100, CA3xxx, CA5xxx) are build errors. Each suppression must be justified in
code and recorded here.

| Rule | Location | Justification |
|------|----------|---------------|
| CA5398 (avoid hard-coded `SslProtocols`) | `src/OneShot.Web/Security/KestrelHardening.cs` `ConfigureHttps`; `tests/OneShot.Tests/KestrelHardeningTests.cs` `ConfigureHttps_AllowsOnlyTls12AndTls13` | The rule prefers `SslProtocols.None` so the OS picks versions, but an OS default can still admit TLS 1.0/1.1 on older hosts. T8 requires a TLS 1.2+ floor, so `Tls12 \| Tls13` is pinned explicitly and the test names the same values to lock it in. Revisit when TLS 1.4 or a deprecation of TLS 1.2 warrants a change. |
