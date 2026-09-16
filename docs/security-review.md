# Pre-Release Security Review

> **Status**: Complete — covers plan task 52.
> **Commit reviewed**: `fb8d37d` (`main`, task 51).
> **Date**: 2026-09-16.
> **Outcome**: Sign-off **conditional** — one release blocker, which is a CI re-run rather than a code change.
> See [Findings](#findings) and [Sign-off](#sign-off).

## Scope and Method

**In scope**: the whole of `src/OneShot.Web` (1,656 lines of C# across `Api`, `Audit`, `Secrets`, `Security`,
`Pages` and `Program.cs`), the TypeScript client in `src/OneShot.Web/Client/src`, the Razor pages, the
`Containerfile`, and the CI and security workflows.

**Method**, in this order:

1. Read every source file in `src/OneShot.Web` against OWASP ASVS 4.0 Level 2, chapter by chapter, recording
   applicability before verdict — a requirement that cannot apply to this design is recorded as such rather
   than silently passed.
2. Walked the fifteen-entry threat register in [`plan.md`](plan.md) against the implementation *and* against
   the test that cites it, so that a mitigation with no live test would show up.
3. Ran the full gate suite locally and read the CI result for the reviewed commit.
4. Verified each claimed finding against a primary source before recording it.

**Not in scope, and not implied by the sign-off below**:

- This is an internal review, not a certified ASVS assessment. ASVS 4.0 L2 has several hundred individual
  requirements; they were assessed by chapter against this design, not signed off one by one.
- No penetration test and no cryptanalysis was performed. The cryptographic claim rests on using AES-256-GCM
  through the platform WebCrypto implementation in the standard way, not on independent analysis.
- The deployment an operator actually builds is out of scope — see [`deployment.md`](deployment.md) and
  [`runbook.md`](runbook.md). This review covers what the code and pipeline guarantee, not what a given host
  is configured to do.

The two facts every section below rests on: **the server never holds a key or any plaintext**, and **nothing
survives the process**.

## ASVS 4.0 Level 2

| Chapter | Applicability | Verdict | Evidence |
|---|---|---|---|
| **V1** Architecture & Threat Modeling | Full | Met | `architecture.md`; `threat-model.md` carries STRIDE per component; a 15-threat register; every security test cites a threat ID and `check_threat_coverage.py` fails the build if one loses its test. |
| **V2** Authentication | Mostly N/A | Met where it applies | No credential store, no passwords, no recovery flow, no MFA surface — so V2.1–V2.9 largely do not apply. The only authentication is opportunistic Negotiate at `GET /api/whoami`, used **solely for audit attribution**; it never gates access, and failure degrades to `anonymous` rather than denying. |
| **V3** Session Management | Partial | Met | There is no application session. The identity cookie is the only session-like artifact: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api`, 5-minute absolute expiry, `SlidingExpiration=false`, signed with ephemeral Data Protection keys (`IdentityCookie.cs`). Termination (V3.3) is absolute: a restart invalidates every cookie ever issued. |
| **V4** Access Control | Narrow | Met | Authorization is possession of a 128-bit Id. There is no user-owned object graph, so the usual IDOR surface does not exist — there is nothing to enumerate *between* users. `GET` is side-effect free by construction (`Peek` only ever calls `Peek`); only the same-origin `POST …/reveal` consumes. |
| **V5** Validation, Sanitization & Encoding | Full | Met | Strict JSON (`UnmappedMemberHandling.Disallow`, `MaxDepth = 8`, `NumberHandling.Strict`, no duplicate properties, no comments, no trailing commas). `Base64UrlStrict` accepts only canonical unpadded base64url and proves it by re-encoding and comparing, so each byte sequence has exactly one accepted spelling. `SecretId.IsValid` pins length, alphabet **and** the four canonical final characters. Output is rendered with `textContent`, never `innerHTML`. |
| **V6** Stored Cryptography | Full | Met | AES-256-GCM via WebCrypto in the browser; 32-byte key and per-secret 12-byte nonce from `crypto.getRandomValues`; keys imported non-extractable. Ids from `RandomNumberGenerator.Fill` (128-bit CSPRNG). Buffers zeroed with `CryptographicOperations.ZeroMemory` on every rejection and consume path. **The server holds no key material at all** — `OneShot.Web` is asserted never to reference `System.Security.Cryptography.Aes*`. |
| **V7** Error Handling & Logging | Full | Met | One fixed error document in every environment — no stack, no exception type, no internal message, nothing echoed from the request. `BadHttpRequestException` maps to its own 4xx and is suppressed from error logging, so an oversized body cannot be used to fill the log. Audit events carry exactly four fields and the type cannot reach a payload. |
| **V8** Data Protection | Full | Met | In-memory store only; ephemeral Data Protection provider unconditionally; no volumes and a read-only root filesystem; `Cache-Control: no-store` and `Pragma: no-cache` on secret paths; `Referrer-Policy: no-referrer`. The key travels in the URL fragment, which browsers never transmit. |
| **V9** Communication | Full | Met | TLS floor pinned to 1.2/1.3 (`KestrelHardening`; CA5398 suppressed with a stated reason and a matching threat-model entry). HSTS 365 days, `includeSubDomains`, `preload`. `UseHttpsRedirection`. Startup validation refuses to run a non-Development deployment that is plain HTTP with no declared proxy. |
| **V10** Malicious Code | Full | Met | Zero runtime JS dependencies; devDependencies pinned exactly; lock files with locked restore on CI. The single first-party bundle is pinned by SRI **and** a CSP `script-src` hash, and a stale recorded SHA-256 fails the build. CodeQL (`security-and-quality`), gitleaks over full history, Trivy on the image, Dependabot across five ecosystems. |
| **V11** Business Logic | Full | Met | The core rule is one atomic compare-and-swap: `TryConsume` swaps the record for its tombstone via `ConcurrentDictionary.TryUpdate`, so exactly one caller can win and no caller observes a gap. Rate limits on create and read, partitioned per client (IPv6 bucketed on /64). |
| **V12** Files & Resources | N/A | Not applicable | No upload, no download, no file-system access, and no path is ever constructed from user input. Static files are the app's own bundle and stylesheet. |
| **V13** API & Web Service | Full | Met | JSON only, `HasJsonContentType()` enforced. Methods constrained on every endpoint including the Razor pages, so TRACE and OPTIONS get 405 with `Allow` rather than a rendered page. Reveal additionally requires a custom header no form or prefetch can send, plus `Sec-Fetch-Site`/`Origin` agreement. Errors are `problem+json` with stable machine-readable codes. |
| **V14** Configuration | Full | Met | `ValidateOnStart` refuses an unsafe deployment outright (T15). Security headers are applied on every response *including* the error path, where the pipeline would otherwise drop them. `AddServerHeader = false`. Security analyzers (CA2100, CA3xxx, CA5xxx) are build errors, and the one suppression is documented in code and in the threat model. Container is non-root, chiselled, shell-less. |

One observation that is a design decision rather than a gap: **`Peek` deliberately distinguishes `consumed`
(200) from `unknown` (404)**. This leaks one bit to a holder of a valid 128-bit Id, and it is the point — the
recipient must learn that a secret was already taken. It is recorded as an accepted residual risk in the
threat model, and this review confirms it was a decision and not an oversight.

## Threat Register

Each threat was checked twice: that the mitigation exists in the code, and that a live test cites it.

| ID | Threat | Implementation | Verdict |
|---|---|---|---|
| T1 | Server-side exposure of plaintext or key | Encryption is browser-side; `AuditLogger` has no path to a payload; HTTP logging silenced | Mitigated |
| T2 | Double-read race | Single `TryUpdate` compare-and-swap; concurrency stress tests | Mitigated |
| T3 | Id enumeration / brute force | 128-bit CSPRNG Ids, canonical-form validation, read rate limit | Mitigated |
| T4 | Pre-burn by scanners; CSRF on reveal | `GET` never consumes; reveal needs a custom header plus origin agreement; methods constrained | Mitigated |
| T5 | Secret material reaching disk | Ephemeral DP provider; no volumes; read-only rootfs; buffer zeroing | Mitigated |
| T6 | DoS / memory exhaustion | `MaxEntries`, `MaxTotalCiphertextBytes`, body and header limits, rate limits, capacity 503 | Mitigated |
| T7 | XSS via content; tampered bundle | CSP `default-src 'none'` with a script hash; `textContent` rendering; SRI; build-enforced bundle hash | Mitigated |
| T8 | Transport / browser leakage | TLS 1.2+ floor, HSTS preload, `no-store`, `no-referrer`, key confined to the fragment | Mitigated |
| T9 | Cryptographic weakness | AES-256-GCM, per-secret nonce, non-extractable keys, CSPRNG throughout | Mitigated |
| T10 | Forged audit identity; PII | Identity only from a Negotiate handshake via a signed 5-minute cookie; exactly four audit fields; retention rules in the runbook | Mitigated |
| T11 | Rate-limit bypass via proxy headers | Forwarded headers honoured only from declared known proxies | Mitigated |
| T12 | Malformed input / parser abuse | Strict JSON options, canonical base64url, fuzzing and property tests | Mitigated |
| T13 | Information disclosure via errors/headers | One fixed error document everywhere; no `Server` header; rejected requests not logged at Error | Mitigated |
| T14 | Vulnerable or malicious dependencies | Lock files, locked restore, Dependabot, CodeQL, gitleaks, Trivy, SBOM, pinned actions | Mitigated — see F1 |
| T15 | Deployment misconfiguration | `DeploymentValidator` refuses to start an unsafe host | Mitigated |

`check_threat_coverage.py` confirms **15 of 15** threats have at least one citing test. No threat in the
register is carried by documentation alone.

## Security CI Results

**Local gate suite**, run at the reviewed tree in `Release`:

| Gate | Result |
|---|---|
| `dotnet build` (warnings and security analyzers as errors) | 0 warnings, 0 errors |
| `dotnet test` | **546 passed**, 0 failed, 0 skipped |
| `dotnet format --verify-no-changes` | clean |
| Coverage gate (`check_coverage.py`) | `Api` 98.7 % lines / 89.7 % branches · `Audit` 96.7 / 94.4 · `Secrets` 98.8 / 96.3 · `Security` 100.0 / 98.5 — all above the 90 / 85 gate |
| Client (`tsc`, vitest, esbuild) | **71 passed** across 11 files |
| End-to-end (Playwright, real Kestrel + Chromium) | **59 passed** |
| Script tests | **65 passed** |
| `check_threat_coverage.py` | 15 of 15 |
| `check_supply_chain.py` | no vulnerable packages, no unpinned versions, every project locked |
| gitleaks 8.30.1 over full history | 105 commits scanned, **no leaks found** |

**CI on the reviewed commit** (`fb8d37d`), Security workflow run
[35058935105](https://github.com/jeedo/oneshot/actions/runs/35058935105): **5 of 6 jobs green; 1 failed.**

- Green: CodeQL (csharp), CodeQL (javascript-typescript), Dependency advisories, Secret scanning (gitleaks),
  ZAP baseline.
- Failed: **Container (build, Trivy, SBOM)** — see F1. The failure is an upstream registry outage, not a
  finding against this commit, but the release gate is red and that is what matters for sign-off.

## Findings

Nothing in this review requires a change to application code. The one blocker is a pipeline re-run.

### F1 — Release blocker (process): the security gate is red on the release commit

The Container job failed with `unexpected status from HEAD request to https://mcr.microsoft.com/... 503
Service Unavailable` while resolving the SDK base image. This is an upstream registry outage.

It is demonstrably not caused by the reviewed commit: `git diff --name-only 86c2346 fb8d37d` lists only
`CLAUDE.md`, `docs/plan.md`, `docs/runbook.md`, `scripts/check_docs.py` and `scripts/test_check_docs.py`.
None of the container build's inputs changed, and the same job passed on the immediately preceding commit.

**A release must not ship on a red security gate regardless of cause**, so this must be re-run to green
before tagging. I could not trigger the re-run myself — the API returned 403 `Resource not accessible by
integration`. **Action required by a maintainer**: re-run the failed job on run 35058935105 and confirm green.

**Recommendation for task 53**: registry pulls are a third-party dependency of the release gate. A retry
around the image pull would stop an upstream blip from reading as a security failure — and, more importantly,
from tempting someone into waving one through.

### F2 — Low: cross-origin isolation headers are not set

`SecurityHeaders.cs` sets CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and
`Permissions-Policy`, but no `Cross-Origin-Opener-Policy`, `-Embedder-Policy` or `-Resource-Policy`. ZAP
reports this as rule 90004 and it is already recorded in `.github/zap-rules.tsv`.

This is the only item in the review that points at a control that is absent rather than deliberately declined.
`COOP: same-origin` is the one worth having: it severs an opener's window reference to a page that renders
plaintext. Recommended as its own task with a threat-model row and header tests — deliberately **not** folded
into this review, since changing what the app sends is not a reviewer's edit.

### F3 — Low, accepted: rate-limit budgets are per-process and reset on restart

Rate limiting is an in-memory fixed-window limiter partitioned per client. Budgets are per-instance and are
reset by any restart, so the T3 and T6 rate-limit mitigations are briefly at full budget after every deploy.
This is consistent with the single-instance design and is not worth adding shared state for — 128-bit Ids
make enumeration infeasible independently of the limiter, which is the control actually carrying T3. Recorded
so it is a known property rather than a surprise.

### F4 — Informational: branch protection is not yet in place

`.github/dependabot.yml` states that "branch protection requires those checks before merge and there is no
auto-merge — a person still approves." Enabling branch protection is plan task **53**, which is not yet done,
so that comment describes the intended end state rather than an enforced one. Not a defect — the tasks are
simply in this order — but the claim should not be read as a control that exists today.

### F5 — Informational, corrected here: stale comment in `dependabot.yml`

The `docker` entry carried "No Dockerfile exists yet (plan task 48); this entry starts working the day one
lands at the repo root." Task 48 landed `Containerfile`, so the comment is out of date. Corrected in this
change.

I checked the adjacent concern — whether Dependabot's `docker` ecosystem finds a file named `Containerfile`
at all, given both base images are digest-pinned and would otherwise never be updated. **It does**: support
was added in [dependabot-core#11141](https://github.com/dependabot/dependabot-core/pull/11141), merged
December 2024. No finding.

### F6 — Informational: chapters recorded as not applicable

ASVS **V12** (Files and Resources) is recorded as not applicable, and most of **V2** (Authentication) with it.
This is a property of the design — no upload, no download, no path built from user input, no credential store
— not a gap in the review. Recorded explicitly so a later reader does not mistake "not assessed" for "not
done", and so that adding any file handling or real authentication is understood to reopen a chapter this
review closed by inapplicability.

## Sign-off

**Conditional pass.**

The implementation is signed off. Every one of the fifteen registered threats is mitigated in code and carried
by a live test; ASVS 4.0 L2 is met in every chapter that applies to this design; the full local gate suite is
green, including 546 unit and integration tests, 59 browser tests, 71 client tests, the coverage gate, the
supply-chain scanners and a clean gitleaks pass over the entire history. **No application code change is
required to release.**

Release is nonetheless **blocked on F1** until the Security workflow is green on the commit being tagged. The
failure is an upstream registry 503 and not a defect in this commit, and the evidence for that is recorded
above — but "we know why it is red" is not the same as green, and a release gate that gets waved through once
stops being a gate. Re-run it; if it passes, this sign-off stands as written with no further review needed.

F2 (cross-origin isolation headers) is the one open recommendation against the application itself and should
be scheduled; it does not block this release. F3, F4 and F6 are recorded properties, not work items. F5 is
corrected in this change.

Re-review is required if: any file handling, credential store, or real authorization is added; the store gains
persistence or is shared between instances; the CSP, the bundle-integrity chain, or `TryConsume`'s atomicity
changes; or the threat register gains an entry.

| | |
|---|---|
| **Reviewed commit** | `fb8d37d` |
| **Review date** | 2026-09-16 |
| **Method** | ASVS 4.0 L2 chapter walk + threat-register walk + full gate suite |
| **Blocking findings** | 1 (F1, process — CI re-run) |
| **Non-blocking findings** | 1 recommendation (F2), 4 informational (F3–F6) |
| **Outcome** | Conditional pass — release when F1 is green |
