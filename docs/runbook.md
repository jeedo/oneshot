# Runbook

> **Status**: Active — covers plan task 51. Read alongside [`deployment.md`](deployment.md) (how to stand the
> app up), [`architecture.md`](architecture.md) (why it is shaped this way) and
> [`threat-model.md`](threat-model.md) (T10 and the residual risks).

This is the operating half of `deployment.md`: what to expect once OneShot is running, what its logs do and do
not contain, and what to do when something has gone wrong. Two properties drive almost everything below.

- **Nothing survives the process.** The store is a `ConcurrentDictionary` and the Data Protection provider is
  ephemeral. There is no disk, no cache, no replica.
- **The server never had the secret.** Plaintext and the key exist only in the browser; the key travels in the
  URL fragment, which is never sent to the server. No incident response step can recover a secret's contents,
  because nothing on the server ever held them.

## Health and Capacity Signals

`GET /healthz` returns 200 as soon as the host is up; it is rate-limit exempt and safe to poll. It reports
liveness only — it does not touch the store, so it stays 200 while the store is at capacity.

Everything else comes from stdout. `LoggingHardening` (`src/OneShot.Web/Security/LoggingHardening.cs`) clears
the default providers and installs the JSON console writer with UTC timestamps, so each line is one JSON
object for whatever collects container output. The lines worth alerting on:

| Signal | Source | What it means |
|---|---|---|
| `Evicted {Count} expired secret entries` | `ExpirySweeperService` | Routine. The sweeper runs every 30 s (`Sweeper:Period`) and scans up to 10,000 entries per pass. |
| `Expiry sweep failed; the next pass will run as scheduled` | `ExpirySweeperService` | Not routine. The store keeps expired entries until a pass succeeds; investigate rather than wait. |
| A 503 with `Retry-After: 30` on `POST /api/secrets` | `SecretsApi` | The store hit `MaxEntries` (10,000) or `MaxTotalCiphertextBytes` (64 MiB). See deployment.md's "Memory Limits". |
| The host exits immediately at startup | `DeploymentValidator` | Outside `Development` the deployment was judged unsafe (T15). The log line names the failing condition; fix that, do not set `ASPNETCORE_ENVIRONMENT=Development` to get past it. |

Sustained capacity rejections are the signal that `MaxEntries` / `MaxTotalCiphertextBytes` no longer match the
load, or that senders are choosing long TTLs — the maximum is 7 days, the default 1 hour. Both are
configuration (`SecretStore__MaxEntries`, `SecretStore__MaxTotalCiphertextBytes`); raising them means raising
the process memory limit alongside.

## Restart Semantics

**Every secret that has not yet been revealed is destroyed by a restart.** This is the design, not a fault —
it is the direct consequence of the in-memory store, and the property that makes "the server holds nothing
past a restart" true. It applies identically to a planned deployment, a container reschedule, an OOM kill, an
IIS app-pool recycle, and a crash.

What a restart destroys:

- Every `Available` secret. A recipient holding a link now gets the 404 that an expired or never-existed Id
  gives, where a moment earlier the same link reported `available`.
- Every tombstone. A consumed Id answers `200` with state `consumed` only while its tombstone is in memory;
  after a restart it is indistinguishable from an Id that never existed, and answers 404 too. No secret is
  exposed either way — a restart makes the store's answers *less* revealing, not more.
- Every identity cookie. They are signed with the ephemeral Data Protection keys, which are regenerated on
  start, so cookies issued by the old process no longer validate. Holders are silently treated as anonymous
  until they revisit `/api/whoami`; nothing fails and nothing is blocked.

Operational consequences:

- **Announce maintenance windows.** Senders cannot tell in advance that their link is about to stop working,
  and there is no way to drain: a graceful shutdown still ends the process, and the secrets go with it. Give
  users enough notice to re-share after the restart.
- **Prefer short TTLs.** The shorter the default, the smaller the population a restart can strand.
- **Do not add instances to get availability.** A second instance does not share the store; a recipient
  load-balanced to the wrong one gets a 404. If a deployment needs more than one instance, it needs sticky
  routing at minimum — and see architecture.md's "Single-instance deployment" trade-off before going further.
- **Nothing needs recovering afterwards.** There is no state to repair, no migration to run, no cache to warm.
  A restarted OneShot is a correct OneShot.

## Audit Log Retention

`AuditLogger` (`src/OneShot.Web/Audit/AuditLogger.cs`) writes exactly one event per create and per reveal, at
`Information`, under the category `OneShot.Web.Audit.AuditLogger` with `EventId` 1001 (create) and 1002
(reveal). Each event carries exactly four fields and has no way to carry a fifth — the type has no dependency
on `SecretRecord`, so it cannot reach a payload even by mistake (T1, T10):

| Field | Example | Notes |
|---|---|---|
| `timestampUtc` | `2026-09-16T04:57:19.412Z` | Always UTC. |
| `action` | `create` / `reveal` | Nothing else is emitted. |
| `secretId` | the opaque Id | Identifies the secret, never its contents. |
| `windowsUser` | a Windows account name, or `anonymous` | The only personal data in the system. |

**What is never in any log, at any level**: plaintext, ciphertext, nonces, keys, request bodies, or full URLs.
That is enforced, not merely intended — `LoggingHardening` sets `Microsoft.AspNetCore.HttpLogging` to `None`
and `Microsoft.AspNetCore.Hosting.Diagnostics` to `Warning`, because both would otherwise print URLs, headers
and bodies. **Neither filter may be relaxed by configuration** (T1, T5). The decryption key is never at risk
from logging in the first place: it lives in the URL fragment, which browsers do not send.

Retention is a deployment decision, because the app itself retains nothing — it writes to stdout and forgets.
Whatever collects that output owns retention, and should be set deliberately:

- **Pick a bounded retention period and configure it explicitly.** The audit trail exists to answer "who
  revealed this secret, and when" during an investigation. Weeks to a small number of months is usually the
  right order; indefinite retention turns a non-repudiation control into an accumulating store of personal
  data. Match whatever period the organisation's own retention policy sets for access logs.
- **Restrict who can read it.** The audit trail names people and what they did. Treat it as access-controlled
  operational data, not general application logs.
- **Do not route it anywhere with weaker controls** to make it easier to search.
- **Make the collector's own storage durable and tamper-evident** if repudiation matters to you. OneShot
  provides the event; it cannot protect a log after handing it to stdout.

## PII and Windows Account Names

`windowsUser` is the only personal data OneShot handles, and it is deliberately the narrowest useful field: an
account name, and nothing else. No email address, no display name, no group membership, no IP address, no user
agent.

How it is obtained (plan tasks 19 and 40, T10):

- Identity is **best-effort and never blocks a flow**. OneShot does not challenge on create or reveal.
- A user who visits `GET /api/whoami` gets a Negotiate challenge; on success the app sets a 5-minute identity
  cookie (`HttpOnly; Secure; SameSite=Strict; Path=/api`) holding only the account name.
- Create and reveal read identity from that cookie only. Missing, expired, tampered, or signed with another
  process's keys all resolve to `anonymous` with no error.
- `anonymous` is recorded **honestly**. It means "not verified", not "nobody". It is the expected value for
  most events in most deployments, and a log full of it is not a misconfiguration to fix.

For handling:

- Treat the audit trail as personal data for the purposes of whatever regime applies (GDPR and equivalents).
  The lawful basis is ordinarily the legitimate interest in an access audit trail for a secret-sharing system;
  confirm that with whoever owns data protection rather than assuming it.
- **Tell users the audit trail exists.** That an account name is recorded when a secret is created or revealed
  belongs in the same notice that covers other access logging.
- **Bounded retention is the main control** — see above. It is also, in practice, how an erasure request is
  satisfied, since individual events cannot be selectively deleted from a log the app no longer holds.
- **Do not enrich it.** Resolving account names to full directory identities in the log pipeline recreates
  exactly the over-collection (T10) the four-field event was shaped to avoid.

## Suspected Compromise

"Compromise" here means the host, the image, the TLS material, or an operator account — not a leaked secret
link. A leaked link needs no incident response: the secret is one-shot, and the audit trail shows whether a
reveal happened (an `action: reveal` event for that Id) and, if identity was verified, who did it.

**Establish first that nothing can be decrypted from what was taken.** The server holds ciphertext, nonces, and
Ids. It has never held a key or any plaintext. An attacker with a complete memory dump of the process, the
container filesystem, and every log line still cannot read a single secret without the fragment from a link.
Say this explicitly in the incident record — it is the difference between a confidentiality breach and a
service compromise, and the ephemeral, no-persistence design is what makes it true.

Then, in order:

1. **Take the instance out of rotation.** Stop it or pull it from the load balancer. Every in-flight secret is
   destroyed by doing so, which is the correct outcome under suspicion and needs no deliberation — see
   "Restart Semantics".
2. **Preserve the logs before they rotate.** They are the only evidence that survives the process. Everything
   else — store contents, tombstones, Data Protection keys — is gone the moment it stops.
3. **Rotate the TLS certificate and key.** Assume the private key was exposed if the host or image was. Issue
   a new key pair, deploy the new certificate, and revoke the old certificate so a held key cannot be used
   against clients that still trust it. Data Protection keys need no rotation step: they are ephemeral and are
   replaced by the restart in step 5.
4. **Review the audit events** for the window of exposure. Look for reveals with no corresponding create,
   reveals long after their create, a single account revealing many secrets, or a run of `anonymous` reveals
   where the deployment normally verifies identity. Remember what the events cannot tell you: the trail proves
   *that* a secret was revealed, never *what* it contained.
5. **Redeploy from a clean image**, rebuilt from a known-good commit — never by restarting the suspect
   container. `Containerfile`'s chiselled base has no shell and no package manager, so persistence inside a
   running container is hard; it is not a reason to reuse one. Confirm the CI security jobs (CodeQL, the
   dependency and secret scans, the image scan) were green for the commit being deployed.
6. **Tell the users whose secrets were in flight.** They cannot tell a destroyed secret from a revealed one,
   and they need to know to re-share — and to rotate the underlying credential if a reveal they did not expect
   appears in the trail.
7. **Record the outcome**, including the reasoning from "establish first" above and which of the four audit
   fields actually informed the investigation.

If the compromise is suspected in a **dependency or the supply chain** rather than the host, the first move is
different: check whether the advisory affects a package this app actually ships. `OneShot.Web` carries a
deliberately tiny runtime surface, pinned by `packages.lock.json` and asserted by `SupplyChainTests`, and the
client has no runtime dependencies at all. `python3 scripts/check_supply_chain.py` answers the question
directly, and the scheduled security workflow runs it weekly against current advisories.
