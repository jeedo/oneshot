# OneShot

[![CI](https://github.com/jeedo/oneshot/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jeedo/oneshot/actions/workflows/ci.yml)
[![Security](https://github.com/jeedo/oneshot/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/jeedo/oneshot/actions/workflows/security.yml)
[![Release](https://github.com/jeedo/oneshot/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/jeedo/oneshot/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/jeedo/oneshot/badge)](https://scorecard.dev/viewer/?uri=github.com/jeedo/oneshot)

Share a secret through a link that works exactly once.

The sender's browser encrypts the secret, sends only the ciphertext, and puts the key in the link's fragment.
The server stores the ciphertext in memory, hands it over to the first caller that asks, and forgets it. It
never sees the key, so it cannot read what it is holding — and neither can anyone who takes its memory, its
logs, or its disk.

Every badge above reports something a machine checked. There is no badge here asserting that this project is
secure, because nothing could verify one.

## How it works

1. You paste a secret. The browser generates a 256-bit key and a 12-byte nonce and encrypts with AES-GCM via
   WebCrypto.
2. It posts **only** the ciphertext and nonce. The server assigns a 128-bit random Id and returns it.
3. You share `https://…/s/<id>#<key>`. Everything after `#` is a
   [fragment](https://developer.mozilla.org/en-US/docs/Web/URI/Fragment) — browsers never send it to a
   server, so the key never leaves the two people holding the link.
4. The recipient opens the link and presses Reveal. The server swaps the record for a tombstone in one atomic
   operation and returns the ciphertext; the browser decrypts it with the key from the fragment.
5. The next person to open that link is told it was already revealed. There is nothing left to hand over.

Opening the link does not consume the secret — only the explicit Reveal does. Link previews, scanners and
prefetchers cannot burn it.

## Security properties

| Property | How |
|---|---|
| The server never holds plaintext or the key | Encryption is in the browser; the key travels in the URL fragment. `OneShot.Web` never references `System.Security.Cryptography.Aes*`. |
| Nothing survives the process | A `ConcurrentDictionary` and an ephemeral Data Protection provider. No database, no cache, no volume, read-only root filesystem. |
| Read exactly once | One `ConcurrentDictionary.TryUpdate` compare-and-swap. Never a read followed by a delete. |
| Reads have no side effects | Only a same-origin `POST …/reveal` consumes, and it requires a header no form or prefetch can send. |
| Logs cannot leak the secret | Audit events carry exactly four fields and cannot reach a payload. Framework request logging is disabled in code, not configuration. |
| Unsafe deployments do not start | Outside `Development` the host validates the deployment it was configured with and refuses to start when it is unsafe. |

Read [`docs/threat-model.md`](docs/threat-model.md) for the STRIDE analysis and the residual risks this design
accepts — including the big one: **anyone who sees the link can read the secret.** The link is the credential.

## Running it

### Development

```bash
dotnet run --project src/OneShot.Web   # http://localhost:5000
```

`Properties/launchSettings.json` sets `Development`, the only environment where `DeploymentValidator` (below)
is skipped — this is the form to use for ordinary local work, testing from another device on the same
network, or passing `--urls`.

### Production

The shape it's actually meant to run in — TLS terminated in front of it, or served directly over HTTPS. The
container, with the same flags [`docs/deployment.md`](docs/deployment.md) documents in full:

```bash
docker build -f Containerfile -t oneshot .
docker run --read-only --tmpfs /tmp -p 8080:8080 \
  -e ForwardedHeaders__KnownProxies__0=127.0.0.1 oneshot
```

Outside `Development`, `DeploymentValidator` refuses to start the host at all if the deployment is unsafe —
most commonly because only plain-HTTP addresses are configured with no trusted proxy declared. To see the
refusal itself, `--no-launch-profile` is required — otherwise `launchSettings.json`'s own `Development`
setting wins and the refusal never triggers:

```bash
dotnet run --project src/OneShot.Web --no-launch-profile --urls http://localhost:5055
```

The log line names the exact condition that failed.

## Verifying a release

Images are published to `ghcr.io/jeedo/oneshot` and signed **keyless**: there is no private key anywhere in
this repository, and the signature is bound to the release workflow's own identity. Verify by digest — a tag
can be repointed at different bytes later:

```bash
cosign verify ghcr.io/jeedo/oneshot@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/jeedo/oneshot/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The SBOM for that digest is attached to the matching GitHub Release as `sbom.spdx.json`, itself signed the same
keyless way as `sbom.spdx.json.sigstore.json`:

```bash
cosign verify-blob --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/jeedo/oneshot/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom.spdx.json
```

## Documentation

| | |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | The design and the trade-offs it commits to |
| [`docs/threat-model.md`](docs/threat-model.md) | STRIDE per component, the T1–T15 register, residual risks |
| [`docs/plan.md`](docs/plan.md) | The threat register and the numbered task list |
| [`docs/deployment.md`](docs/deployment.md) | Linux, container and Windows deployment; TLS; branch protection |
| [`docs/runbook.md`](docs/runbook.md) | Restart semantics, audit retention, incident steps |
| [`docs/security-review.md`](docs/security-review.md) | ASVS 4.0 L2 walk, threat-register walk, findings and sign-off |
| [`docs/research.md`](docs/research.md) | The existing tools this design learned from |

## Building and testing

```bash
dotnet build OneShot.sln                       # warnings and security analyzers are errors
dotnet test OneShot.sln                        # unit and integration tests
npm --prefix src/OneShot.Web/Client run check   # typecheck, vitest, bundle
npm --prefix tests/e2e run check                # Playwright, against a self-started app
```

Every security test names the threat it covers, and `scripts/check_threat_coverage.py` fails the build if any
threat in the model loses its test. [`CLAUDE.md`](CLAUDE.md) has the full set of local checks.

## License

[Apache License 2.0](LICENSE).
