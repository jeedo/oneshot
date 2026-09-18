# Deployment

> **Status**: Active — covers plan task 50. Read alongside [`architecture.md`](architecture.md) (design and
> trade-offs) and [`threat-model.md`](threat-model.md) (T5, T15 and the residual risks below).

OneShot is a single ASP.NET Core instance with an in-memory secret store (see architecture.md's "Single-instance
deployment" trade-off) — there is no database, cache, or shared backend to provision. Deployment is mostly about
getting TLS, the reverse-proxy trust boundary, and the container/host hardening right; the application itself
needs no persistent storage anywhere.

Outside `Development`, `DeploymentValidator` (`src/OneShot.Web/Security/DeploymentValidation.cs`, plan task 49,
T15) refuses to start the host at all if the deployment is unsafe — most commonly because no HTTPS address is
configured and no trusted proxy is declared. Every configuration below is shaped to satisfy that check; if the
app exits immediately on startup, its log line names exactly which condition failed.

## Linux and Container Deployment

The `Containerfile` at the repository root (plan task 48, T5, T14) builds a two-stage image: a full SDK build
stage, and a final `mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled` stage with no shell, no package
manager, and nothing beyond the published app. It runs as a non-root user (`USER $APP_UID`), declares no
`VOLUME`, and is meant to run with a read-only root filesystem — nothing the app does writes anything to disk
that needs to survive a restart.

The tested, working invocation (verified locally with both Docker and Podman against the built image):

```bash
docker run -d --name oneshot \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --memory=256m \
  -p 8080:8080 \
  -e ForwardedHeaders__KnownProxies__0=127.0.0.1 \
  oneshot:latest
```

- `--read-only` plus a `tmpfs` for `/tmp`: the app needs no persistent scratch space, but a memory-backed
  `/tmp` covers whatever the .NET runtime itself wants transiently. A `tmpfs` never touches disk and is wiped
  on container stop, so it does not reopen the door `--read-only` closes (see "No Persistence Layer" below).
- `ForwardedHeaders__KnownProxies__0=127.0.0.1` stands in for a TLS-terminating reverse proxy running as a
  sidecar or on the same host's loopback interface. In a real deployment this is the actual address (or CIDR,
  via `ForwardedHeaders__KnownNetworks__0`) of whatever terminates TLS in front of the container — see "TLS
  Certificates" below for the two ways to satisfy this requirement.
- The image's `HEALTHCHECK` calls the app's own `--healthcheck` switch
  (`src/OneShot.Web/Api/HealthCheckProbe.cs`) rather than `curl`/`wget`, because the chiseled image has
  neither. `docker inspect --format='{{.State.Health.Status}}' oneshot` reports `healthy` once `/healthz`
  responds; `security.yml`'s `container` CI job runs this exact check on every build.
- Set `--memory` to bound the container's total footprint — see "Memory Limits" below for how the app's own
  caps relate to it.

A plain (non-containerized) Linux deployment behind a reverse proxy (nginx, Caddy, a cloud load balancer) needs
the same `ForwardedHeaders__KnownProxies__0`/`KnownNetworks__0` configuration and no HTTPS binding of its own;
Kestrel serves plain HTTP on the loopback interface, and the proxy is the one holding the TLS certificate.

## Windows Deployment

Windows hosting exists for one reason: `Microsoft.AspNetCore.Authentication.Negotiate` (plan task 19, T10) lets
the app capture the caller's Windows account name for the audit log when the client and server are both on a
network that negotiates Kerberos/NTLM. It is best-effort and never required — anonymous requests always still
work, on any platform. There are two supported shapes.

### IIS, with Windows Authentication and Anonymous both enabled

When hosted behind IIS with the ASP.NET Core Module (in-process hosting), IIS's own Windows Authentication
feature is what actually performs the Kerberos/NTLM handshake; it then forwards the resulting Windows token to
the ASP.NET Core Negotiate middleware running inside the worker process. Both of IIS's authentication features
must be enabled together in the site's `web.config`/IIS Manager settings:

```xml
<location path="." >
  <system.webServer>
    <security>
      <authentication>
        <anonymousAuthentication enabled="true" />
        <windowsAuthentication enabled="true" />
      </authentication>
    </security>
  </system.webServer>
</location>
```

- **Anonymous must stay enabled.** OneShot's create and reveal pages must load for recipients who are not
  domain-joined or not on a network that negotiates Windows Authentication — IIS-level anonymous access is what
  lets those requests reach the app at all. Disabling it would make Windows Authentication mandatory for every
  request, which contradicts the "never required" design (architecture.md, "Optional authentication").
- **Windows Authentication enabled lets the token reach the app**, but the app itself decides whether to
  challenge — only `GET /api/whoami` does, per the Negotiate middleware configuration. IIS should not be
  configured to force a 401 challenge on the whole site.
- TLS still terminates the same way as any other reverse-proxy shape: either bind an HTTPS site binding
  directly in IIS with a certificate (see "TLS Certificates"), or terminate TLS upstream of IIS and set
  `ForwardedHeaders__KnownProxies` to that upstream's address.

### Kestrel-only Negotiate on a domain-joined host

Without IIS, Kestrel's own `Microsoft.AspNetCore.Authentication.Negotiate` handler performs the handshake
directly, using the operating system's SSPI/GSSAPI credential store. This requires:

- The host machine is domain-joined (Kerberos needs a domain controller to validate against; without one,
  Negotiate silently falls back to NTLM, which still works but loses mutual authentication).
- A Service Principal Name (SPN) is registered for the hostname the app is reached at, bound to whichever
  account the process runs as:
  ```
  setspn -A HTTP/oneshot.example.corp DOMAIN\svc-oneshot
  ```
  If the process runs as the machine account itself (e.g. as a Windows Service under `LocalSystem`) and is
  reached by the computer's own hostname, the machine account's implicit SPN already covers it and no explicit
  `setspn` is needed — registration is only required for a custom hostname/CNAME or a dedicated service
  account.
- A missing or mismatched SPN does not break the app: Negotiate simply never succeeds, every caller is treated
  as anonymous, and the audit log records `"anonymous"` instead of an account name. There is no user-visible
  failure to diagnose against — only "the audit log never shows real names," which is why the SPN is worth
  getting right rather than something that announces its own breakage.

## TLS Certificates

`DeploymentValidator` requires either an HTTPS address or a declared trusted proxy outside `Development`
(T15) — exactly one of these two shapes, never neither:

1. **Kestrel terminates TLS directly.** Configure a certificate the standard ASP.NET Core way (`appsettings.json`
   `Kestrel:Certificates:Default:Path`/`Password`, a Windows certificate store binding, or `ASPNETCORE_Kestrel__Certificates__Default__Path`/`__Password` environment variables) and bind an `https://` URL. `KestrelHardening`
   (`src/OneShot.Web/Security/KestrelHardening.cs`, T8) pins the floor to TLS 1.2/1.3 regardless of the OS
   default, and `AddHsts` (`Program.cs`) sets a 365-day `max-age` with `includeSubDomains` and `preload` — do
   not lower either without updating the corresponding tests (`KestrelHardeningTests`, the T7/T8 headers tests).
2. **A reverse proxy or load balancer terminates TLS**, and Kestrel serves plain HTTP on a loopback or
   container-internal address. Declare the proxy's address (or CIDR) via `ForwardedHeaders__KnownProxies__0`
   (a single IP) or `ForwardedHeaders__KnownNetworks__0` (a CIDR range) so `X-Forwarded-For`/`X-Forwarded-Proto`
   are honored from that source only — an undeclared, forged header is never trusted (T11). This is the shape
   used by the container invocation above and by IIS with an upstream TLS-terminating load balancer.

Certificate renewal (an internal CA, ACME/Let's Encrypt, or a cloud load balancer's managed certificate) is an
operational detail outside the app's configuration surface either way — OneShot never reads or validates a
certificate itself beyond what Kestrel or the proxy does.

## Memory Limits

The in-memory secret store is bounded by `SecretStoreOptions` (`src/OneShot.Web/Secrets/SecretStoreOptions.cs`,
T6): `MaxEntries` (default 10,000) and `MaxTotalCiphertextBytes` (default 64 MiB) together cap the store's own
footprint — `Create` returns `CapacityExceeded` (503 with `Retry-After`) rather than growing past either limit.
These are configuration, not code: override them under the `SecretStore` section
(`SecretStore__MaxEntries`, `SecretStore__MaxTotalCiphertextBytes`) if a deployment's expected load differs.

The store's cap is not the same as the process's total memory footprint — the .NET runtime, ASP.NET Core's own
buffers, and per-request overhead sit on top of it. When setting a container or cgroup memory limit (`docker
run --memory`, a Kubernetes `resources.limits.memory`, an IIS Application Pool's private memory limit), leave
enough headroom above `MaxTotalCiphertextBytes` for that overhead — 256 MiB is a reasonable floor for the
default store caps; raise it proportionally if `MaxTotalCiphertextBytes` is increased. A limit set too tight
fails the same way any other OOM condition would (the container or worker process is killed and restarted),
which is a routine restart for a store with no persistence to lose (see "No Persistence Layer"), not a
security incident — but it is worth choosing deliberately rather than discovering it under load.

## Feature Flags

`FeatureOptions` (`src/OneShot.Web/FeatureOptions.cs`) holds the one feature currently gated deployment-wide:
`SplitKeyDelivery` (default **on**), which withholds the key from every created secret's link so it can be
delivered over a second channel instead (issue #77, plan task 57) — a deployment-wide default, not a
per-secret choice; there is no create-page toggle. Turn it off under the `Features` section
(`Features__SplitKeyDelivery=false`) to remove the create page's separate key field and the reveal page's
matching manual key-entry prompt from every page, deployment-wide, reverting to a single fragment-carrying
link for every secret (for example, a policy against manual key transcription). This is a UI toggle, not a security
control: `T1` ("the server never sees the key") holds identically whether the flag is on or off, since the key
never leaves the browser via either path.

## No Persistence Layer

This is a standing rule, not a per-deployment choice: **no database, cache, file, or Data Protection key ring
may ever be attached to the secret store**, on any platform. It is what makes the "the server never sees
plaintext or holds anything past a restart" guarantee (architecture.md) actually true in production, not just
in the code that ships today.

Concretely, on every platform this repository supports:

- `InMemorySecretStore` is a `ConcurrentDictionary` and nothing else — there is no configuration surface that
  points it at a database or a distributed cache, and adding one is a security invariant violation, not a
  feature (see `CLAUDE.md`).
- `Program.cs` calls `AddDataProtection().UseEphemeralDataProtectionProvider()` unconditionally, on every
  platform and environment. This overrides the default behavior a host might otherwise apply on its own — IIS,
  for instance, will auto-persist Data Protection keys to the registry or a file share unless told not to; the
  ephemeral provider means that never happens here regardless of hosting model, so there is nothing for an
  operator to accidentally leave enabled.
- The container image declares no `VOLUME` and is run `--read-only` (see "Linux and Container Deployment");
  there is no mount point for a well-meaning operator to attach a persistent disk to even by mistake.
- A restart — planned or not, on any platform — loses every secret currently `Available`. This is the
  documented trade-off behind the single-instance design (architecture.md), not a bug: announce maintenance
  windows and keep TTLs short, covered further in `docs/runbook.md` (plan task 51).

If a future requirement genuinely needs secrets to survive a restart or to be shared across instances, that is
a different system with a different threat model — it does not get bolted onto this one.

## Releases, Signing and Branch Protection

Releases are cut by `.github/workflows/release.yml` (plan task 53, issue #61). A push to `main` runs
semantic-release, which reads the Conventional Commits since the last tag and decides the version: `fix:` a
patch, `feat:` a minor, a `!` after the type or a `BREAKING CHANGE:` footer a major. `docs`, `chore`,
`refactor`, `test` and `ci` are release-silent, so a documentation change does not mint a version. If a
version is cut, the image is built from the same `Containerfile` the security workflow scans, pushed to
`ghcr.io/jeedo/oneshot`, signed, and the SBOM of the pushed image is attached to the GitHub Release.

No changelog file is generated and no bot ever commits to `main`: the release notes are the changelog. That is
a deliberate choice — the alternative plugins push a commit straight to the release branch, which this
repository's own rules forbid.

### Verify before you deploy

The image is signed **keyless**: there is no private key anywhere in this repository, and the signature is
bound to the release workflow's own OIDC identity. Verify the digest you are about to run:

```bash
cosign verify ghcr.io/jeedo/oneshot@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/jeedo/oneshot/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Signatures cover the **digest**, not the tag — a tag can later be repointed at different bytes, so verify and
deploy by digest. The SBOM for that digest is attached to the matching GitHub Release as `sbom.spdx.json`.

### Branch protection (required, and enabled by hand)

The release workflow triggers on a push to `main` and does **not** re-run the CI and security gates. That is
safe only because branch protection means a commit cannot reach `main` without having passed them on a pull
request. **Without branch protection, `main` is an unguarded release trigger.**

Branch protection cannot be set from the pipeline — it is an owner-level repository setting. Configure it on
`main` under Settings → Branches:

- **Require a pull request before merging**, with at least one approving review.
- **Require status checks to pass**, with *Require branches to be up to date* on, and every one of these
  selected: `Build, format and test`, `Client (tsc, vitest, bundle)`, `End to end (Playwright)`,
  `Docs, threat coverage and scripts`, `CodeQL (csharp)`, `CodeQL (javascript-typescript)`,
  `Dependency advisories`, `Secret scanning (gitleaks)`, `ZAP baseline`, `Container (build, Trivy, SBOM)`.
- **Do not allow bypassing the above settings**, including for administrators.
- **Restrict force pushes and deletions** on `main`.

Leave auto-merge off. Dependabot pull requests are gated by exactly the same checks and still need a human
approval, which is the control that makes an automated dependency bump safe to accept (T14).
