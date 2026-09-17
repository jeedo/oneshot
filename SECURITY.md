# Security Policy

OneShot's whole premise is security (see [`docs/threat-model.md`](docs/threat-model.md)), so a real report
deserves a real, private channel — not a public issue that discloses the problem to everyone before it's fixed.

## Supported Versions

Releases are cut by `.github/workflows/release.yml` (semantic-release, from Conventional Commits on `main` —
see `docs/plan.md` task 53). There is one supported line: **the latest published release.** Fixes land on
`main` and go out in the next release rather than being backported to an older tag.

## Reporting a Vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/jeedo/oneshot/security/advisories/new)
(Security tab → "Report a vulnerability"). It reaches the maintainer directly and keeps the report out of
public issues, PRs, and commit messages until a fix is ready — the same reasoning this repo already applies to
its own audit logs and error responses: nothing sensitive belongs somewhere it wasn't asked to be.

Please include:

- What you found and why it's a vulnerability, not just unexpected behavior.
- Steps to reproduce, or a proof of concept if you have one.
- The threat you believe it maps to, if any — [`docs/threat-model.md`](docs/threat-model.md) lists the T1–T15
  register this project already tracks against, and it's useful to know if a report lands inside that model or
  outside it.

Please don't open a public issue for a suspected vulnerability, and please don't test against a deployment you
don't control — this project's design assumes the person holding a share link is the only one who should be
able to reveal it, and testing that assumption against someone else's data crosses from research into misuse.

## What to Expect

- **Acknowledgment within 7 days** of a report.
- After that, updates as the investigation progresses — this is a single-maintainer project, so response time
  depends on severity and availability rather than a fixed SLA, but a report will not go silent.
- Credit in the eventual GitHub Security Advisory, if you'd like it; anonymous reporting is fine too.

## Scope

In scope: `OneShot.Web` (the application), the client TypeScript in `src/OneShot.Web/Client`, the
`Containerfile` and the CI/release workflows in `.github/workflows/`.

Out of scope: the residual risks already documented and accepted in
[`docs/threat-model.md`](docs/threat-model.md) — most notably, that **anyone who has the share link can reveal
the secret.** The link is the credential by design; a report that a link works for whoever holds it is not a
vulnerability.
