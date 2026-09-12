# Threat Model

> **Status**: Stub — plan task 7 expands this into the full STRIDE-per-component model.
> **Last Updated**: 2026-09-12

The threat register (T1–T15) lives in [`plan.md`](plan.md); every mitigation and security test cites one of its
IDs. This file also records the analyzer suppressions that CLAUDE.md requires to be justified here.

## Analyzer Suppressions

| Rule | Location | Justification |
|------|----------|---------------|
| CA5398 (avoid hard-coded `SslProtocols`) | `src/OneShot.Web/Security/KestrelHardening.cs` `ConfigureHttps`; `tests/OneShot.Tests/KestrelHardeningTests.cs` `ConfigureHttps_AllowsOnlyTls12AndTls13` | The rule prefers `SslProtocols.None` so the OS picks versions, but an OS default can still admit TLS 1.0/1.1 on older hosts. T8 requires a TLS 1.2+ floor, so `Tls12 \| Tls13` is pinned explicitly and the test names the same values to lock it in. Revisit when TLS 1.4 or a deprecation of TLS 1.2 warrants a change. |
