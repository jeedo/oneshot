# Claude Instructions — OneShot

OneShot is a .NET 10 web app for sharing a secret that can be read exactly once. Security is the primary
quality attribute: the server never sees plaintext or the decryption key, the encrypted secret lives only in
memory, and consumption is atomic. The design and its rationale live in the docs below — read them before
touching code.

## Session Start

Always read at the beginning of every session:
- [`docs/architecture.md`](docs/architecture.md) — system design and decided trade-offs
- [`docs/plan.md`](docs/plan.md) — threat register (T1–T15) and the phased, numbered task list
- [`docs/research.md`](docs/research.md) — survey of existing one-time-secret tools this design is based on

Then run `python3 scripts/check_docs.py` and surface any failures to the user before proceeding.

---

## Security Invariants (never trade these away)

- The server never receives, logs, or stores plaintext or the decryption key. Encryption happens in the
  browser; the key travels only in the URL fragment. `OneShot.Web` must never reference `System.Security.Cryptography.Aes*`.
- The secret store is in-memory only. Never add a database, cache, file, or Data Protection key ring that could
  persist secret material to disk.
- `TryConsume` is a single atomic operation. Never split it into read-then-delete.
- `GET` endpoints have no side effects; only the same-origin `POST …/reveal` consumes a secret.
- Audit and application logs may contain secret Ids and Windows account names — never ciphertext, nonces,
  keys, or request bodies.
- Every mitigation and every security test cites a threat ID from the register in `docs/plan.md`; tests use
  `[Trait("Threat", "T#")]`.
- Security-category analyzer rules (CA2100, CA3xxx, CA5xxx) are build errors. Never suppress one without a
  code comment stating why and a matching note in `docs/threat-model.md`.

---

## Implementing a Task

When the user asks to implement a task from `docs/plan.md`:

1. Identify the task number and the threat IDs it cites
2. Create a branch from `main`: `git checkout -b feature/<task-number>-<short-slug>`
3. **Write tests first** — run them and confirm they **fail** (red phase)
4. Implement until all tests pass (green phase), then run the full local checks below
5. Mark the task complete: `python3 scripts/complete_task.py <task-number>`
6. Commit using a conventional commit message (includes the updated `docs/plan.md`)
7. Push and open a PR (use `gh pr create` where the CLI is available, otherwise the session's GitHub tools)

---

## Local Checks (run before every commit)

```bash
dotnet build OneShot.sln                             # warnings are errors; security analyzers are errors
dotnet test OneShot.sln                              # xUnit unit + integration tests
dotnet format OneShot.sln --verify-no-changes        # LF endings, using-directive groups, style rules
python3 scripts/check_docs.py                        # docs structure and task numbering
npm --prefix src/OneShot.Web/Client run check        # tsc --noEmit, vitest, esbuild bundle
```

Fix all errors before proceeding.

---

## Environment Notes

- The .NET SDK is pinned by `global.json` (10.0, `latestFeature` roll-forward).
- In Claude Code on the web the egress proxy blocks `builds.dotnet.microsoft.com`, so the dotnet-install script
  fails. Install from the Ubuntu archive instead: `apt-get update && apt-get install -y dotnet-sdk-10.0`.
  NuGet (`api.nuget.org`) is reachable.
- Node.js 22.12+ is required: `dotnet build` runs `npm ci --ignore-scripts` and the esbuild bundle for
  `src/OneShot.Web/Client` before compiling, producing the git-ignored `wwwroot/js/oneshot.js`. The client has
  zero runtime dependencies (`dependencies` in `package.json` stays `{}`); devDependencies are pinned exactly and
  `package-lock.json` is committed.

---

## Branching

- Always branch from `main` — never commit directly to `main`
- Name format: `feature/<task-number>-<short-slug>` (e.g. `feature/8-secret-record`)

---

## Commit Messages (Conventional Commits)

Format: `<type>(<scope>): <description>`

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`

Examples:
```
feat(store): add atomic TryConsume with tombstones
test(api): cover scanner pre-burn vectors (T4)
docs(arch): record whoami identity cookie decision
```

---

## Task Management Scripts

Run from the project root:

| Script | Usage | Description |
|--------|-------|-------------|
| `check_docs.py` | `python3 scripts/check_docs.py` | Validate architecture.md and plan.md (required sections, numbering, TBD markers) |
| `renumber_tasks.py` | `python3 scripts/renumber_tasks.py` | Restore sequential numbering after adding/removing tasks |
| `complete_task.py` | `python3 scripts/complete_task.py <N>` | Mark task N as complete |
| `get_phase_tasks.py` | `python3 scripts/get_phase_tasks.py <phase>` | List tasks for a phase (by name or number) |
