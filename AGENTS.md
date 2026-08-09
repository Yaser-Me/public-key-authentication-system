# Repository Guidance

## Project scope

This repository is evolving from an academic passwordless-authentication demo
into an identity security and detection lab. Work must follow the approved
project phase and the decisions recorded in `docs/decision-log.md`.

## Strategic context

- Read `MARKET_CONTEXT.md` before proposing or implementing any project phase.
- Use it to understand the project's market purpose, portfolio role, and
  evidence priorities.
- Treat it as strategic context, not permission to expand the active phase.
  Explicit approved phase instructions remain authoritative for implementation
  scope.
- Make product and technical decisions from this repository's own verified needs.
  Do not restrict a useful local capability merely because another project may
  cover related market skills.

## Approved product assumptions

- The application is local-only and CLI-first. Tkinter remains secondary.
- The MVP is Windows-first. Keep ordinary Python portable where doing so is simple.
- One trusted local OS account operates administration, analysis, and the service.
- Mutually untrusted local OS users and production deployment are outside scope.

## Coding level, complexity, and learning fit

- Target the level of a strong university student or practical junior developer.
  The user must be able to understand, explain, modify, test, and troubleshoot
  every major control.
- Keep the implementation simple and close to the repository's existing
  Python, Flask, and `unittest` style. Improve it gradually instead of replacing
  it with a different architecture.
- Prefer the simplest correct solution that satisfies the security requirement
  and acceptance criteria. Security correctness must not be weakened for
  simplicity.
- Prefer clear functions, small modules, direct control flow, descriptive
  variable names, standard Python, Flask's normal features, and straightforward
  `unittest` tests.
- Avoid unnecessary abstract base classes, factories, repository or service
  layers, dependency-injection frameworks, decorative decorators, generic
  utility systems, excessive configuration, advanced patterns, large
  inheritance structures, premature optimization, and clever one-line code.
- Do not split understandable logic across many files or classes without a
  concrete security or maintainability need. If additional structure is
  necessary, use the smallest structure that handles the requirement safely.
- Before adding an abstraction, explain the specific problem it solves, why
  the existing simple approach is insufficient, and why a simpler alternative
  would not work.
- When security correctness requires an advanced concept, use the smallest
  understandable implementation and document why the concept is necessary,
  what unsafe behavior it prevents, and what must be understood to maintain it.
- Keep comments natural and useful. Do not rewrite harmless human wording only
  to make it sound more polished.
- Do not add enterprise-looking complexity for presentation value. Portfolio
  value must come from correct controls, clear tests, reproducible evidence,
  detection and investigation capability, understandable documentation, and
  the user's ability to explain the work.
- Every phase plan must include a section named **Complexity and learning fit**.
  State whether the work matches the current coding level, identify each new
  concept and why it is needed, and explain how the user can test and understand
  it.
- After implementation, identify anything that may be difficult for a beginner
  to explain and provide a simple explanation.

## Completed Phase 0 constraints

- Preserve current runtime behavior. Do not change application code merely to
  make a characterization test pass.
- Treat insecure behavior captured by characterization tests as documented
  technical debt for a later phase.
- Keep tests isolated from the repository's `database.json` and client key
  files. Use temporary directories and Flask's in-process test client.
- Do not add security scanners, telemetry, rate limiting, storage migrations,
  dependency-policy changes, or application restructuring during Phase 0.
- Do not commit or push unless the user explicitly requests it.

## Completed foundation milestone

- Replace fragile JSON and process-global state with direct, transactional SQLite.
- Require explicit local state initialization and fail closed for missing,
  corrupt, or unsupported state.
- Validate the current HTTP request boundary and registered RSA public keys.
- Reject duplicate device or public-key registration instead of overwriting
  identity and revocation state.
- Preserve the valid RSA challenge-response flow and the useful Phase 0 tests.
- Keep tests isolated in temporary directories.
- Do not pull authorized lifecycle, passphrase/OS key storage, challenge expiry,
  rate limiting, telemetry, detection, or incident response into this milestone.

## Administrator-controlled lifecycle milestone

- Use the approved Milestone 1 execution plan for explicit v1-to-v2 migration,
  local identity creation, scoped enrollment authorization, RSA-PSS proof of
  possession, sanitized inventory, and terminal reasoned revocation.
- Keep lifecycle authority in the trusted local administrative CLI. Untrusted HTTP
  clients must not create identities, bind without authorization and proof, or
  revoke authenticators.
- Preserve the existing login challenge-response protocol in this milestone; its
  RSA-PSS/context redesign, challenge expiry, rate limiting, key-custody redesign,
  telemetry, detection, investigation, recovery orchestration, sessions, and RBAC
  remain later work.
- Use direct SQLite transactions and focused functions. Do not add a migration
  framework, token framework, ORM, service/repository layer, or application locks.
- After an enrollment request is sent, keep complete local key material unless the
  operator explicitly cleans it up after inventory review. Exact retries must not
  create new trusted state.

## Passphrase-protected client credential milestone

- Store new software private keys only in the supported credential-v1 envelope:
  fixed-profile Argon2id plus AES-GCM around DER PKCS#8, with authenticated
  identity, binding, and fingerprint metadata. Do not reintroduce adjacent raw
  AES-key storage or a weaker fallback.
- Keep credential parsing bounded and closed. Existing credential destinations
  must never be replaced; use complete validation before no-overwrite publication.
- Unlock locally before requesting a login challenge. Preserve a complete current
  credential after any enrollment request may have reached the server, and retry
  with the same key.
- Legacy AES/ciphertext files are migration-only. Require an exact trusted binding
  match before initial migration, claim CURRENT before deleting legacy material,
  and block routine use while pending cleanup exists. Do not silently fall back to
  legacy storage.
- Keep this client work local and CLI-first. Do not pull login-protocol hardening,
  replacement/recovery orchestration, telemetry, detection, sessions, or key-store
  integrations into this milestone.

## Required checks

Use the repository-local virtual environment and run the complete suite before
and after any approved change:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --branch
```

Never commit `database.json`, `.env`, generated AES keys, encrypted private
keys, virtual environments, or Python test artifacts.
