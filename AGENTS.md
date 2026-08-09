# Repository Guidance

## Project scope

This repository has evolved from an academic passwordless-authentication demo
into a local identity-security and secure-engineering lab. M1-M6 are complete:
the supporting investigation capability is deliberately bounded, and no further
feature milestone is currently approved. Work must follow `docs/decision-log.md`.

## Approved product assumptions

- The application is local-only and CLI-first. Tkinter remains secondary.
- The MVP is Windows-first. Keep ordinary Python portable where doing so is simple.
- One trusted local OS account operates administration, analysis, and the service.
- Mutually untrusted local OS users and production deployment are outside scope.

## Coding style and complexity

- Keep major security controls understandable, explainable, modifiable, testable,
  and troubleshootable by a future maintainer.
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
- Do not add enterprise-looking complexity without a concrete security or
  maintainability need. Prefer correct controls, clear tests, reproducible
  evidence, bounded investigation, and understandable documentation.

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

## Completed M1-M4 authenticator lifecycle

- Treat administrator-controlled enrollment/revocation, Credential-v1 custody,
  PKAS-AUTH-V2, and bounded revoke-first replacement as settled behavior.
- Lifecycle authority remains the trusted local OS account through the local CLI.
  HTTP clients cannot create identities, bind without scoped authorization and
  proof of possession, or revoke authenticators.
- New software keys use the fixed-profile Argon2id/AES-GCM Credential-v1 envelope.
  Current credential paths are no-overwrite, unlock precedes challenge issuance,
  and uncertain enrollment retries preserve and reuse the same key.
- Authentication uses versioned, context-bound RSA-PSS proofs and independent,
  expiring, single-use challenges. Revocation is terminal and invalidates open
  challenges; replacement creates a distinct binding and key without reactivation.
- This is logical software-authenticator lifecycle state, not physical-device
  identity, hardware attestation, human identity proofing, or generic recovery.

## Completed M5 security-evidence milestone

- Keep application-native evidence focused on identity lifecycle and authentication
  decisions. Monitoring and investigation support the identity-security product;
  they are not separate product goals.
- Prefer state mutation and its authoritative success event in the same SQLite
  transaction. Keep observational denials truthful about claimed versus verified
  actors, and fail closed on trusted-state failures.
- Exclude passphrases, bearer secrets, private keys, raw signatures, credential
  material, and unnecessary challenge nonce data. Local SQLite evidence shares the
  application's trusted-OS/database boundary and is not tamper-proof or independent.
- Inspection is local, bounded, structured, and CLI-first. The v4 evidence model
  does not add alerts, dashboards, log shipping, event buses, severity frameworks,
  or SIEM/SOC infrastructure.

## Completed M6 bounded findings

- Derive findings on demand from committed M5 events; do not persist alerts or add
  a schema migration, background worker, generic rule format, or automatic response.
- Limit analysis to repeated invalid proofs across distinct challenges, replay after
  a successful challenge consumption, and requests targeting a terminally revoked
  binding. Challenge expiry and limit events are timeline context only.
- Return a bounded chronological timeline and exact evidence-event links. Keep
  verified facts separate from cautious interpretation and explicitly report when
  earlier matching evidence was truncated.
- Preserve M5 actor assurance: a denial naming a binding does not prove which person,
  physical device, or private key sent it. Keep the implementation substantially
  smaller than the lifecycle and evidence milestones.

## Current state

- Feature development stopped after M6. Future maintenance may improve truthful
  presentation, reproducibility, repository hygiene, or verified defects without
  expanding the settled M1-M6 product scope.
- Do not start another feature milestone, add generic detection/SOC capabilities,
  or expand the trust model without a new explicit product decision.

## Milestone process

- Normally use repository inspection, focused research, one short manager/checkpoint,
  implementation, verification, and independent review for security-sensitive work.
  Do not create chains of revised plans unless a real architecture conflict requires it.

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
