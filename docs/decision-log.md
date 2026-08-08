# Decision Log

## 2026-07-22 — Market context guides strategy, not phase scope

**Decision:** `MARKET_CONTEXT.md` is the repository's strategic source for
market purpose, portfolio positioning, and evidence priorities. Approved phase
instructions remain authoritative for implementation scope.

**Consequences:** Market relevance informs decisions but must not cause
uncontrolled feature, architecture, or tool expansion. Work remains bounded by
the active approved phase, and this supporting identity-security project stays
distinct from the separate Azure/Sentinel flagship project.

## 2026-07-22 — Prefer the simplest secure and testable implementation

**Decision:** The repository will favor solutions that are secure, testable,
and understandable at the project's current Python and Flask coding level over
enterprise-style abstraction or architectural complexity.

**Consequences:** Changes should adapt to the existing code and introduce only
the smallest necessary structure. Any new abstraction must solve a specific
problem that a simpler approach cannot handle safely. Phase plans must explain
their complexity and learning fit, and completed work must include a simple
explanation of anything that may be difficult for a beginner to defend.

## 2026-07-22 — Phase 0 is characterization-only

**Decision:** Phase 0 preserves and documents the existing system before later
restructuring or security fixes.

**Consequences:** Runtime source files remain unchanged. Tests may encode
insecure behavior when that behavior is the current implementation, and the
assessment records it as technical debt rather than treating it as a desired
security property.

## 2026-07-22 — Test Flask routes in process

**Decision:** Authentication routes are exercised through Flask's
`app.test_client()` instead of a live development server.

**Consequences:** Characterization tests require no bound TCP port or external
HTTP service and remain deterministic in local and CI environments.

## 2026-07-22 — Isolate generated state

**Decision:** Route tests redirect `db_utils.DB_FILE` to a temporary directory,
reset the server's in-memory database for every test, and generate RSA keys only
in memory.

**Consequences:** Tests exercise the real JSON persistence functions without
reading or writing the repository's `database.json`. They do not create client
AES-key or encrypted-private-key files.

## 2026-07-22 — Defer security and architecture work

**Decision:** Static security scanning, dependency-policy changes, structured
telemetry, authentication hardening, rate limiting, SQLite migration, and
application restructuring are deferred to later approved phases.

**Consequences:** The existing CI is changed only if its current unittest
discovery command cannot run the characterization suite reliably.

## 2026-08-03 — Approve the local device identity and detection direction

**Decision:** The product will evolve into a local, CLI-first device identity
security application that connects controlled public-key authentication and
device lifecycle actions to structured evidence, detection, investigation,
containment, and recovery validation.

The MVP is Windows-first while ordinary Python remains portable where simple.
One trusted local OS account is the administration, service, and analysis trust
boundary. Mutually untrusted local OS users, enterprise IAM, and production
deployment are outside scope.

This product decision supersedes the earlier constraint that treated this
repository as subordinate to a separate flagship project. Other projects do not
limit useful capabilities here.

**Consequences:** The Tkinter GUI remains secondary. Work proceeds in small,
coherent milestones based on technical dependency rather than treating an older
roadmap or proposed file list as fixed. Later product capabilities must not be
pulled into an earlier milestone merely for presentation value.

## 2026-08-03 — Use direct SQLite for trustworthy local state

**Decision:** Replace the process-global JSON dictionary with direct use of
Python's standard-library `sqlite3` module. Local state must be explicitly
initialized, schema-versioned, opened per operation, and changed through focused
transactions and database constraints.

Do not add an ORM, application factory, migration framework, dependency
injection, or generic repository/service layer. Do not silently import, replace,
or delete a legacy `database.json` or unreadable SQLite database.

**Consequences:** `manage.py init` and `manage.py status` establish the first
CLI operations. Missing or corrupt state fails closed. Registration, challenge
issuance, successful challenge consumption, and revocation no longer depend on a
stale in-memory copy or whole-file JSON rewrite. Later schemas may be extended
with explicit, reviewable migrations when real lifecycle or evidence needs
require them.

## 2026-08-03 — Validate public keys and reject identity replacement

**Decision:** Ignore the legacy client-supplied integrity hash because it is not
a security control. The server validates Base64 and PEM, accepts only RSA keys
of at least 2048 bits, stores a canonical key, computes a SHA-256 fingerprint,
and rejects duplicate device identifiers or reused public keys.

Successful challenge consumption uses a conditional SQLite update so only one
request can consume the current challenge. Invalid signatures continue to leave
the challenge available until a later authentication-protocol phase decides the
attempt and expiry policy.

**Consequences:** Re-registration can no longer replace a key or reactivate a
revoked device. Current clients no longer send or receive the unused hash; an
extra field from a legacy request is harmlessly ignored. The current RSA
PKCS#1 v1.5 raw challenge protocol, unauthenticated enrollment/revocation,
adjacent AES key, challenge expiry, rate limits, telemetry, and detection remain
explicitly deferred.

## 2026-08-08 — Harden initialization and client registration failure handling

**Decision:** SQLite schema creation uses an explicit transaction and an
exclusively created target file. A failed initialization rolls back, closes the
connection, and removes only the partial file created by that attempt. Existing
state is never replaced. Every state open runs SQLite's full integrity check and
foreign-key check before use.

Default `manage.py init` also stops when the repository's legacy
`database.json` exists and the SQLite target does not. An explicit `--database`
path or `PKAS_DATABASE_PATH` override is required to start separate empty state;
no import, deletion, or automatic migration is performed.

The client creates both new key files with exclusive modes before contacting the
server. A local write failure is cleaned up before any request. The registration
route's known `400`, `409`, and `413` outcomes remove the newly created files,
while an exception, timeout, or unexpected HTTP response keeps both files
because server acceptance is uncertain.

**Consequences:** Initialization failures are retryable instead of leaving an
unusable partial database. The CLI does not silently strand legacy JSON state.
Client registration no longer creates a server-side device after a partial local
write, although ambiguous network outcomes still require manual reconciliation.
These controls stay within the state and request-boundary milestone and do not
add lifecycle authorization, key-storage redesign, or recovery automation.
