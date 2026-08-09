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

## 2026-08-09 — Use local administrator-controlled authenticator binding

**Decision:** The trusted local OS account, through `manage.py`, creates logical
identities and authorizes one proposed authenticator binding at a time. HTTP
clients cannot create identities or revoke authenticators. A binding requires a
high-entropy, scoped, short-lived authorization and RSA-PSS proof of possession of
the submitted public key.

Authorization consumption and binding creation occur in one SQLite write
transaction. The authorization stores only a digest of its bearer secret and, on
successful consumption, the bound public-key fingerprint. This permits exact
idempotent reconciliation after a lost response without permitting new state after
expiry. A consumed authorization whose stored binding does not agree fails closed.

**Consequences:** The schema moves explicitly from v1 to v2. Normal runtime
rejects v1 with `migration_required`; the explicit migration command is the only
v2-code path allowed to transform v1. Fresh initialization creates v2 directly.
The client keeps complete key material after every post-send outcome and provides
an explicit retry path using the existing key. This milestone does not redesign
private-key storage, login signatures, challenge expiry, telemetry, detection,
recovery, sessions, RBAC, or a web-administration system.

## 2026-08-09 — Make revocation terminal trusted-local containment

**Decision:** Revocation is a reasoned local CLI action. It preserves the original
timestamp and reason, clears the current challenge transactionally, and never
reactivates or replaces the binding key. Repeating revocation is idempotent.

**Consequences:** Inventory exposes only lifecycle information and fingerprints,
not public keys, challenges, authorization secrets/digests, signatures, or local
private-key paths. The legacy HTTP revocation endpoint remains non-mutating for
clear compatibility behavior. Revoking the last active authenticator is allowed
because containment can take priority over availability.

## 2026-08-09 — Use a bounded passphrase-protected client credential envelope

**Decision:** Replace adjacent AES-key storage with one application-owned
credential-v1 envelope containing DER PKCS#8 RSA private-key material. The
envelope uses fixed-profile Argon2id and AES-256-GCM with deterministic,
length-prefixed associated data for the exact logical identity, binding label,
and public-key fingerprint. It has a closed parser, bounded reads, and no
file-controlled KDF parameters.

New credentials are completely written, reopened, and validated before a
same-directory hard link claims the final no-overwrite path. The client only
contacts the enrollment service after this succeeds, and preserves the same key
after every post-send outcome. Login unlocks locally before requesting a
challenge.

**Consequences:** This is an application envelope containing PKCS#8 material,
not a standard encrypted PKCS#8 format. It reduces exposure from copied local
credential files but does not defend against same-account malware or trusted-OS
compromise. Legacy AES/ciphertext files are never used routinely. Explicit
migration requires an exact active local inventory match, claims CURRENT before
deleting legacy material, and leaves a recognizable blocked state if cleanup is
interrupted. A later revocation may still permit cleanup when the same binding
history and fingerprint remain, but never makes that binding usable.

## 2026-08-09 — Replace legacy login with explicit versioned challenges

**Decision:** Retire the raw PKCS#1 v1.5 login challenge protocol and require
`PKAS-AUTH-V2` for normal authentication. A v3 SQLite table stores independent,
server-generated 32-byte nonce challenges with a 256-bit opaque identifier,
identity/binding/fingerprint scope, issuance time, expiry time, and terminal
consumption timestamp. Authentication signatures use RSA-PSS with SHA-256,
MGF1-SHA-256, and `PSS.DIGEST_LENGTH` over a deterministic length-prefixed
protocol domain, challenge identifier, nonce, identity, binding, and fingerprint.

**Consequences:** Multiple login attempts can hold independent challenges; a
successful conditional consumption creates at most one authentication success.
Expiry and active-binding state are checked after the SQLite writer transaction
is acquired, so a stale pre-lock clock cannot extend a challenge. Revocation
deletes outstanding challenges in its transaction; it prevents a later
consumption transition but does not rewrite an earlier committed authentication
result. Invalid signatures preserve an otherwise valid challenge until success
or expiry. Existing v1/v2 state requires explicit migration to v3; old raw
challenges are cleared because they cannot be safely reinterpreted as v2
protocol state. Challenge issuance removes expired or consumed rows and caps
open challenges at eight per binding, keeping durable challenge state bounded
without a rate-limit system or background cleanup job. This adds no session,
telemetry, phishing-resistance, hardware-attestation, or compliance claim.

## 2026-08-09 — Use bounded replacement preparation instead of recovery

**Decision:** A trusted local administrator may prepare one authenticator
replacement by atomically revoking an active old binding and issuing a scoped
enrollment authorization for a distinct new binding label. The client then uses
the existing Credential-v1 enrollment and exact-retry behavior to create and
bind a new key.

**Consequences:** The old key and revocation history remain immutable and a
failed or uncertain new enrollment never reactivates the old binding. A second
administrator action against the same old binding observes it as already
revoked, so it cannot issue a competing replacement authorization. This is a
containment-oriented lifecycle operation, not generic account recovery, human
identity proofing, key restoration, backup, or passphrase reset. No new schema
or replacement-link field is introduced because the existing immutable bindings,
terminal revocation state, and trusted command output establish the required
bounded operation without a recovery framework.

## 2026-08-09 — Keep security evidence with authoritative local state

**Decision:** Schema v4 adds one fixed-field `security_events` table to the
existing SQLite database. Important successful identity, enrollment,
authentication, revocation, and replacement transitions insert sanitized evidence
inside the same explicit transaction as authoritative state. Selected protocol,
enrollment, replay, expiry, signature, binding, and challenge-limit denials are
separate observational events with claimed-versus-verified actor assurance.

The trusted-local `manage.py events` command provides bounded JSON inspection.
Events exclude bearer authorization values, credential/private-key material,
passphrases, raw signatures, public-key encodings, and challenge nonces. Migration
records only that migration occurred and does not manufacture historical events.
Unverified request values are not copied into event context unless they resolve
to trusted binding or challenge state. Canonical v4 validation requires the
application indexes, rejects persisted triggers/views, and verifies that an
inserted event row remains present and unchanged before its transaction commits.

**Consequences:** SQLite evidence and lifecycle state cannot disagree because of a
process failure between two separate commits. The event history still shares the
same trusted OS/database boundary and is not tamper-proof, independently
attributable, or an enterprise audit system. M5 adds no retention automation,
detections, alerts, severity framework, event shipping, dashboards, or SIEM
integration. M6 is conditional on whether this real event model supports a small,
identity-specific investigation/detection milestone with proportional value.

## 2026-08-09 — Derive bounded identity findings on demand

**Decision:** Use one consistent, bounded SQLite read snapshot to derive three
identity-specific findings from committed M5 evidence: repeated invalid proofs over
distinct challenge interactions within a documented ten-minute lab policy window,
replay after successful challenge consumption, and activity targeting a terminally
revoked binding. Return the selected timeline and exact evidence-event links with
separate fact, interpretation, and limitation text.

Findings are calculated on demand and are not stored. Challenge expiry and challenge
limits remain investigation context rather than standalone findings.

**Consequences:** No schema migration, alert lifecycle, background monitor, generic
rule format, severity system, or automatic response is introduced. A truncated
selection is explicitly incomplete. Unverified requests cannot be attributed to a
person, physical device, or private-key holder, and the invalid-signature threshold
is a reproducible lab analysis policy rather than a universal security standard.
