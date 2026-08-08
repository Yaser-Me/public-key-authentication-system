# Administrator-Controlled Authenticator Binding and Revocation

Implementation date: 2026-08-09

## Objective

Replace anonymous identity-state mutation with a small, local administrator-controlled
authenticator lifecycle. This milestone strengthens Identity Security / IAM and
secure software engineering without adding a web-admin system, telemetry, or
enterprise IAM architecture.

## Trust model

The trusted local OS account operating `manage.py` is the lifecycle authority.
It can create logical identities, issue or cancel enrollment authorizations,
inspect sanitized inventory, and revoke authenticators.

HTTP clients are untrusted. They cannot create identities, bind a key without an
authorization and proof of possession, or revoke a binding. The project remains
loopback/local-only. This is not authenticated attribution to a particular human
administrator, protected-channel enrollment, physical-device attestation, or
production IAM.

`device_id` is a logical authenticator-binding label. It is not a verified physical
device identity.

## Lifecycle and state

```text
identity:       ABSENT -> CREATED
authenticator:  ABSENT -> ACTIVE -> REVOKED
authorization:  OPEN -> CONSUMED | CANCELLED | EXPIRED
```

Revocation is terminal. A replacement must use a new binding identifier and key;
the old public key is never replaced or reactivated in place. A fingerprint remains
globally unique, including after revocation.

SQLite schema v2 adds:

- `devices.revocation_reason`, nullable only for preserved historical v1 revoked
  records that truthfully had no recorded reason;
- `enrollment_authorizations`, containing authorization scope, expiry, cancellation
  and consumption state, a digest of the random bearer secret, and the consumed
  public-key fingerprint.

The plaintext authorization secret is never stored in SQLite or displayed through
inventory. Consumption timestamp and consumed fingerprint must either both be set
or both be absent. A cancelled authorization cannot be consumed.

## Migration

Fresh `init` creates schema v2. Existing supported v1 state requires the explicit
`python manage.py migrate` command.

Normal v2 runtime rejects v1 state with `migration_required`; it does not serve
two versions simultaneously and does not migrate automatically at server startup.
The migration is one explicit SQLite transaction. It preserves v1 identities,
keys, fingerprints, challenges, and revocation timestamps. If it fails, it rolls
back to usable v1 state so the operator can retry. Stop the local service and make
a manual copy before migration when an operator recovery copy is wanted.

Version acceptance checks the primary keys, global fingerprint uniqueness,
identity ownership foreign keys, and required nullability. It also compares the
stored `sqlite_schema.sql` lifecycle table definitions with the canonical shapes
created by supported application versions. The accepted v2 device shapes are a
fresh v2 table and the known table produced by the explicit v1-to-v2 migration.
Matching columns, probe-specific CHECK clauses, or expected CHECK text weakened
by an always-true alternative are not accepted. Migration validates both the
supported v1 source and the completed v2 shape before commit.

This deliberately rejects manually rewritten or third-party table definitions,
including definitions that might be semantically equivalent. The application
owns and versions this small schema; conservative recognition is easier to audit
and safer than attempting to parse arbitrary SQL or infer a constraint from a
finite set of invalid-row probes.

Migrated rows are preserved history, not retroactive evidence that the new local
administrator authorization process was used.

## Enrollment authorization and proof of possession

`manage.py enrollment-issue USER_ID DEVICE_ID` generates an authorization ID and
a secret made from 32 random bytes. It is scoped to one existing identity and one
currently unused binding identifier. The default lifetime is ten minutes.

An authorization is open only when it is unconsumed, uncancelled, and unexpired.
Issuing a replacement for the same scope cancels an earlier still-open one in the
same SQLite write transaction. Concurrent issuance is serialized by SQLite; no
process-global lock or token framework is used.

The client submits the authorization ID and secret, a validated RSA public key,
and a proof that it possesses the corresponding private key. The proof is a
deterministic, length-prefixed enrollment context containing:

- the proof-v1 domain marker;
- authorization ID;
- logical identity identifier;
- binding identifier;
- server-derived public-key fingerprint.

It is signed with RSA-PSS, SHA-256, MGF1-SHA-256, and the explicit
`PSS.DIGEST_LENGTH` salt policy. This is separate from the legacy PKCS#1 v1.5
login signature protocol, which is deliberately unchanged in this milestone.

## Atomic binding and exact retry

The binding operation uses `BEGIN IMMEDIATE` and rechecks authorization state and
binding availability inside the write transaction. Its required outcome is:

```text
binding created + authorization consumed with fingerprint
OR
neither persists
```

Invalid proof, wrong scope, invalid secret, expiry, cancellation, duplicate
conflict, and database failure do not consume an authorization.

The timestamp used to authorize a new binding is captured only after the SQLite
write transaction is acquired. A request that waits behind another writer until
the authorization expires cannot use a stale pre-wait timestamp. Authorization
issuance and cancellation likewise use one timestamp from inside their write
transaction.

If a binding commits but the HTTP response is lost, the client can retry with the
same key and authorization. A consumed authorization can reconcile only when the
secret, scope, valid proof, submitted fingerprint, stored consumed fingerprint,
and stored binding all agree. Reconciliation makes no state change. It may succeed
after the original expiry because it creates no new trusted state.

If the binding was revoked after initial enrollment, reconciliation returns its
current `revoked` state rather than claiming the key remains active or usable. If
consumed authorization state contradicts binding state, the service fails closed
as `state_unavailable`.

RSA-PSS signatures are randomized. Exact retry means the same trusted context and
key, not byte-for-byte identical signatures. Two concurrent identical requests may
therefore return `created` and `reconciled`, but only one binding and one
consumption transition exist.

## Client outcome safety

The client writes its two existing encrypted-key files before a request and never
overwrites existing files. It removes partial files only when local creation fails
before a request could be sent.

After a request starts, the client preserves complete key material for denials,
timeouts, malformed responses, unexpected responses, and server failures. It
validates successful response identity, binding identifier, fingerprint, outcome,
and current binding state. An explicit `retry_device_enrollment()` function uses
the existing private key for safe retry. Inventory is the manual reconciliation
tool; no broader reconciliation subsystem is added.

## Revocation and inventory

`manage.py revoke USER_ID DEVICE_ID REASON` performs terminal revocation inside a
SQLite transaction. It records the first reason and timestamp, clears an
outstanding challenge, and preserves the binding history. Repeated revocation is
idempotent and cannot overwrite the original reason. Revoking the last active
authenticator is allowed for containment and reports a warning.

The retired HTTP `/device/revoke` route cannot mutate state. The administrator
inventory shows logical identity, binding label, state, fingerprint, timestamps,
and reason. It does not show full public keys, challenges, authorization secrets
or digests, private keys, local paths, or proof signatures.

Challenge issuance after revocation fails. A challenge committed before revocation
is cleared by revocation. Login verification still uses a conditional active-device
challenge-consumption update, so a consumption attempt after revocation cannot
succeed.

## Evidence and limitations

The automated suite covers:

- fresh v2 initialization, explicit v1 migration, rollback, retry, and fail-closed
  state handling, including same-column schemas with missing, probe-specific, or
  always-true-weakened lifecycle constraints;
- explicit identity creation and rejection of anonymous legacy mutation routes;
- scoped, digest-stored authorization issuance, cancellation, expiry, and
  concurrent replacement;
- independent proof-v1 encoding and RSA-PSS parameter checks, randomized valid
  proofs, wrong keys, modified context, and legacy-signature rejection;
- atomic binding rollback, concurrent use, exact retry, post-expiry reconciliation,
  consumed-state inconsistency, lock-across-expiry denial, and failure during grant
  consumption;
- sanitized inventory, terminal reasoned revocation, controlled challenge and
  verification ordering with revocation, and authentication regression;
- local key partial-write cleanup, post-send preservation across denial, server,
  transport, and malformed-response outcomes, response-field validation, and
  explicit existing-key retry.

This milestone does not add passphrase-encrypted PKCS#8, a client CLI redesign,
login protocol hardening, challenge expiry, rate limiting, telemetry, detections,
investigation, recovery orchestration, sessions, RBAC, WebAuthn, PKI, dashboards,
or a migration framework.

## Complexity and learning fit

The implementation stays with direct `sqlite3`, small Python functions, normal
Flask handlers, `argparse`, and `unittest`. The most important concepts to explain
are a high-entropy bearer capability, proof of possession versus authorization,
RSA-PSS context binding, explicit SQLite transactions, conditional state changes,
terminal revocation, and idempotent retry after an ambiguous network outcome.

SQLite stores each table's defining SQL in `sqlite_schema`. The validator removes
only harmless case and whitespace differences and accepts the small set of full
table definitions created by supported application paths. Comparing the full
definition, rather than searching for CHECK substrings, prevents unrelated or
weakened expressions from impersonating required lifecycle constraints.

The advanced-looking pieces are deliberately narrow: `BEGIN IMMEDIATE` serializes
the few competing lifecycle writes, and the consumed fingerprint is retained only
so the server can distinguish an exact safe retry from a new authorization attempt.
