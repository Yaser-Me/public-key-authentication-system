# Authenticator Lifecycle

This project models a local software-authenticator lifecycle. The trusted local
OS account operates `manage.py`; HTTP clients may request enrollment and login,
but cannot create identities or revoke authenticators.

## Binding an authenticator

The administrator creates a logical identity and issues a short-lived enrollment
authorization for one identity and binding label. The client submits the
authorization, a validated RSA public key, and an RSA-PSS proof of possession.
The server stores only a digest of the authorization secret.

Binding creation and authorization consumption occur in one SQLite write
transaction. If a response is lost after that transaction commits, the client can
retry with the same key and authorization. The service reconciles only an exact
match of the authorization, scope, proof, fingerprint, and stored binding; it
does not create new state after expiry. Reconciliation can succeed after expiry
and reports the binding's current state, including revocation. A consumed
authorization that disagrees with the authoritative binding fails closed.

Revocation is a terminal trusted-local CLI action. It preserves the original
reason and timestamp, invalidates open authentication challenges, and never
reactivates or replaces a public key in place. `replacement-prepare` revokes an
active binding and issues an authorization for a distinct binding label and key.
It is a containment workflow, not account recovery or identity proofing.

## Authentication

Normal login uses `PKAS-AUTH-V2`. The server issues an independent 32-byte nonce
with a 256-bit challenge identifier for an active binding. The client signs a
length-prefixed context containing the protocol domain, challenge ID, nonce,
identity, binding, and public-key fingerprint with RSA-PSS/SHA-256,
MGF1-SHA-256, and `PSS.DIGEST_LENGTH`.

Challenges expire after five minutes and can succeed only once. SQLite conditionally
consumes a verified challenge after the writer transaction is acquired, so a
concurrent login or a revocation that wins first cannot also produce success.
Issuance removes consumed or expired rows and permits at most eight open
challenges per binding. Invalid signatures leave an otherwise valid challenge
available until it expires.

## Local state

The application uses direct `sqlite3` persistence with explicit initialization,
schema recognition, integrity checks, and focused transactions. `init` refuses
missing prerequisites, corrupt state, unsupported schemas, and implicit legacy
replacement. `migrate` is the only command that transforms supported v1, v2, or
v3 state to the current schema. Supported migrations are explicit SQLite
transactions; a failure leaves the prior usable state unmodified.

The schema validator accepts only canonical table definitions and indexes created
by supported application versions. This is intentionally stricter than checking
column names: lifecycle constraints must not be inferred from a manually altered
schema.

## Scope

The lifecycle is local-only and CLI-first. It does not establish a human identity,
create an application session, protect a remote resource, provide hardware
attestation, or support mutually untrusted local OS users. See the README for
commands and the full limitation statement.
