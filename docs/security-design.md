# Security Design

This document describes the security decisions behind the local authenticator
lifecycle. The README provides the runnable path; this document explains the
protocol, custody, transaction, migration, and evidence rules that make the
observed behavior trustworthy within the lab's stated boundary.

## Trust model

The trusted local OS account is the administration boundary. It operates
`manage.py`, owns the application files, and can create identities, issue or
cancel enrollment authorizations, revoke authenticators, prepare replacements,
inspect state, and run bounded investigation.

HTTP clients may request enrollment and authentication. They cannot create an
identity, issue an authorization, revoke a binding, or replace an authenticator.
The legacy anonymous registration and HTTP revocation paths fail closed rather
than mutating lifecycle state.

The system returns authentication decisions. It does not establish a human
identity, create an application session, protect a remote resource, provide
hardware attestation, or isolate mutually untrusted users who share the trusted
OS account. Enrollment and authentication use loopback HTTP and do not claim
protected-channel or phishing resistance.

## Authenticator bindings and controlled enrollment

An authenticator binding joins one logical identity, one device label, one RSA
public key, and its fingerprint. A binding is either active or terminally
revoked; a revoked binding cannot be reactivated or have its key replaced in
place.

Before a client can create a binding, the administrator issues an enrollment
authorization scoped to one identity and device label. The authorization has a
random identifier and bearer secret, expires, and can be consumed only once.
Only a digest of the bearer secret is stored.

The client generates its RSA key pair locally and submits the public key with a
`PKAS-ENROLLMENT-PROOF-V1` proof. The proof signs an unambiguous,
length-prefixed context containing the authorization identifier, identity,
device label, and public-key fingerprint. It uses RSA-PSS with SHA-256,
MGF1-SHA-256, and `PSS.DIGEST_LENGTH`. A proof for another authorization,
identity, label, key, or protocol context does not verify.

The service validates the RSA public key before accepting it. Binding creation,
authorization consumption, and the corresponding success event occur in one
SQLite write transaction. Competing requests cannot consume one authorization
to create different bindings.

### Exact retry after an uncertain response

A network failure can hide a successful commit from the client. Once an
enrollment request may have been sent, the client therefore retains the same
local credential for every denied or uncertain outcome.

Retry submits the same authorization, key, fingerprint, scope, and proof. If
the original transaction committed, the service reconciles only an exact match
with the authoritative binding. It does not create new state during
reconciliation, and it reports the binding's current state, including later
revocation. Reconciliation may succeed after the authorization's expiry because
the binding already exists; an expired open authorization cannot create a new
binding. Any disagreement between a consumed authorization and the stored
binding fails closed.

## Credential-v1 custody

Each enrolled client stores its RSA private key in a Credential-v1 JSON
envelope. The private key is DER PKCS#8 material encrypted with AES-256-GCM. The
encryption key is derived with Argon2id using 65,536 KiB of memory, three
iterations, and four lanes.

Authenticated data binds the credential format, identity, device label,
public-key fingerprint, salt, and nonce. Parsing is strict: duplicate or unknown
fields, noncanonical Base64, invalid sizes, and unsupported parameters are
rejected. KDF settings are fixed by the application rather than accepted from
an untrusted credential file.

Credential-v1 is an application-owned format, not standard encrypted PKCS#8 or
hardware-backed storage. It makes a copied credential file subject to offline
passphrase guessing. It does not protect the key from malware already running
as the trusted local user.

### Publication without overwrite

Before enrollment, the client writes a complete credential to a temporary file,
reopens and validates it, and then uses a same-directory hard link to claim the
final path without overwrite. If two fresh enrollment attempts race, only the
winner's complete credential can claim that path and proceed with its key.

The client unlocks Credential-v1 locally before requesting an authentication
challenge. A wrong passphrase or invalid local file therefore creates no server
request and no unused challenge.

## PKAS-AUTH-V2 authentication

Authentication begins only for an active binding. The service issues an
independent 32-byte nonce and a 256-bit challenge identifier. The client signs a
deterministic, length-prefixed context containing:

- the `PKAS-AUTHENTICATION-PROOF-V2` protocol domain;
- the challenge identifier and nonce;
- the logical identity and device label; and
- the bound public-key fingerprint.

The signature uses RSA-PSS with SHA-256, MGF1-SHA-256, and
`PSS.DIGEST_LENGTH`. Enrollment and authentication proofs have separate domains
and are not interchangeable. Legacy PKCS#1 v1.5 login proofs and altered
protocol contexts are rejected.

Challenges expire after five minutes and can succeed only once. At most eight
open challenges may exist for one binding; issuance removes consumed or expired
rows before enforcing that bound. An invalid signature does not consume an
otherwise valid challenge, so the legitimate key may still use it before
expiry.

Signature verification occurs before the short SQLite writer transaction. Once
the transaction is acquired, the service conditionally consumes only the exact,
unexpired, unused challenge for the still-active, still-unrevoked binding. This
ordering gives concurrent outcomes a clear meaning:

- competing verification requests can produce at most one success;
- revocation that commits first prevents challenge issuance or consumption; and
- verification that commits first remains an earlier valid success even if the
  authenticator is revoked immediately afterward.

## Terminal revocation and distinct replacement

Revocation is a trusted-local action. The first reason and timestamp are
preserved, open challenges for the binding are invalidated, and later attempts
cannot obtain a new challenge. Revocation does not delete the historical
binding or pretend that the corresponding local credential disappeared.

`replacement-prepare` is a containment transaction, not account recovery or
identity proofing. It verifies that the destination label is distinct and
unused, terminally revokes the active binding, invalidates its challenges, and
issues an enrollment authorization for the replacement label. Those changes
and their success event commit together.

The replacement client must generate and prove possession of a new key. The old
binding is never reactivated, and its stored public key is never changed. Other
active authenticators for the same identity remain usable.

If replacement preparation cannot commit, the old binding remains active and no
replacement authorization is published. If the old binding was revoked but the
replacement secret is later unavailable, recovery requires an explicit new
authorization; it never restores the old binding.

## Transactional state and schema recognition

The application uses direct `sqlite3` persistence and focused transactions.
Initialization uses exclusive creation and refuses to replace existing,
corrupt, unsupported, or migration-required state.

Authoritative transitions—initialization, identity creation, authorization
changes, binding, successful authentication, revocation, replacement, and
migration—write their corresponding success event in the same transaction. If
event insertion or verification fails, the state change rolls back. Denial
observations are recorded separately after the decision because they are not
successful lifecycle transitions.

Database readiness is not inferred from column names alone. The validator runs
SQLite integrity and foreign-key checks, recognizes the complete normalized
table and index definitions produced by supported versions, and rejects unknown
tables, indexes, views, triggers, weakened constraints, and counterfeit schemas.
If the trusted store is unavailable or unusable, the application returns a
state-unavailable failure rather than claiming a decision or evidence record it
cannot support.

## Security events and bounded findings

Security events use fixed fields for occurrence time, event type, outcome,
reason, actor assurance, logical identity, binding references, public-key
fingerprint, and a resolved challenge identifier where applicable.

Events never contain:

- passphrases or private keys;
- credential contents;
- enrollment authorization secrets or their digests;
- raw signatures or public-key encodings;
- challenge nonces; or
- untrusted submitted identifiers that were not resolved to authoritative
  state.

`manage.py events` returns a bounded chronological JSON selection filtered by
identity, binding, or event type. The events live in the same SQLite database
and OS trust boundary as lifecycle state. They are not tamper-proof,
independently attributable, centrally retained, or a substitute for centralized
audit logging. Retention is not automated, so sustained local request volume can
grow the table.

`manage.py investigate` reads one bounded snapshot and derives three kinds of
nonpersistent finding:

1. **Repeated invalid signatures** — at least three distinct challenge
   interactions for one binding within the ten-minute lab policy window.
2. **Replay after success** — a request reuses a challenge already recorded as
   successfully consumed.
3. **Post-revocation targeting** — a later request targets a terminally revoked
   binding.

Each finding links to the source events that support it and separates the
verified fact from interpretation and limitations. A truncated selection cannot
establish that older activity was absent. Invalid signatures and
post-revocation requests do not prove who sent them or that the bound private
key was used. A replay may be a benign retry after an uncertain response.

Investigation does not write alerts, score severity, run continuously, automate
a response, or provide SIEM/SOC integration.

## Explicit migrations

`manage.py migrate` is the only command that transforms supported v1, v2, or v3
SQLite state into the current v4 schema. Migrations validate the source schema,
run in an explicit transaction, preserve supported state, and do not invent
historical events. Failure leaves the previous usable state unmodified.

Legacy client AES/ciphertext pairs are handled only through explicit inspection
and migration commands. Migration requires an exact active binding and
fingerprint match. It creates and validates a pending Credential-v1, claims the
current credential location, and only then removes legacy files.

Interrupted cleanup leaves recognizable pending state instead of silently
discarding key material. Conflicting current and pending files block normal use
until an explicit safe resume or discard operation completes. A matching
binding revoked after the new credential was claimed may permit cleanup of
migration residue, but revocation never restores credential usability.

## Implementation and executable evidence

The main implementation boundaries are:

- `manage.py` for trusted-local lifecycle and inspection commands;
- `client.py` and `credential_store.py` for enrollment, authentication, local
  custody, and credential migration;
- `server.py` and `crypto_utils.py` for the loopback HTTP boundary and
  proof/signature operations; and
- `db_utils.py` for lifecycle state, transactions, schema recognition, events,
  and bounded analysis.

The [`tests/`](../tests/) directory exercises protocol separation, replay,
expiry, context tampering, exact retry, credential publication races, competing
transactions, rollback, revocation ordering, replacement, schema counterfeits,
migration interruption, event integrity, attribution limits, and a process-level
lifecycle over real loopback HTTP.
