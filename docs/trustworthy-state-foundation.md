# Trustworthy State and Request-Boundary Foundation

Implementation date: 2026-08-03
Independent review date: 2026-08-08
Working branch: `codex/trustworthy-state-boundary`
Starting commit: `01f6d43bb6fd7289308a293b6be4511e6ba074fd`

## Objective

Establish the first trustworthy foundation for the approved local Identity
Security and Detection application without pulling later lifecycle, telemetry,
detection, or incident-response work forward.

This milestone replaces fragile process-global JSON state, prevents silent state
replacement, creates a minimal state-management CLI, validates the current API
boundary, and preserves the valid RSA challenge-response flow.

## Approved product direction and assumptions

- Local-only and CLI-first; the Tkinter GUI remains secondary.
- Windows-first, with ordinary Python kept portable where simple.
- One trusted local OS account operates the service, administration, and analysis.
- The project remains a small Python, Flask, `sqlite3`, and `unittest` application.
- The target product connects identity actions to evidence, detection,
  investigation, containment, and recovery, but this milestone implements only
  the state and request foundation.

## Implemented scope

- Direct standard-library SQLite persistence with explicit schema version 1.
- Stable Windows application-data path with an environment-variable override.
- `manage.py init` and `manage.py status` commands.
- Exclusive, transactional initialization that removes a partial file on failure
  and never replaces existing unreadable or unsupported state.
- Default initialization refusal when repository-local legacy JSON state exists.
- Per-operation SQLite connections instead of a process-global dictionary.
- Full SQLite integrity and foreign-key checks before state is used.
- Transactions for registration, challenge issuance, successful challenge
  consumption, and revocation.
- Conditional challenge consumption so concurrent successful requests cannot
  both consume the same challenge.
- Server-side RSA public-key parsing, 2048-bit minimum, canonical storage, and
  SHA-256 fingerprinting.
- Duplicate user/device and public-key registration rejection.
- JSON-object, required-field, identifier, Base64, field-length, and total
  request-size validation.
- Consistent 400, 409, 413, and 503 JSON errors for the new failure cases.
- Client-side identifier validation, finite request timeouts, all-or-cleaned-up
  local writes before registration, known-rejection cleanup, preservation on
  ambiguous network or server failure, and refusal to overwrite existing keys.
- Removal of challenge and signature debug prints from normal login.

## SQLite schema

The schema intentionally contains only what current behavior needs:

- `users`: local identifier and creation timestamp;
- `devices`: user/device identity, canonical public key, fingerprint, current
  challenge, revocation state, and lifecycle timestamps.

The schema uses a composite device primary key, a unique public-key fingerprint,
foreign-key enforcement, revocation-state checks, and `PRAGMA user_version`.
Key history, enrollment grants, events, and alerts are deferred until their
workflows are approved and implemented.

## Behavior before and after

| Area | Before | After |
|---|---|---|
| Missing/corrupt database | Silently returned `{}` | Missing state returns 503; corrupt state remains untouched |
| Failed initialization | Could leave an unusable partial SQLite file | Rolls back and removes only the new partial file so initialization can be retried |
| Legacy JSON state | Could be silently abandoned when creating the new default | Default initialization stops and requires an explicit new path decision |
| Persistence | Whole JSON file rewritten | Transactional SQLite changes |
| Running state | Loaded once into a global dictionary | Opened from the configured path for each operation |
| Duplicate device | Replaced the public key and cleared revocation | Rejected with 409; original key and revocation remain |
| Client integrity hash | Client-controlled value was treated like an integrity control | Removed from current runtime; an extra legacy request field is ignored |
| Public key | Stored before cryptographic parsing | Strict Base64 PEM, RSA type, and size validation before storage |
| Missing/malformed fields | Frequently produced 500 | Rejected with bounded 400 responses |
| Oversized request | No explicit application limit | Rejected at 16 KiB with 413 |
| Invalid Base64 signature | Could be treated as an ordinary bad signature | Rejected as malformed input with 400 |
| Successful challenge use | Cleared through shared in-memory state | Conditional SQLite update accepts consumption only once |
| Client registration failure | Could overwrite keys or leave server state after a partial local write | Existing keys are not overwritten; local writes finish before the request; known route rejections clean up |
| Server mode | Flask debug mode enabled | Explicit loopback binding with debug disabled |

## Verification evidence

Baseline before implementation:

```text
Ran 9 tests in 0.747s

OK
```

Current complete suite:

```text
Ran 38 tests in 1.810s

OK
```

The independent review started from the previously reported 27-test suite and
added product-boundary checks for the failure paths that were not yet proven.

The new coverage includes:

- CLI initialization, status, idempotence, and corrupt-state refusal;
- retryable schema failure, invalid parent paths, unsupported schemas, legacy JSON
  detection, and foreign-key integrity failure;
- valid registration, challenge issuance, authentication, replay rejection, and
  revocation using temporary SQLite state;
- registration with an ignored legacy client integrity-hash field;
- duplicate replacement after revocation and public-key reuse across devices;
- malformed JSON, identifiers, Base64, public keys, and oversized requests;
- non-RSA key rejection and stable public-key fingerprints;
- missing and corrupt state failing closed;
- forced registration failure rolling back the newly inserted user;
- concurrent challenge consumption across separate SQLite connections and at
  the Flask verification boundary;
- Windows application-data override and space, Unicode, and `#` path handling;
- client rejection cleanup, partial-write cleanup, ambiguous-timeout and
  unexpected-server-error preservation, and local key overwrite prevention.

Tests use temporary directories and do not read or write repository runtime state
or normal client key paths.

## Independent review corrections

The review reproduced and corrected these concrete defects:

- server registration could succeed before the second local key file failed;
- a schema error left a partial SQLite file that blocked retry;
- an invalid database parent escaped as a raw filesystem exception;
- default initialization did not warn that legacy JSON state would be abandoned;
- `quick_check` did not support the breadth of the documented integrity claim;
- concurrency was tested only at the database helper, not at the login route;
- broad cryptographic exception handling could hide unrelated programming errors;
- unused integrity-hash request and response logic implied a control that was no
  longer stored or enforced.

Challenge issuance was also simplified from a select followed by an update in an
immediate transaction to one conditional update. SQLite already serializes the
write, and the route needs only the update result.

## Remaining limitations and deferred work

- Enrollment and revocation remain unauthenticated.
- The client still stores the AES key beside the encrypted private key.
- The current client key format and filenames need a dedicated lifecycle phase.
- A timeout or connection error preserves both local key files because server
  acceptance is uncertain. There is no reconciliation command yet.
- Power loss or a cleanup failure can still leave partial client files.
- Challenges still lack expiry, attempt limits, and request throttling.
- Invalid signatures do not consume a challenge.
- Authentication still signs a raw challenge with RSA PKCS#1 v1.5.
- The API does not create a session or protect another resource.
- There is no device inventory command beyond internal persistence functions.
- There is no safe reset command or legacy JSON import.
- There are no structured security events, detections, alerts, investigation, or
  response workflows.

These are documented technical debt, not properties claimed as secure.

## Market-relevant skill strengthened

This milestone provides concrete evidence of secure software development and
identity-state integrity: the original unsafe behavior is characterized, state
changes are transactional, malformed inputs fail predictably, duplicate key
replacement is blocked, rollback and concurrency behavior are tested, and
runtime secrets remain isolated from the repository.

It does not yet prove authorized authenticator lifecycle, complete protocol
hardening, telemetry, detection engineering, or incident response.

## Complexity and learning fit

The implementation stays within the existing code level. It introduces direct
SQLite tables, constraints, per-operation connections, commit/rollback, a small
`argparse` CLI, and explicit Flask validation. It does not introduce an ORM,
application factory, dependency injection, or generic service/repository layers.

The most important new concept is transaction rollback: registration inserts a
user and a device as one unit, so a forced device-insert failure removes the
uncommitted user instead of leaving partial identity state. The concurrency test
demonstrates the related idea that only one conditional update can consume a
stored challenge.

Schema creation also uses an explicit transaction because Python's `sqlite3`
context manager does not start one for DDL. Exclusive file creation prevents a
check-then-create race from overwriting state. These are the smallest mechanisms
that make initialization all-or-nothing and safely retryable.

## Independent review references

- [Python `sqlite3` transaction and context-manager documentation](https://docs.python.org/3.12/library/sqlite3.html)
- [SQLite transaction behavior](https://www.sqlite.org/lang_transaction.html)
- [SQLite URI filename behavior](https://www.sqlite.org/uri.html)
- [SQLite integrity and foreign-key check documentation](https://www.sqlite.org/pragma.html)

## Historical note

This document records the completed schema-v1 foundation and its 38-test evidence
at the time of independent review. The later administrator-controlled lifecycle
milestone explicitly migrates that state to schema v2; its current design and
evidence are documented in `administrator-controlled-lifecycle.md`. The historical
limitations above must not be read as current claims about v2 behavior.
