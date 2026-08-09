# Application-native security evidence

Milestone 5 adds a small structured event history for the existing local
software-authenticator lifecycle. Its purpose is to explain and test identity
security decisions, not to turn the project into a logging platform or SIEM.

## Storage and trust boundary

Schema v4 adds one `security_events` table to the same SQLite database as the
authoritative identity state. This was chosen over JSONL or Python file logging
because lifecycle state and its success event can commit or roll back in one
transaction. A separate file would leave a crash window in which one side could
commit without the other.

The table uses fixed columns rather than a free-form payload:

- event ID and UTC occurrence time;
- stable event type, outcome, and reason code;
- actor kind and assurance;
- optional logical identity, primary binding, related binding, public-key
  fingerprint, and interaction identifier.

There is no generic severity, arbitrary message, HTTP body, or extensible logging
framework. SQLite values are rendered through JSON encoding by the trusted-local
`manage.py events` command.

This evidence shares the trusted local OS account and database boundary with the
application. A person who can alter that database can also alter its events. The
events are therefore not tamper-proof, immutable, non-repudiable, or forensically
independent.

## Authoritative events

The following successful transitions insert evidence in the same explicit SQLite
transaction as the state change:

- state initialization or explicit schema migration;
- logical identity creation;
- enrollment authorization issuance or cancellation;
- new authenticator binding and authorization consumption;
- exact binding reconciliation;
- authentication challenge issuance;
- successful challenge consumption;
- terminal revocation and challenge invalidation;
- replacement preparation, including old-binding revocation and new scoped
  enrollment authorization.

If the event insert fails, the corresponding state transition rolls back. A
schema migration records only the migration itself; it does not invent lifecycle
events for historical records created before M5.

## Observational events and assurance

Selected denials are useful without a persistent lifecycle mutation. They are
stored in their own short writer transaction after the application has made the
decision. Current reasons distinguish invalid enrollment proof, enrollment
authorization denial, unsupported authentication protocol, invalid signature,
unknown/consumed/expired challenge, inactive binding at consumption, revoked or
unknown binding at challenge request, and the open-challenge limit.

`actor_assurance` prevents a claimed binding from being presented as a verified
actor:

- `trusted_local_account` means the local administration trust boundary, not a
  named human administrator;
- `proof_of_possession_verified` applies to successful enrollment binding;
- `cryptographically_verified` applies only to successful authentication;
- `unverified_claim` applies to requests and denials that do not prove who sent
  them.

A request targeting a revoked binding is evidence of that claimed target. It is
not proof that the revoked authenticator or its private key sent the request.
Context is retained only after it matches authoritative binding or challenge
state. Unknown submitted identity, binding, or challenge values are omitted;
they remain attacker-controlled input and could themselves contain a secret.

## Sensitive-data boundary

Events never contain Credential-v1 data, passphrases, private keys, enrollment
authorization IDs or bearer secrets, secret digests, public-key encodings, raw
signatures, challenge nonces, or local credential paths. A challenge identifier
is retained as a non-secret interaction identifier only after it resolves to a
stored application challenge, so challenge issue, invalid signature, success,
replay, and expiry can be correlated. An unknown submitted value is never copied
into evidence merely because its syntax resembles a challenge identifier.

Malformed request bodies and most bounded field-validation errors are not
persisted. This avoids recording attacker-controlled payloads and excessive noise.
An unsupported authentication protocol is recorded only as a fixed reason code;
the supplied protocol value is not stored.

The server cannot truthfully record client-local unlock failures or know that an
HTTP response was lost after it sent it. Trusted-state failures return
`state_unavailable`; if SQLite itself is unavailable or inconsistent, the same
store cannot be trusted to record that failure.

Schema v4 accepts the canonical application table definitions and required
indexes and rejects persisted triggers or views. Each event insertion is also
read back inside its caller transaction before commit. These checks prevent a
rewritten local schema from silently suppressing or changing an authoritative
event while allowing its lifecycle state change to commit.

## Inspection and retention

`python manage.py events` returns JSON for the newest 100 events by default, in
chronological order. Filters support identity, binding, and exact event type; the
maximum result is 1,000 rows. A binding filter also includes replacement events
where that binding is the related replacement target.

M5 does not add deletion, rotation, archival, or background cleanup. Event storage
therefore grows with recorded activity, including repeated denied requests. This
is an explicit local-lab availability limitation, while inspection remains
bounded. Later work must not silently describe this local history as an enterprise
retention or audit system.

## Bounded on-demand investigation

Milestone 6 derives three findings from a single bounded SQLite read snapshot:

- three invalid-signature denials for one authoritative binding across distinct
  challenge interactions within the documented ten-minute lab policy window;
- challenge replay recorded after successful consumption of that same interaction;
- activity targeting a binding after direct revocation or revoke-first replacement.

The analysis is identity-scoped, read-only, and non-persistent. It returns the
chronological event selection, exact evidence event IDs, a verified fact, cautious
interpretation, and a limitation for each finding. A result marked incomplete used
only the newest bounded selection, so absence of a finding does not establish absence
of older activity.

Invalid signatures prove failed verification for authoritative challenge context,
not who sent the request. Replay can also be a benign retry after response
uncertainty. Post-revocation targeting proves that a request named the revoked
binding, not that its old private key was used. Expiry and challenge-limit events are
timeline context rather than findings.

## Deliberate non-goals

The evidence and analysis add no persisted alerts, severity scoring, dashboards,
event shipping, automatic response, hash chain, background service, KQL/SPL,
MITRE mapping, generic rule framework, or SOC workflow.
