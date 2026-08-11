# Security Evidence and Findings

The application records a small structured event history in the same SQLite
database as identity state. Successful identity, enrollment, authentication,
revocation, replacement, initialization, and migration transitions write their
event in the same transaction as the state change. If event insertion fails, the
state change rolls back.

Selected denial observations are recorded separately after the relevant decision;
they are not presented as successful state transitions. If the trusted SQLite store
is unavailable or unusable, the application cannot rely on that same store to
record evidence of its own failure.

Events use fixed fields for occurrence time, event type, outcome, reason,
actor assurance, logical identity, binding references, public-key fingerprint,
and a resolved challenge identifier where applicable. They do not contain
passphrases, private keys, credential data, authorization secrets or digests,
raw signatures, public-key encodings, challenge nonces, or untrusted submitted
identifiers.

`manage.py events` returns a bounded chronological JSON selection that can be
filtered by identity, binding, or event type. The event history shares the local
OS and SQLite trust boundary, so it is not tamper-proof, independently
attributable, or a substitute for centralized audit logging. Retention is not
automated; a high volume of local requests can grow the table.

`manage.py investigate` reads one bounded snapshot and derives three
non-persistent findings:

- repeated invalid signatures for one binding across three distinct challenges
  within the ten-minute lab policy window;
- replay after successful consumption of the same challenge; and
- requests targeting a binding after terminal revocation.

Each finding links to its source events and separates the verified fact from its
interpretation and limitation. A truncated selection cannot establish that older
activity was absent. Invalid signatures and post-revocation requests do not prove
who sent them; replay can be a benign retry after an uncertain response.

This is a local diagnostic aid. It does not persist alerts, score severity, run a
background monitor, automate a response, or provide SIEM/SOC integrations.
