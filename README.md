# Passwordless Identity Security Lab

A local, CLI-first identity-security and secure-engineering lab for a bounded
software-authenticator lifecycle. A registered client signs a server challenge,
and the Flask API verifies the signature with the stored public key.

Public-key login alone does not govern who may bind an authenticator, how
credentials are protected, how compromised bindings are revoked or replaced,
or how security decisions are evidenced. This lab brings those boundaries
together in one small, testable local system.

The current implementation combines an administrator-controlled local
authenticator lifecycle, passphrase-protected software credentials, a versioned
authentication challenge-response protocol, application-native security evidence,
and bounded on-demand identity investigation. It is a local lab, not enterprise
IAM, a SIEM, or a production authentication service.

## Authentication flow

1. The trusted local administrator initializes or explicitly migrates SQLite state.
2. The administrator creates a logical identity and issues one short-lived,
   scoped enrollment authorization.
3. The client generates an RSA-2048 key pair and stores its private key in a
   passphrase-protected local credential envelope.
4. The client signs the versioned enrollment context with RSA-PSS to prove that it
   possesses the submitted public key's private key.
5. The server atomically creates the binding and consumes the authorization.
6. The server issues a fresh, independently identified 32-byte nonce challenge
   for one active authenticator binding.
7. The client unlocks its private key before requesting the challenge and signs
   the versioned authentication context with RSA-PSS.
8. The server verifies and atomically consumes that one unexpired challenge. A
   trusted local administrator can terminally revoke a binding.

The API returns an authentication result but does not create a session or grant
access to another protected application.

## Current features

- Versioned RSA-PSS/SHA-256 challenge-response authentication
- Passphrase-protected local credential-v1 files using Argon2id and AES-256-GCM
- Authenticated local identity, binding, and fingerprint association for credentials
- No-overwrite credential publication using complete temporary validation and hard links
- Server-validated RSA public keys and SHA-256 fingerprints
- Explicit SQLite initialization, status, and v1/v2/v3-to-v4 migration commands
- SQLite integrity plus conservative recognition of the application-generated
  v1/v2/v3/v4 lifecycle schemas on every state open
- Trusted-local identity creation, inventory, enrollment authorization, and
  reasoned revocation commands
- High-entropy, digest-stored, scoped, short-lived, single-use enrollment
  authorizations
- RSA-PSS/SHA-256 proof of possession for new authenticator bindings
- Atomic authenticator binding and authorization consumption with exact retry
  reconciliation after a lost response
- Transactional independent challenge issuance, successful challenge consumption,
  expiry enforcement, and terminal revocation
- Bounded revoke-first authenticator replacement that preserves old binding history
  and creates a distinct new binding and credential
- Duplicate device and public-key rejection
- Strict JSON, identifier, Base64, public-key, and request-size validation
- Successful challenge replay protection, including concurrent database updates
- Structured, sanitized lifecycle and authentication events committed with
  authoritative state transitions where applicable
- Bounded local JSON event inspection by identity, binding, or event type
- Bounded, read-only investigation of invalid-proof, replay, and post-revocation
  evidence with exact event links and explicit limitations
- Flask JSON API
- Tkinter desktop client
- Isolated automated positive, negative, concurrency, and rollback tests

## Project files

| File | Purpose |
|---|---|
| `manage.py` | Trusted-local lifecycle, migration, and state commands |
| `server.py` | Authenticator binding and challenge-response API |
| `client.py` | CLI-first client binding, retry, login, and legacy migration logic |
| `gui_client.py` | Secondary Tkinter interface |
| `crypto_utils.py` | RSA, AES-GCM, hashing, signing, and key validation |
| `credential_store.py` | Credential-v1 parsing, encryption, and safe local publication |
| `db_utils.py` | Direct SQLite schema and state operations |
| `tests/` | Automated unit, route, client, persistence, and CLI tests |
| `docs/administrator-controlled-lifecycle.md` | Milestone security model and evidence |
| `docs/application-native-security-evidence.md` | Security-event semantics, trust boundary, and evidence |
| `requirements.txt` | Python dependencies |

## Run locally

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`requirements.txt` pins the direct dependency versions validated in a clean local
Python 3.12.10 environment. Pip still resolves their transitive dependencies at
install time, so this project does not claim a fully locked transitive environment.
The CI workflow runs the same requirements path on Python 3.12 for Windows and
Ubuntu.

Initialize local state:

```powershell
python manage.py init
python manage.py status
```

For supported existing v1, v2, or v3 SQLite state, stop the local service, make a
manual copy if desired, then run:

```powershell
python manage.py migrate
```

On Windows, the default database is:

```text
%LOCALAPPDATA%\PublicKeyAuthenticationSystem\identity_lab.sqlite3
```

If `LOCALAPPDATA` is unavailable, the portable fallback is
`~/.local/share/PublicKeyAuthenticationSystem/identity_lab.sqlite3`. Set
`PKAS_DATABASE_PATH` to use an explicit path. Tests always use temporary paths.

Start the API:

```powershell
python server.py
```

In a second terminal, start the secondary desktop client:

```powershell
python gui_client.py
```

The CLI is the primary client interface. It prompts for enrollment capabilities
and passphrases without putting them in command arguments:

```powershell
python client.py enroll student1 laptop1 AUTHORIZATION_ID
python client.py retry-enrollment student1 laptop1 AUTHORIZATION_ID
python client.py login student1 laptop1
python client.py credential-status student1 laptop1
```

New enrollment and legacy migration require a confirmed passphrase of at least
15 characters. The default credential directory is:

```text
%LOCALAPPDATA%\PublicKeyAuthenticationSystem\credentials
```

Use `--credential-directory` only when deliberately working with a separate
local test/development directory. Legacy files are not used automatically. An
eligible explicit migration requires a trusted local database and source
directory:

```powershell
python client.py --database C:\path\to\identity_lab.sqlite3 legacy-inspect student1 laptop1 --legacy-directory C:\legacy
python client.py --database C:\path\to\identity_lab.sqlite3 legacy-migrate student1 laptop1 --legacy-directory C:\legacy
```

User and device identifiers must be 1-64 characters and contain only letters,
numbers, `.`, `_`, or `-`. The server runs on
[http://127.0.0.1:5000](http://127.0.0.1:5000) with Flask debug mode disabled.

## State commands

Use an explicit path when testing or inspecting a separate instance:

```powershell
python manage.py --database C:\path\to\identity_lab.sqlite3 init
python manage.py --database C:\path\to\identity_lab.sqlite3 status
python manage.py --database C:\path\to\identity_lab.sqlite3 migrate
```

`init` is idempotent for a valid current schema. It refuses to replace corrupt,
unreadable, unsupported, or migration-required state. Only `migrate` is allowed
to interpret supported v1, v2, or v3 state. There is intentionally no reset command yet.
Supported means a canonical schema produced by this application's recognized
v1, v2, v3, or v4 creation path. Manually rewritten or third-party schemas fail closed,
even if they appear semantically equivalent, because the lifecycle constraints
cannot safely be inferred from column names or a few sample inserts. Validation
also requires the application-owned indexes and rejects persisted triggers or
views that could change lifecycle or evidence behavior.
If the repository contains a legacy `database.json`, default initialization
stops without modifying it so the operator cannot silently abandon old state.
Passing `--database` or setting `PKAS_DATABASE_PATH` is treated as an explicit
decision to initialize a separate SQLite path; no legacy migration is performed.

## Trusted local lifecycle commands

```powershell
python manage.py identity-add student1
python manage.py enrollment-issue student1 laptop1
python manage.py enrollment-cancel AUTHORIZATION_ID
python manage.py inventory --user-id student1
python manage.py revoke student1 laptop1 suspected_compromise
python manage.py replacement-prepare student1 old-laptop replacement-laptop suspected_compromise
python manage.py events --user-id student1 --limit 100
python manage.py investigate --user-id student1 --limit 100
```

`enrollment-issue` displays the authorization ID and bearer secret once. Do not
place the secret in source code, repository files, or screenshots. It is scoped
to the supplied identity and binding label, expires after ten minutes by default,
and is consumed only by a successful committed binding.

`replacement-prepare` is a trusted-local containment action. In one SQLite
transaction it terminally revokes the old binding and issues an authorization
for a distinct new binding label. Use the returned authorization with the normal
`client.py enroll` command so it creates a new Credential-v1 key. If enrollment
is uncertain, retain that new credential and use `retry-enrollment` with the
same authorization; the old binding is never reactivated. This is a bounded
authenticator replacement workflow, not account recovery or human identity
proofing. If the administrator loses the displayed authorization secret after
preparation, the old binding remains safely revoked. Inspect inventory, then
use the explicit `enrollment-issue` command for the still-absent replacement
label rather than trying to prepare the old binding again.

`events` emits structured JSON in chronological order for the newest bounded
selection. It can filter by logical identity, binding (including a replacement's
related binding), or exact event type. The event table never stores enrollment
bearer values, private-key material, passphrases, raw signatures, or challenge
nonces.

`investigate` reads one bounded, consistent snapshot of an identity's committed
events and derives three non-persistent findings: repeated invalid proofs across
three distinct challenges within the ten-minute lab policy window, challenge replay
after a successful authentication, and requests targeting a binding after terminal
revocation. Each finding cites exact event IDs and separates facts, interpretation,
and limitations. Expiry and challenge-limit events remain timeline context. If the
selection is truncated, the output says that earlier activity may affect the result.

## Reviewer path

Use an explicit temporary database and credential directory for a clean local
walkthrough; do not place generated state or secrets in the repository. Replace
both the angle-bracket placeholders and the illustrative `C:\path\to\...` locations
below before running the commands. The commands use the repository virtual
environment explicitly, so each terminal has the same Python environment. In the
API terminal, set the database path, initialize it, then start the server:

```powershell
$env:PKAS_DATABASE_PATH = "C:\path\to\identity_lab.sqlite3"
.\.venv\Scripts\python.exe manage.py init
.\.venv\Scripts\python.exe server.py
```

In a second terminal, create an identity, issue a scoped authorization, and use
the authorization ID with the normal client enrollment command:

```powershell
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 identity-add <USER_ID>
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 enrollment-issue <USER_ID> <BINDING_ID>
.\.venv\Scripts\python.exe client.py --credential-directory C:\path\to\credentials enroll <USER_ID> <BINDING_ID> <AUTHORIZATION_ID>
.\.venv\Scripts\python.exe client.py --credential-directory C:\path\to\credentials login <USER_ID> <BINDING_ID>
```

`enrollment-issue` displays the bearer secret once; `client.py enroll` prompts
for it and for a new confirmed passphrase, so neither belongs in command history.
Successful enrollment reports the expected identity, binding, and fingerprint;
successful login reports `success`.

For containment and replacement, use `replacement-prepare` with an active old
binding and a distinct new binding label, then run the same enrollment command for
the returned replacement authorization:

```powershell
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 replacement-prepare <USER_ID> <OLD_BINDING_ID> <NEW_BINDING_ID> suspected_compromise
.\.venv\Scripts\python.exe client.py --credential-directory C:\path\to\credentials enroll <USER_ID> <NEW_BINDING_ID> <REPLACEMENT_AUTHORIZATION_ID>
```

The old binding remains revoked even if replacement enrollment fails or is
uncertain. Inspect lifecycle state and the resulting evidence with:

```powershell
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 inventory --user-id <USER_ID>
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 events --user-id <USER_ID>
.\.venv\Scripts\python.exe manage.py --database C:\path\to\identity_lab.sqlite3 investigate --user-id <USER_ID>
```

`events` returns sanitized, chronological committed evidence. `investigate` is
read-only and returns only the selected bounded timeline plus supported findings;
its output distinguishes fact, interpretation, and limitation. A walkthrough is
not a substitute for the automated evidence. Review the focused suites for the
replacement/authentication lifecycle, transactional evidence, and findings:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_auth_flow.py" -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_security_events.py" -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_security_analysis.py" -v
```

## API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Report readiness; returns 503 until state is initialized |
| `/authenticator/bind` | POST | Bind an authorized public key after RSA-PSS proof of possession |
| `/login/request_challenge` | POST | Issue a fresh v2 protocol challenge for an active binding |
| `/login/verify` | POST | Verify and atomically consume one successful v2 protocol challenge |

The retired `/register_device` and `/device/revoke` routes return non-mutating
errors. Authenticator lifecycle mutation belongs to the trusted local CLI.

## Test locally

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --branch
```

## Security limitations

This is a local educational identity-security and secure-engineering lab, not a
production authentication service.

- The trusted local OS account is the administrator boundary. This does not
  attribute an action to a particular human administrator.
- Enrollment authorization travels over loopback HTTP and is displayed to the
  trusted operator. It is not safe against hostile local accounts, malicious
  local processes, or network attackers.
- Local credentials are application-owned passphrase-protected envelopes, not
  standard encrypted PKCS#8 files. They protect copied credential files only by
  requiring offline passphrase guessing; they do not protect against same-account
  malware, keyloggers, process-memory access, or trusted-OS compromise.
- Credential-v1 uses a fixed Argon2id/AES-GCM profile and authenticated scope
  metadata. It is not hardware-backed, non-exportable, or a secure-backup format.
- A new credential is validated before it becomes visible or enrollment HTTP is
  sent. Existing credential locations are never overwritten. Once a request is
  sent, every denial and uncertain response preserves the same credential for an
  exact retry.
- Legacy AES/ciphertext pairs are used only by explicit inspection/migration. A
  migration must match an active trusted binding before it claims the current
  credential location. If cleanup is interrupted, normal client use stops until
  the current/pending cleanup state is resumed or resolved. Deletion makes no
  secure-erasure claim.
- A public key fingerprint can belong to only one device, including after
  revocation. Replacement creates a distinct new binding and never changes the
  old binding's key or revocation history. It is not generic account recovery,
  key backup, or identity re-proofing.
- Authentication uses `PKAS-AUTH-V2`: a 32-byte server nonce, a 256-bit
  challenge identifier, and RSA-PSS/SHA-256 with MGF1-SHA-256 and
  `PSS.DIGEST_LENGTH`. The signature binds the protocol domain, challenge ID,
  nonce, logical identity, authenticator binding, and public-key fingerprint.
- Challenges expire after five minutes. Multiple independent challenges can be
  outstanding for one active binding; each can succeed only once. Invalid
  signatures leave an unexpired challenge available for a later valid attempt.
  Challenge issuance opportunistically deletes consumed or expired rows and
  permits at most eight open challenges per binding, preventing routine durable
  challenge-state growth. There is no request or verification-attempt rate limit
  in this milestone.
- Legacy raw PKCS#1 v1.5 login requests are retired and fail non-mutatingly;
  the separate RSA-PSS enrollment proof remains proof-v1.
- Revocation deletes outstanding v2 challenges in its transaction. A verification
  whose final consumption transition runs after revocation cannot succeed; a
  verification already committed before revocation remains historical success.
- Plain HTTP is limited to loopback; the protocol does not claim protected-channel
  or phishing resistance.
- The local OS account and application data directory are the current trust
  boundary. Mutually untrusted local OS users are outside scope.
- A successful result proves possession of the stored software private key. It
  does not prove a real-world identity, a physical device, or create a login session.
- Security events share the application's SQLite and trusted local OS boundary.
  They are not tamper-proof, immutable, independently attributable, or a substitute
  for centralized audit logging. Storage retention is not automated, although CLI
  reads are bounded; a high volume of local requests can grow the event table.
- Trusted-state/database failures still return `state_unavailable`, but the same
  failing database cannot be relied on to preserve evidence of its own failure.
  Client-local passphrase failures and lost responses are not server-observable and
  are deliberately absent from server evidence.
- Findings are derived on demand from the local event history. They are not persisted
  alerts, attacker attribution, continuous monitoring, or SIEM integration. The
  invalid-signature threshold is a lab analysis policy, not a universal attack rule.
- Existing `database.json` files are not imported automatically. Initialization
  never silently replaces them or any unreadable SQLite state.

See `docs/current-state-assessment.md` for the historical Phase 0 baseline,
`docs/trustworthy-state-foundation.md` for the historical foundation evidence,
and `docs/administrator-controlled-lifecycle.md` for the historical Milestone 1
scope. See `docs/passphrase-protected-credentials.md` for the current credential
format, migration behavior, and evidence boundaries.
