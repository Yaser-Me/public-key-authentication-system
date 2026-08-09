# Passwordless Identity Security Lab

A local public-key authentication project evolving into a CLI-first Identity
Security and Detection application. A registered client signs a server
challenge, and the Flask API verifies the signature with the stored public key.

The current milestone establishes an administrator-controlled local
authenticator lifecycle on top of trustworthy SQLite state. It is a local lab,
not enterprise IAM or a production authentication service.

## Authentication flow

1. The trusted local administrator initializes or explicitly migrates SQLite state.
2. The administrator creates a logical identity and issues one short-lived,
   scoped enrollment authorization.
3. The client generates an RSA-2048 key pair and stores its private key in a
   passphrase-protected local credential envelope.
4. The client signs the versioned enrollment context with RSA-PSS to prove that it
   possesses the submitted public key's private key.
5. The server atomically creates the binding and consumes the authorization.
6. The server issues a fresh 32-byte challenge for login.
7. The client unlocks its private key before requesting and signing the legacy
   login challenge.
8. The server verifies the signature and atomically clears the challenge after
   successful use. A trusted local administrator can terminally revoke a binding.

The API returns an authentication result but does not create a session or grant
access to another protected application.

## Current features

- RSA-2048 challenge-response authentication
- Passphrase-protected local credential-v1 files using Argon2id and AES-256-GCM
- Authenticated local identity, binding, and fingerprint association for credentials
- No-overwrite credential publication using complete temporary validation and hard links
- Server-validated RSA public keys and SHA-256 fingerprints
- Explicit SQLite initialization, status, and v1-to-v2 migration commands
- SQLite integrity plus conservative recognition of the application-generated
  v1/v2 lifecycle schemas on every state open
- Trusted-local identity creation, inventory, enrollment authorization, and
  reasoned revocation commands
- High-entropy, digest-stored, scoped, short-lived, single-use enrollment
  authorizations
- RSA-PSS/SHA-256 proof of possession for new authenticator bindings
- Atomic authenticator binding and authorization consumption with exact retry
  reconciliation after a lost response
- Transactional challenge issuance, successful challenge consumption, and
  terminal revocation
- Duplicate device and public-key rejection
- Strict JSON, identifier, Base64, public-key, and request-size validation
- Successful challenge replay protection, including concurrent database updates
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
| `replay_test.py` | Legacy manual replay helper; not reproducible evidence |
| `docs/administrator-controlled-lifecycle.md` | Milestone security model and evidence |
| `requirements.txt` | Python dependencies |

## Run locally

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Initialize local state:

```powershell
python manage.py init
python manage.py status
```

For supported existing v1 SQLite state, stop the local service, make a manual
copy if desired, then run:

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
to interpret supported v1 state. There is intentionally no reset command yet.
Supported means a canonical schema produced by this application's recognized
v1 or v2 creation path. Manually rewritten or third-party schemas fail closed,
even if they appear semantically equivalent, because the lifecycle constraints
cannot safely be inferred from column names or a few sample inserts.
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
```

`enrollment-issue` displays the authorization ID and bearer secret once. Do not
place the secret in source code, repository files, or screenshots. It is scoped
to the supplied identity and binding label, expires after ten minutes by default,
and is consumed only by a successful committed binding.

## API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Report readiness; returns 503 until state is initialized |
| `/authenticator/bind` | POST | Bind an authorized public key after RSA-PSS proof of possession |
| `/login/request_challenge` | POST | Issue a fresh challenge |
| `/login/verify` | POST | Verify and atomically consume a successful challenge |

The retired `/register_device` and `/device/revoke` routes return non-mutating
errors. Authenticator lifecycle mutation belongs to the trusted local CLI.

## Test locally

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --branch
```

## Security limitations

This is a local student-level application under active development, not a
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
  revocation. This intentionally models per-authenticator keys, but recovery and key
  rotation workflows are not implemented yet.
- Challenges do not expire and have no request or verification-attempt limits.
- Requesting another challenge replaces the previous outstanding challenge.
- Invalid signatures leave the challenge available for another attempt.
- The enrollment proof uses versioned RSA-PSS context, but login still signs a
  raw challenge with RSA PKCS#1 v1.5 until its dedicated hardening milestone.
- Plain HTTP is limited to loopback; the protocol does not claim protected-channel
  or phishing resistance.
- The local OS account and application data directory are the current trust
  boundary. Mutually untrusted local OS users are outside scope.
- A successful result proves possession of the stored software private key. It
  does not prove a real-world identity, a physical device, or create a login session.
- There is no structured security telemetry, detection, alert, investigation,
  containment, or recovery workflow yet.
- Existing `database.json` files are not imported automatically. Initialization
  never silently replaces them or any unreadable SQLite state.

See `docs/current-state-assessment.md` for the historical Phase 0 baseline,
`docs/trustworthy-state-foundation.md` for the historical foundation evidence,
and `docs/administrator-controlled-lifecycle.md` for current milestone evidence
and remaining work. See `docs/passphrase-protected-credentials.md` for the
current credential format, migration behavior, and evidence boundaries.
