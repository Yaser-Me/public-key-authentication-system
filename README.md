# Passwordless Authentication Demo

A local public-key authentication project evolving into a CLI-first Identity
Security and Detection application. A registered client signs a server
challenge, and the Flask API verifies the signature with the stored public key.

The current milestone establishes trustworthy local SQLite state and a safer
HTTP request boundary. Authorized device lifecycle, challenge expiry, key
rotation, telemetry, detection, and incident workflows are not implemented yet.

## Authentication flow

1. The operator explicitly initializes local SQLite state.
2. The client generates an RSA-2048 key pair.
3. The server validates and stores the public key with its SHA-256 fingerprint.
4. The private key is encrypted locally with AES-256-GCM.
5. The server issues a fresh 32-byte challenge for login.
6. The client decrypts its private key and signs the challenge with RSA and SHA-256.
7. The server verifies the signature and atomically clears the challenge after
   successful use.
8. Revoked devices are denied before signature verification.

The API returns an authentication result but does not create a session or grant
access to another protected application.

## Current features

- RSA-2048 challenge-response authentication
- AES-256-GCM encryption of the local private-key file
- Server-validated RSA public keys and SHA-256 fingerprints
- Explicit SQLite initialization and status commands
- SQLite integrity, foreign-key, and supported-schema checks on every state open
- Transactional registration, challenge issuance, successful challenge
  consumption, and revocation
- Duplicate device and public-key rejection
- Strict JSON, identifier, Base64, public-key, and request-size validation
- Successful challenge replay protection, including concurrent database updates
- Flask JSON API
- Tkinter desktop client
- Isolated automated positive, negative, concurrency, and rollback tests

## Project files

| File | Purpose |
|---|---|
| `manage.py` | Initialize and inspect local SQLite state |
| `server.py` | Registration, challenge, verification, and revocation API |
| `client.py` | Client registration and login logic |
| `gui_client.py` | Secondary Tkinter interface |
| `crypto_utils.py` | RSA, AES-GCM, hashing, signing, and key validation |
| `db_utils.py` | Direct SQLite schema and state operations |
| `tests/` | Automated unit, route, client, persistence, and CLI tests |
| `replay_test.py` | Legacy manual replay helper; not reproducible evidence |
| `revoke_test.py` | Legacy manual revocation helper |
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

User and device identifiers must be 1-64 characters and contain only letters,
numbers, `.`, `_`, or `-`. The server runs on
[http://127.0.0.1:5000](http://127.0.0.1:5000) with Flask debug mode disabled.

## State commands

Use an explicit path when testing or inspecting a separate instance:

```powershell
python manage.py --database C:\path\to\identity_lab.sqlite3 init
python manage.py --database C:\path\to\identity_lab.sqlite3 status
```

`init` is idempotent for a valid current schema. It refuses to replace corrupt,
unreadable, or unsupported state. There is intentionally no reset command yet.
If the repository contains a legacy `database.json`, default initialization
stops without modifying it so the operator cannot silently abandon old state.
Passing `--database` or setting `PKAS_DATABASE_PATH` is treated as an explicit
decision to initialize a separate SQLite path; no legacy migration is performed.

## API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Report readiness; returns 503 until state is initialized |
| `/register_device` | POST | Validate and register a new public key |
| `/login/request_challenge` | POST | Issue a fresh challenge |
| `/login/verify` | POST | Verify and atomically consume a successful challenge |
| `/device/revoke` | POST | Revoke a registered device; authorization is still deferred |

## Test locally

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --branch
```

## Security limitations

This is a local student-level application under active development, not a
production authentication service.

- Device enrollment and revocation are still unauthenticated HTTP operations.
- The AES key is stored beside the encrypted private key. The client now avoids
  overwriting existing keys, but a passphrase- or OS-protected key format is
  still required.
- Client key filenames still derive from identifiers and are not yet stored in a
  dedicated application data directory.
- Both local key files are created before registration. A local write failure is
  cleaned up before the server is called, and the route's known `400`, `409`, or
  `413` rejection removes the files. A timeout or unexpected server error
  preserves the complete key pair because the server may already have accepted
  it; reconciling that uncertain result is still a manual recovery task. Power
  loss or cleanup failure can still leave partial local state.
- A public key fingerprint can belong to only one device, including after
  revocation. This intentionally models per-device keys, but recovery and key
  rotation workflows are not implemented yet.
- Challenges do not expire and have no request or verification-attempt limits.
- Requesting another challenge replaces the previous outstanding challenge.
- Invalid signatures leave the challenge available for another attempt.
- The signature covers the raw challenge rather than a versioned contextual
  payload, and it still uses RSA PKCS#1 v1.5 rather than RSA-PSS.
- Plain HTTP is limited to loopback; the protocol does not claim protected-channel
  or phishing resistance.
- The local OS account and application data directory are the current trust
  boundary. Mutually untrusted local OS users are outside scope.
- A successful result proves possession of the stored software private key. It
  does not prove a real-world identity and does not create a login session.
- There is no structured security telemetry, detection, alert, investigation,
  containment, or recovery workflow yet.
- Existing `database.json` files are not imported automatically. Initialization
  never silently replaces them or any unreadable SQLite state.

See `docs/current-state-assessment.md` for the Phase 0 baseline and
`docs/trustworthy-state-foundation.md` for the current milestone evidence and
remaining work.
