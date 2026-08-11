# Passwordless Identity Security Lab

A local, CLI-first lab for software-authenticator lifecycle security. A client
proves possession of an RSA private key; the Flask API verifies a server
challenge against the registered public key.

The project covers the parts public-key login alone leaves open: controlled
binding, protected local credentials, terminal revocation and replacement, and
local evidence for identity-security decisions. It is a small local system for
learning and testing these boundaries, not a production authentication service.

## How it works

1. A trusted local administrator initializes SQLite state, creates an identity,
   and issues a short-lived enrollment authorization.
2. The client creates a passphrase-protected RSA credential and proves possession
   of the submitted public key with RSA-PSS.
3. The server atomically binds the key and consumes the authorization.
4. For login, the server issues an expiring, single-use challenge and the client
   signs the versioned challenge context with RSA-PSS.
5. The server verifies and consumes the challenge in SQLite. The administrator can
   revoke a binding or prepare a replacement with a new key and binding label.

The API reports authentication results only; it does not create sessions or
grant access to another application.

## Project layout

| Path | Purpose |
|---|---|
| `manage.py` | Trusted-local lifecycle, migration, and state commands |
| `server.py` | Authenticator binding and challenge-response API |
| `client.py` | Primary CLI client for enrollment, retry, login, and migration |
| `gui_client.py` | Secondary Tkinter client |
| `credential_store.py` | Credential-v1 parsing, encryption, and safe publication |
| `crypto_utils.py` | Key validation and cryptographic operations |
| `db_utils.py` | SQLite schema and state operations |
| `tests/` | Unit, route, CLI, persistence, concurrency, and rollback tests |
| `docs/` | Lifecycle, credential-storage, and security-evidence design notes |

## Run locally

This project targets Python 3.12. Create a virtual environment and install the
pinned direct dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`requirements.txt` pins direct dependencies. Pip resolves transitive dependencies
at install time, so this is reproducible for the tested direct dependency set,
not a fully locked environment. CI runs this same path on Python 3.12 for Windows
and Ubuntu.

Initialize state and start the loopback API:

```powershell
python manage.py init
python manage.py status
python server.py
```

The default Windows database is
`%LOCALAPPDATA%\PublicKeyAuthenticationSystem\identity_lab.sqlite3`. If
`LOCALAPPDATA` is unavailable, the fallback is
`~/.local/share/PublicKeyAuthenticationSystem/identity_lab.sqlite3`. Set
`PKAS_DATABASE_PATH` or pass `--database` to work with another path. Tests always
use temporary paths.

Supported existing v1, v2, or v3 SQLite state requires an explicit migration:

```powershell
python manage.py migrate
```

`init` never replaces corrupt, unreadable, unsupported, or migration-required
state. Existing `database.json` is not imported or silently replaced.

## Enroll and authenticate

In a second terminal, create an identity and issue an authorization:

```powershell
python manage.py identity-add student1
python manage.py enrollment-issue student1 laptop1
python manage.py enrollment-list --user-id student1 --device-id laptop1
```

`enrollment-issue` displays an authorization ID and bearer secret once. Keep the
secret out of source files, screenshots, and command history. Then enroll and log
in with the CLI; it prompts for the secret and a confirmed passphrase. New
Credential-v1 creation and eligible legacy migration require a confirmed
passphrase of at least 15 characters; this is the application's creation policy.
Use
`enrollment-list` to rediscover an authorization ID after losing terminal output;
it never returns the bearer secret.

```powershell
python client.py enroll student1 laptop1 AUTHORIZATION_ID
python client.py login student1 laptop1
python client.py credential-status student1 laptop1
```

The client stores credentials by default in
`%LOCALAPPDATA%\PublicKeyAuthenticationSystem\credentials`. It will not overwrite
an existing credential. After a denied or uncertain enrollment result, retain the
Credential-v1 and inspect trusted inventory. If the binding may have committed,
use `retry-enrollment` with the same authorization and key for exact
reconciliation. Only when inventory confirms the binding is absent may the
administrator issue a fresh authorization for the same identity and binding
scope, then retry with the preserved credential and key.

```powershell
python client.py retry-enrollment student1 laptop1 AUTHORIZATION_ID
```

Use `--credential-directory` only when deliberately using a separate local
directory. Legacy AES/ciphertext files are never used automatically; inspect or
migrate them only with an explicit `--legacy-directory` and trusted database.

## Administration and inspection

```powershell
python manage.py inventory --user-id student1
python manage.py revoke student1 laptop1 suspected_compromise
python manage.py replacement-prepare student1 old-laptop replacement-laptop suspected_compromise
python manage.py events --user-id student1 --limit 100
python manage.py investigate --user-id student1 --limit 100
```

`replacement-prepare` revokes the old binding before issuing authorization for a
new one. Enroll the returned replacement authorization with the normal client
command; the old binding remains revoked even if replacement enrollment fails.

## API

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Report readiness; returns 503 until state is initialized |
| `/authenticator/bind` | POST | Bind an authorized public key after RSA-PSS proof of possession |
| `/login/request_challenge` | POST | Issue a challenge for an active binding |
| `/login/verify` | POST | Verify and consume a challenge |

Retired `/register_device` and `/device/revoke` routes are non-mutating. Lifecycle
changes belong to the trusted local CLI.

## Test locally

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q .
.\.venv\Scripts\python.exe -m pip check
git diff --check
git status --short --branch
```

## Security limitations

- This is a local educational lab, not enterprise IAM, a SIEM, or a production
  authentication service.
- The trusted local OS account is the administration boundary. It does not
  attribute an action to a specific person and excludes mutually untrusted local
  users.
- Enrollment authorization travels over loopback HTTP. It is not safe against
  hostile local accounts, malicious local processes, or network attackers.
- Credential-v1 is application-owned passphrase-protected storage. It is not
  hardware-backed, non-exportable, a secure-backup format, or protection against
  same-account malware, keyloggers, or memory access.
- A public-key fingerprint can belong to one binding only, including after
  revocation. Replacement is not account recovery, key backup, or identity
  proofing.
- `PKAS-AUTH-V2` uses a 32-byte nonce, 256-bit challenge identifier, and
  RSA-PSS/SHA-256. It does not claim protected-channel or phishing resistance.
- Challenges expire after five minutes. Up to eight can be open for a binding;
  there is no request or verification-attempt rate limit.
- Security events share the application's SQLite and trusted-OS boundary. They
  are not tamper-proof, independently attributable, or centrally retained.
- Findings are on-demand local analysis, not attacker attribution, continuous
  monitoring, or automated response.

## Design notes

- [Authenticator lifecycle](docs/authenticator-lifecycle.md)
- [Credential storage](docs/credential-storage.md)
- [Security evidence and findings](docs/security-evidence.md)
