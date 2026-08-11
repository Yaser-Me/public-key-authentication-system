# Passwordless Identity Security Lab

[![CI](https://github.com/Yaser-Me/public-key-authentication-system/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/Yaser-Me/public-key-authentication-system/actions/workflows/ci.yml)

A local, CLI-first identity-security lab for controlled software-authenticator
enrollment, credential custody, RSA-PSS challenge-response authentication,
terminal revocation and replacement, and local security evidence.

Built with Python 3.12, Flask, SQLite, and `cryptography`. It returns
authentication decisions rather than creating application sessions, and it does
not claim production IAM.

## System at a glance

```mermaid
flowchart LR
    Admin["Trusted administrator CLI<br/>identity · authorize · revoke · replace"]
    Credential["Credential-v1<br/>encrypted local RSA key"]
    Client["Client CLI<br/>unlock · enroll · authenticate"]
    API["Flask loopback API<br/>bind · challenge · verify"]
    State[("SQLite<br/>lifecycle state + security events")]
    Inspect["Local inspection<br/>inventory · events · findings"]

    Admin -->|lifecycle transactions| State
    Credential --> Client
    Client -->|RSA-PSS proofs| API
    API -->|validated transitions| State
    State --> Inspect
```

## What the lifecycle enforces

- Enrollment authorizations are scoped, expiring, and single-use; binding
  requires RSA-PSS proof of possession, while an uncertain response can
  reconcile only the same committed key.
- Credential-v1 uses Argon2id and AES-256-GCM, no-overwrite publication, and
  local unlock before challenge issuance.
- PKAS-AUTH-V2 signs a context-bound RSA-PSS challenge; SQLite allows each
  expiring challenge to succeed once, including under concurrent verification.
- Revocation is terminal, and replacement revokes first before enrolling a
  distinct binding and key.
- Authoritative state changes and success events commit together; denial
  evidence and derived findings remain bounded and cautiously attributed.

## Important boundaries

- The trusted local OS account is the administration boundary; mutually
  untrusted local users are outside scope.
- Enrollment uses loopback HTTP. The lab does not claim protected-channel or
  phishing resistance.
- Credentials are software, passphrase-protected application files—not
  hardware-backed storage or protection from same-account malware.
- Events share the local SQLite and OS boundary. They are not tamper-proof,
  independently attributable, centrally retained, or automated alerts.

## Run the lab

Use Python 3.12 and an ordinary interactive PowerShell terminal. The client
refuses to read secrets when hidden input is unavailable.

### Terminal 1: install, initialize, and start the API

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py init
python server.py
```

Leave the server running. This first walkthrough creates persistent local state
under `%LOCALAPPDATA%\PublicKeyAuthenticationSystem`; set
`PKAS_DATABASE_PATH` if you want a separate SQLite instance.

### Terminal 2: activate the same environment, then enroll and authenticate

```powershell
.\.venv\Scripts\Activate.ps1
python manage.py identity-add demo
python manage.py enrollment-issue demo laptop
```

`enrollment-issue` displays an authorization ID and bearer secret once. Copy the
ID into the next command; the client prompts for the secret so it stays out of
command history. Choose a new passphrase of at least 15 characters.

```powershell
python client.py enroll demo laptop AUTHORIZATION_ID
python client.py login demo laptop
```

Enrollment returns `created`; login returns `success`.

### Contain the original binding and replace it

```powershell
python manage.py replacement-prepare demo laptop replacement suspected_compromise
```

This terminally revokes `laptop` and displays a replacement authorization ID and
bearer secret. Before using it, try the old credential again:

```powershell
python client.py login demo laptop
```

This denial is expected: the command reports `authentication_denied` and exits
nonzero because a revoked binding cannot receive a challenge. It proves that a
request targeted a revoked binding and was rejected. It does not prove that the
original private key, credential, or authenticator generated that request.

Enroll the distinct replacement with the authorization ID from
`replacement-prepare`, then authenticate with it:

```powershell
python client.py enroll demo replacement REPLACEMENT_AUTHORIZATION_ID
python client.py login demo replacement
```

### Inspect the result

```powershell
python manage.py inventory --user-id demo
python manage.py events --user-id demo
python manage.py investigate --user-id demo --device-id laptop
```

Inventory shows the original `laptop` binding as revoked and `replacement` as
active. Events are chronological, sanitized local evidence. The bounded
investigation links the replacement preparation and the denied old-binding
request as `post_revocation_targeting`; it makes no claim about who sent that
request.

## Project map

| Path | Responsibility |
|---|---|
| `manage.py` | Trusted-local lifecycle and inspection commands |
| `client.py` / `credential_store.py` | Enrollment, authentication, Credential-v1 custody, and migration |
| `server.py` / `crypto_utils.py` | HTTP boundary and RSA-PSS protocol operations |
| `db_utils.py` | SQLite lifecycle, transactions, evidence, and analysis |
| `tests/` | Protocol, migration, rollback, concurrency, and failure evidence |
| `docs/` | Lifecycle, credential-storage, and security-evidence details |

## Validation

CI compiles and runs the full suite on Python 3.12 for Windows and Ubuntu. Run
the same checks locally:

```powershell
.\.venv\Scripts\python.exe -m compileall -q .
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
```

## Design notes

- [Authenticator lifecycle](docs/authenticator-lifecycle.md)
- [Credential storage](docs/credential-storage.md)
- [Security evidence and findings](docs/security-evidence.md)

Existing v1, v2, or v3 SQLite state requires explicit migration; see the
lifecycle note before running `python manage.py migrate`.
