# Passwordless Identity Security Lab

A local, CLI-first lab for the lifecycle around software public-key
authentication. It covers what basic public-key login leaves open: who may bind
a credential, how that credential is stored, how a compromised binding is
contained and replaced, and what local evidence remains afterward.

It is a small learning and testing system, not a production authentication
service. Authentication returns a result; it does not create a session or grant
access to another application.

## The model

- A trusted local administrator creates identities and authorizes one
  authenticator binding at a time.
- The client creates a passphrase-protected RSA credential and proves possession
  of its private key.
- The server verifies expiring, single-use challenge responses, records lifecycle
  decisions in SQLite, and can terminally revoke a binding before authorizing a
  distinct replacement.

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

## Important boundaries

- The trusted local OS account is the administration boundary; mutually
  untrusted local users are outside scope.
- Enrollment uses loopback HTTP. The lab does not claim protected-channel or
  phishing resistance.
- Credentials are software, passphrase-protected application files—not
  hardware-backed storage or protection from same-account malware.
- Events share the local SQLite and OS boundary. They are not tamper-proof,
  independently attributable, centrally retained, or automated alerts.

## Read more

- [Authenticator lifecycle](docs/authenticator-lifecycle.md)
- [Credential storage](docs/credential-storage.md)
- [Security evidence and findings](docs/security-evidence.md)

Existing v1, v2, or v3 SQLite state requires explicit migration; see the
lifecycle note before running `python manage.py migrate`.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
