# Passwordless Authentication Demo

A cybersecurity proof of concept for passwordless login using public-key cryptography. A registered client signs a fresh server challenge, and the Flask API verifies the signature with the stored public key.

## Authentication flow

1. The client generates an RSA-2048 key pair.
2. The public key and a device-binding hash are registered with the server.
3. The private key is encrypted locally with AES-256-GCM.
4. The server issues a fresh 32-byte challenge for login.
5. The client decrypts its private key and signs the challenge with RSA and SHA-256.
6. The server verifies the signature and clears the challenge after successful use.
7. Revoked devices are denied before signature verification.

## Main features

- RSA-2048 challenge-response authentication
- AES-256-GCM encryption of the local private-key file
- SHA-256 user, device, and public-key consistency check
- Single-use challenge replay protection
- Device revocation
- Flask JSON API
- Tkinter desktop client
- Manual replay and revocation test scripts

## Project files

| File | Purpose |
|---|---|
| `server.py` | Registration, challenge, verification, and revocation API |
| `client.py` | Client registration and login logic |
| `gui_client.py` | Tkinter interface |
| `crypto_utils.py` | RSA, AES-GCM, hashing, signing, and verification |
| `db_utils.py` | JSON persistence |
| `replay_test.py` | Manual replay-validation helper |
| `revoke_test.py` | Manual revocation helper |
| `requirements.txt` | Python dependencies |

## Run locally

Create and activate a virtual environment:

```bash
python -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Bash:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

Start the API:

```bash
python server.py
```

In a second terminal, start the desktop client:

```bash
python gui_client.py
```

Register a test user/device pair, then use the same pair to perform the challenge-response login. The server runs at [http://127.0.0.1:5000](http://127.0.0.1:5000).

## API endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Health check |
| `/register_device` | POST | Register a public key |
| `/login/request_challenge` | POST | Issue a fresh challenge |
| `/login/verify` | POST | Verify the signed challenge |
| `/device/revoke` | POST | Revoke a registered device |

## Security limitations

This is an academic demonstration, not a production authentication service.

- The JSON database is local and has no concurrency or access-control layer.
- Flask debug mode and plain HTTP are enabled for local testing.
- The AES key is stored next to the encrypted private key, so the encryption demonstrates the mechanism but does not protect against a full local compromise.
- The device hash is a consistency check, not hardware-backed device attestation.
- The revocation endpoint is not administrator-authenticated.
- Production use would require HTTPS, protected enrollment and revocation, secure hardware-backed key storage, rate limiting, structured audit logs, and hardened error handling.
