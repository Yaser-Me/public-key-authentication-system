# Current-State Assessment

Assessment date: 2026-07-22  
Branch: `upgrade/identity-security-detection-lab`  
Baseline commit: `73d2c0e`

## Architecture

The project is a local passwordless-authentication demonstration with four main
parts:

- `server.py` exposes registration, challenge, verification, and revocation
  routes through Flask.
- `client.py` generates and stores client keys and calls the Flask API over
  HTTP. `gui_client.py` provides a Tkinter interface.
- `crypto_utils.py` implements RSA-2048 signatures, AES-256-GCM private-key
  encryption, and the SHA-256 device consistency hash.
- `db_utils.py` stores users, devices, challenges, and revocation state in a
  process-global dictionary persisted to `database.json`.

Successful authentication requests a 32-byte server challenge, signs it with
the locally decrypted private key, verifies it against the registered public
key, and clears the stored challenge. The API returns a success message but
does not create an authenticated session or token.

## Market and portfolio context

This repository is currently an academic authentication demonstration. Its
long-term direction is a market-aligned Identity Security and Detection Lab,
positioned as a focused supporting portfolio project rather than the separate
Azure/Sentinel flagship project. Phase 0 only preserves and documents current
behavior. Later approved phases will connect identity controls, telemetry,
detection, investigation, containment, and recovery evidence without allowing
the long-term direction to expand the active phase implicitly.

## Registration and key storage

Registration generates an RSA key pair and AES key on the client. The encrypted
private key and plaintext AES key are stored as adjacent local files. The
public key and client-computed consistency hash are sent to an unauthenticated
registration route. Registering the same user and device identifiers overwrites
the existing device record.

## Challenge, replay, and revocation behavior

- Challenges are generated with `os.urandom(32)` and stored as Base64.
- A valid signature clears its challenge; replaying the successful request is
  rejected because no challenge remains.
- An invalid signature is rejected but leaves the challenge available.
- Challenges have no expiration or attempt limit.
- Revocation marks a device revoked and clears its challenge. Revoked devices
  cannot obtain or verify challenges.
- The revocation route is unauthenticated, and re-registration of the same
  identifiers resets the stored revocation state.

## Persistence and isolation limitations

The JSON database uses a relative path, non-atomic writes, and no concurrency
control. A missing, empty, or unreadable database is treated as an empty
dictionary. Client key filenames are derived from user-provided identifiers,
with only spaces replaced.

The Phase 0 route tests redirect the database to a temporary directory and
generate keys only in memory, so they do not touch repository data or create
client key files.

## Confirmed technical debt

- Enrollment and revocation are unauthenticated.
- Re-registration can replace a public key and reset revocation.
- Flask debug mode and plain HTTP are enabled.
- The AES key is stored beside the encrypted private key.
- Challenges do not expire and are not atomically consumed.
- Invalid signatures can be retried against the same challenge without limit.
- JSON persistence has no locking, atomic replacement, or access-control layer.
- Input, Base64, and public-key validation are incomplete.
- Login prints challenge and signature material for manual replay testing.
- There is no structured security telemetry or incident workflow.

These findings are documented rather than fixed during Phase 0.

## Baseline environment

The existing, unchanged `requirements.txt` was installed in `.venv` with
Python 3.12.10. Direct dependencies resolved to:

```text
cryptography==49.0.0
Flask==3.1.3
requests==2.34.2
```

Baseline command, run before adding characterization tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_crypto.py" -v
```

Exact result:

```text
test_modified_challenge_is_rejected (test_crypto.CryptoTests.test_modified_challenge_is_rejected) ... ok
test_private_key_encryption_round_trip (test_crypto.CryptoTests.test_private_key_encryption_round_trip) ... ok
test_signature_round_trip (test_crypto.CryptoTests.test_signature_round_trip) ... ok

----------------------------------------------------------------------
Ran 3 tests in 0.139s

OK
```

Exit code: `0`.

## Characterization coverage

`tests/test_auth_flow.py` characterizes device registration, challenge
issuance, valid authentication, invalid-signature rejection, rejection of a
successfully consumed challenge, and rejection of revoked devices. These tests
use Flask's in-process test client and do not start an external server.

Final Phase 0 verification command:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Exact result:

```text
test_challenge_issuance (test_auth_flow.AuthenticationFlowTests.test_challenge_issuance) ... ok
test_device_registration (test_auth_flow.AuthenticationFlowTests.test_device_registration) ... ok
test_invalid_signature_is_rejected_and_challenge_remains (test_auth_flow.AuthenticationFlowTests.test_invalid_signature_is_rejected_and_challenge_remains) ... ok
test_revoked_device_is_rejected (test_auth_flow.AuthenticationFlowTests.test_revoked_device_is_rejected) ... ok
test_successful_challenge_replay_is_rejected (test_auth_flow.AuthenticationFlowTests.test_successful_challenge_replay_is_rejected) ... ok
test_valid_authentication (test_auth_flow.AuthenticationFlowTests.test_valid_authentication) ... ok
test_modified_challenge_is_rejected (test_crypto.CryptoTests.test_modified_challenge_is_rejected) ... ok
test_private_key_encryption_round_trip (test_crypto.CryptoTests.test_private_key_encryption_round_trip) ... ok
test_signature_round_trip (test_crypto.CryptoTests.test_signature_round_trip) ... ok

----------------------------------------------------------------------
Ran 9 tests in 0.851s

OK
```

Exit code: `0`.
