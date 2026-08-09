"""CLI-first local authenticator client.

The server remains responsible for enrollment authorization and authentication.
This module keeps the local private key complete and passphrase-protected before
any enrollment request can leave the client.
"""

import argparse
import base64
import binascii
import getpass
import json
import os
import sys
import warnings
from pathlib import Path

import requests
from cryptography.exceptions import InvalidTag

from credential_store import (
    CredentialError,
    create_credential_bytes,
    credential_paths,
    credentials_are_same,
    describe_local_state,
    load_credential,
    publish_credential,
)
from crypto_utils import (
    AUTHENTICATION_PROTOCOL,
    decrypt_private_key,
    generate_rsa_keypair,
    public_key_b64_from_private_key,
    sign_authentication_proof,
    sign_enrollment_proof,
    validate_rsa_public_key,
)
from db_utils import (
    DatabaseError,
    list_authenticator_inventory,
    run_if_binding_active,
    validate_challenge_id,
    validate_identifier,
)


BASE_URL = "http://127.0.0.1:5000"
REQUEST_TIMEOUT_SECONDS = 5
MAX_LEGACY_CIPHERTEXT_BYTES = 16 * 1024


def _validate_identifier(value, field_name):
    return validate_identifier(value, field_name)


def _validate_enrollment_authorization(authorization_id, authorization_secret):
    if not isinstance(authorization_id, str) or not authorization_id:
        raise ValueError("authorization_id is required.")
    if not isinstance(authorization_secret, str) or not authorization_secret:
        raise ValueError("authorization_secret is required.")


def _build_enrollment_payload(
    private_key_pem, user_id, device_id, authorization_id, authorization_secret
):
    public_key_b64 = public_key_b64_from_private_key(private_key_pem)
    canonical_public_key_b64, fingerprint = validate_rsa_public_key(public_key_b64)
    proof = sign_enrollment_proof(
        private_key_pem,
        authorization_id,
        user_id,
        device_id,
        fingerprint,
    )
    return {
        "user_id": user_id,
        "device_id": device_id,
        "authorization_id": authorization_id,
        "authorization_secret": authorization_secret,
        "public_key_b64": canonical_public_key_b64,
        "enrollment_proof": base64.b64encode(proof).decode("ascii"),
    }, fingerprint


def _enrollment_warning(message, status):
    return {
        "status": status,
        "error": message,
        "warning": (
            "Enrollment outcome is uncertain or denied; the passphrase-protected "
            "credential was preserved. Use trusted administrator inventory before "
            "manual cleanup."
        ),
    }


def _submit_enrollment(payload, expected_fingerprint):
    """Send a proof-bound enrollment request and validate only authoritative success."""
    try:
        response = requests.post(
            f"{BASE_URL}/authenticator/bind",
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return _enrollment_warning(
            "Enrollment outcome is uncertain because the server response was not received.",
            "enrollment_outcome_uncertain",
        )
    try:
        response_data = response.json()
    except ValueError:
        return _enrollment_warning(
            f"Enrollment outcome is uncertain because the response could not be parsed (HTTP {response.status_code}).",
            "enrollment_outcome_uncertain",
        )

    if not response.ok:
        return _enrollment_warning(
            "Enrollment was not confirmed by the server.", "enrollment_not_confirmed"
        )
    if not isinstance(response_data, dict):
        return _enrollment_warning(
            "Enrollment outcome is uncertain because the response could not be validated.",
            "enrollment_outcome_uncertain",
        )
    if (
        response_data.get("status") not in {"created", "reconciled"}
        or response_data.get("user_id") != payload["user_id"]
        or response_data.get("device_id") != payload["device_id"]
        or response_data.get("public_key_fingerprint") != expected_fingerprint
        or response_data.get("binding_state") not in {"active", "revoked"}
    ):
        return _enrollment_warning(
            "Enrollment outcome is uncertain because the response could not be validated.",
            "enrollment_outcome_uncertain",
        )
    return response_data


def _current_state(user_id, device_id, credential_directory):
    state, current_path, pending_path = describe_local_state(
        user_id, device_id, credential_directory
    )
    if state == "mixed_or_conflicting":
        raise CredentialError(
            "mixed_cleanup_required",
            "Credential migration cleanup or local conflict must be resolved first.",
        )
    if state == "invalid_or_conflicting":
        raise CredentialError(
            "credential_state_invalid",
            "Credential state is invalid or conflicts with the requested authenticator.",
        )
    return state, current_path, pending_path


def register_device(
    user_id,
    device_id,
    authorization_id,
    authorization_secret,
    passphrase,
    credential_directory=None,
):
    """Create one new local credential before submitting enrollment HTTP."""
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    _validate_enrollment_authorization(authorization_id, authorization_secret)
    state, current_path, _ = _current_state(user_id, device_id, credential_directory)
    if state != "absent":
        raise CredentialError(
            "credential_exists",
            "Refusing to replace existing local credential material.",
        )

    private_key_pem, _ = generate_rsa_keypair()
    payload, fingerprint = _build_enrollment_payload(
        private_key_pem,
        user_id,
        device_id,
        authorization_id,
        authorization_secret,
    )
    credential_bytes, local_fingerprint = create_credential_bytes(
        private_key_pem, user_id, device_id, passphrase
    )
    if local_fingerprint != fingerprint:
        raise CredentialError("invalid_credential", "Generated credential fingerprint is inconsistent.")
    publish_credential(
        current_path,
        credential_bytes,
        user_id,
        device_id,
        passphrase,
    )

    # A pending migration state appearing before dispatch means another local
    # lifecycle operation needs operator attention. The just-created CURRENT is
    # retained, but its key must not be submitted.
    state, _, _ = _current_state(user_id, device_id, credential_directory)
    if state != "current":
        raise CredentialError(
            "mixed_cleanup_required",
            "Credential state changed before enrollment could be sent.",
        )
    return _submit_enrollment(payload, fingerprint)


def _load_current_private_key(user_id, device_id, passphrase, credential_directory=None):
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    state, current_path, _ = _current_state(user_id, device_id, credential_directory)
    if state != "current":
        raise CredentialError("credential_missing", "No current local credential exists.")
    return load_credential(current_path, user_id, device_id, passphrase)


def retry_device_enrollment(
    user_id,
    device_id,
    authorization_id,
    authorization_secret,
    passphrase,
    credential_directory=None,
):
    """Retry enrollment with the existing key without changing local material."""
    _validate_enrollment_authorization(authorization_id, authorization_secret)
    private_key_pem, _, fingerprint = _load_current_private_key(
        user_id, device_id, passphrase, credential_directory
    )
    payload, payload_fingerprint = _build_enrollment_payload(
        private_key_pem,
        user_id,
        device_id,
        authorization_id,
        authorization_secret,
    )
    if payload_fingerprint != fingerprint:
        raise CredentialError("invalid_credential", "Credential fingerprint is inconsistent.")
    return _submit_enrollment(payload, fingerprint)


def _parse_authentication_challenge(data, user_id, device_id, fingerprint):
    required_fields = {
        "protocol",
        "challenge_id",
        "nonce",
        "user_id",
        "device_id",
        "public_key_fingerprint",
        "expires_at",
    }
    if not isinstance(data, dict) or set(data) != required_fields:
        return None
    if data["protocol"] != AUTHENTICATION_PROTOCOL:
        return None
    if (
        data["user_id"] != user_id
        or data["device_id"] != device_id
        or data["public_key_fingerprint"] != fingerprint
    ):
        return None
    if not isinstance(data["expires_at"], str) or not data["expires_at"]:
        return None
    try:
        challenge_id = validate_challenge_id(data["challenge_id"])
        nonce = base64.b64decode(data["nonce"], validate=True)
    except (TypeError, ValueError, binascii.Error):
        return None
    if len(nonce) != 32:
        return None
    return challenge_id, nonce


def login(user_id, device_id, passphrase, credential_directory=None):
    """Unlock locally before requesting and signing one v2 challenge."""
    private_key_pem, _, fingerprint = _load_current_private_key(
        user_id, device_id, passphrase, credential_directory
    )
    try:
        response = requests.post(
            f"{BASE_URL}/login/request_challenge",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "user_id": user_id,
                "device_id": device_id,
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return {"status": "challenge_unavailable", "error": "Challenge request did not complete."}
    try:
        data = response.json()
    except ValueError:
        return {"status": "challenge_unavailable", "error": "Challenge response could not be parsed."}
    challenge = _parse_authentication_challenge(data, user_id, device_id, fingerprint)
    if challenge is None:
        return (
            data
            if isinstance(data, dict) and data.get("code") == "authentication_denied"
            else {"status": "challenge_unavailable", "error": "Challenge response is invalid."}
        )
    challenge_id, nonce = challenge
    signature = sign_authentication_proof(
        private_key_pem, challenge_id, nonce, user_id, device_id, fingerprint
    )
    try:
        response = requests.post(
            f"{BASE_URL}/login/verify",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "challenge_id": challenge_id,
                "signature": base64.b64encode(signature).decode("ascii"),
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException:
        return {
            "status": "authentication_outcome_uncertain",
            "error": "Authentication outcome is uncertain because the verification response was not received.",
        }
    try:
        result = response.json()
    except ValueError:
        return {"status": "authentication_outcome_uncertain", "error": "Authentication outcome is uncertain; response could not be parsed."}
    return result if isinstance(result, dict) else {"status": "authentication_outcome_uncertain", "error": "Authentication outcome is uncertain."}


def _legacy_key_paths(user_id, device_id, legacy_directory):
    _validate_identifier(user_id, "user_id")
    _validate_identifier(device_id, "device_id")
    if legacy_directory is None:
        raise ValueError("legacy_directory must be supplied explicitly.")
    directory = Path(legacy_directory)
    return (
        directory / f"privkey_{user_id}_{device_id}.enc",
        directory / f"aeskey_{user_id}_{device_id}.bin",
    )


def _load_legacy_private_key(user_id, device_id, legacy_directory):
    """Read legacy paired files only for explicit inspection or migration."""
    private_path, aes_path = _legacy_key_paths(user_id, device_id, legacy_directory)
    if not private_path.is_file() or private_path.is_symlink() or not aes_path.is_file() or aes_path.is_symlink():
        raise CredentialError("legacy_unavailable", "A complete regular legacy credential pair is required.")
    try:
        with aes_path.open("rb") as aes_file:
            aes_key = aes_file.read(33)
        with private_path.open("rb") as private_file:
            ciphertext_bytes = private_file.read(MAX_LEGACY_CIPHERTEXT_BYTES + 1)
    except OSError as exc:
        raise CredentialError("legacy_unavailable", "Legacy credential could not be read.") from exc
    if len(aes_key) != 32 or len(ciphertext_bytes) > MAX_LEGACY_CIPHERTEXT_BYTES:
        raise CredentialError("legacy_unavailable", "Legacy credential is invalid.")
    try:
        ciphertext = ciphertext_bytes.decode("ascii").strip()
        decoded = base64.b64decode(ciphertext, validate=True)
        if len(decoded) < 12 + 16:
            raise ValueError("legacy ciphertext is too short")
        private_key_pem = decrypt_private_key(aes_key, ciphertext)
        public_key_b64 = public_key_b64_from_private_key(private_key_pem)
        _, fingerprint = validate_rsa_public_key(public_key_b64)
    except (InvalidTag, UnicodeDecodeError, binascii.Error, ValueError, TypeError) as exc:
        raise CredentialError("legacy_unavailable", "Legacy credential is invalid.") from exc
    return private_key_pem, fingerprint, private_path, aes_path


def inspect_legacy_credential(user_id, device_id, legacy_directory):
    """Return the local legacy fingerprint without trusting its filenames as scope."""
    _, fingerprint, _, _ = _load_legacy_private_key(user_id, device_id, legacy_directory)
    return {"status": "legacy_inspected", "public_key_fingerprint": fingerprint}


def _binding_state(database_path, user_id, device_id, fingerprint):
    inventory = list_authenticator_inventory(
        database_path, user_id=user_id, fingerprint=fingerprint
    )
    matches = [
        authenticator
        for identity in inventory
        if identity["user_id"] == user_id
        for authenticator in identity["authenticators"]
        if authenticator["device_id"] == device_id
        and authenticator["public_key_fingerprint"] == fingerprint
    ]
    if len(matches) != 1:
        return None
    return matches[0]["state"]


def _remove_legacy_file(path, label):
    try:
        if path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink():
                raise CredentialError("mixed_cleanup_required", f"Legacy {label} path is unsafe.")
            path.unlink()
    except OSError as exc:
        raise CredentialError(
            "mixed_cleanup_required", f"Legacy {label} cleanup must be resumed."
        ) from exc


def _finish_cleanup(user_id, device_id, passphrase, database_path, legacy_directory, credential_directory):
    state, current_path, pending_path = describe_local_state(
        user_id, device_id, credential_directory
    )
    if state != "mixed_or_conflicting":
        raise CredentialError("mixed_cleanup_required", "No claimed migration cleanup state exists.")
    if not credentials_are_same(current_path, pending_path, user_id, device_id, passphrase):
        raise CredentialError("mixed_cleanup_required", "Migration credential links do not agree.")
    _, fingerprint = validate_rsa_public_key(
        public_key_b64_from_private_key(
            load_credential(current_path, user_id, device_id, passphrase)[0]
        )
    )
    binding_state = _binding_state(database_path, user_id, device_id, fingerprint)
    if binding_state not in {"active", "revoked"}:
        raise CredentialError(
            "mixed_cleanup_required",
            "Trusted binding history does not match the migration credential.",
        )

    private_path, aes_path = _legacy_key_paths(user_id, device_id, legacy_directory)
    if aes_path.exists() or aes_path.is_symlink():
        if not private_path.exists() and not private_path.is_symlink():
            raise CredentialError(
                "mixed_cleanup_required",
                "Legacy ciphertext is missing while its AES key remains.",
            )
        _remove_legacy_file(aes_path, "AES key")
    _remove_legacy_file(private_path, "ciphertext")
    try:
        pending_path.unlink()
    except OSError as exc:
        raise CredentialError(
            "mixed_cleanup_required", "Migration marker cleanup must be resumed."
        ) from exc
    return {
        "status": "legacy_migrated",
        "binding_state": binding_state,
        "public_key_fingerprint": fingerprint,
    }


def migrate_legacy_credential(
    user_id,
    device_id,
    passphrase,
    database_path,
    legacy_directory,
    credential_directory=None,
):
    """Migrate one exact active legacy binding without changing its RSA key."""
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    private_key_pem, fingerprint, _, _ = _load_legacy_private_key(
        user_id, device_id, legacy_directory
    )
    if _binding_state(database_path, user_id, device_id, fingerprint) != "active":
        raise CredentialError(
            "migration_refused", "No exact active trusted binding matches the legacy key."
        )
    state, current_path, pending_path = _current_state(
        user_id, device_id, credential_directory
    )
    if state != "absent":
        raise CredentialError(
            "migration_refused", "Existing credential state must be resolved before migration."
        )

    credential_bytes, envelope_fingerprint = create_credential_bytes(
        private_key_pem, user_id, device_id, passphrase
    )
    if envelope_fingerprint != fingerprint:
        raise CredentialError("migration_refused", "Legacy key fingerprint is inconsistent.")
    publish_credential(
        pending_path, credential_bytes, user_id, device_id, passphrase
    )

    def claim_current():
        try:
            os.link(pending_path, current_path)
            return True
        except FileExistsError:
            return False
        except OSError as exc:
            raise CredentialError("storage_unavailable", "Credential could not claim CURRENT safely.") from exc

    claimed = run_if_binding_active(
        database_path, user_id, device_id, fingerprint, claim_current
    )
    if not claimed:
        # A live migration that lost to an existing CURRENT has not touched the
        # legacy pair, so its own PENDING link is safe to remove.
        if current_path.exists() and pending_path.exists():
            try:
                pending_path.unlink()
            except OSError:
                pass
        raise CredentialError(
            "migration_refused",
            "Migration could not claim CURRENT; legacy material was not changed.",
        )
    if not credentials_are_same(current_path, pending_path, user_id, device_id, passphrase):
        raise CredentialError("mixed_cleanup_required", "Migration credential links do not agree.")
    return _finish_cleanup(
        user_id,
        device_id,
        passphrase,
        database_path,
        legacy_directory,
        credential_directory,
    )


def resume_legacy_cleanup(
    user_id, device_id, passphrase, database_path, legacy_directory, credential_directory=None
):
    """Claim unclaimed staging or finish a claimed migration after a failure."""
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    state, current_path, pending_path = describe_local_state(
        user_id, device_id, credential_directory
    )
    if state == "mixed_or_conflicting":
        return _finish_cleanup(
            user_id,
            device_id,
            passphrase,
            database_path,
            legacy_directory,
            credential_directory,
        )
    if state != "pending_unclaimed":
        raise CredentialError("migration_refused", "No recoverable migration staging state exists.")

    _, _, pending_fingerprint = load_credential(
        pending_path, user_id, device_id, passphrase
    )
    legacy_key, legacy_fingerprint, _, _ = _load_legacy_private_key(
        user_id, device_id, legacy_directory
    )
    del legacy_key
    if pending_fingerprint != legacy_fingerprint:
        raise CredentialError("migration_refused", "Staging does not match intact legacy material.")

    def claim_current():
        try:
            os.link(pending_path, current_path)
            return True
        except FileExistsError:
            return False
        except OSError as exc:
            raise CredentialError("storage_unavailable", "Credential could not claim CURRENT safely.") from exc

    claimed = run_if_binding_active(
        database_path, user_id, device_id, pending_fingerprint, claim_current
    )
    if not claimed:
        raise CredentialError(
            "migration_refused", "Migration staging could not claim CURRENT safely."
        )
    if not credentials_are_same(current_path, pending_path, user_id, device_id, passphrase):
        raise CredentialError("mixed_cleanup_required", "Migration credential links do not agree.")
    return _finish_cleanup(
        user_id,
        device_id,
        passphrase,
        database_path,
        legacy_directory,
        credential_directory,
    )


def discard_unclaimed_staging(
    user_id, device_id, passphrase, database_path, legacy_directory, credential_directory=None
):
    """Discard only staging whose complete legacy source still proves equivalence."""
    state, _, pending_path = _current_state(user_id, device_id, credential_directory)
    if state != "pending_unclaimed":
        raise CredentialError("migration_refused", "There is no unclaimed migration staging credential.")
    legacy_key, legacy_fingerprint, _, _ = _load_legacy_private_key(
        user_id, device_id, legacy_directory
    )
    _, _, pending_fingerprint = load_credential(
        pending_path, user_id, device_id, passphrase
    )
    if legacy_fingerprint != pending_fingerprint:
        raise CredentialError("migration_refused", "Staging does not match intact legacy material.")
    del legacy_key

    def discard_if_unclaimed():
        final_state, _, _ = describe_local_state(
            user_id, device_id, credential_directory
        )
        if final_state != "pending_unclaimed":
            return False
        try:
            pending_path.unlink()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise CredentialError("storage_unavailable", "Staging could not be discarded.") from exc
        return True

    if not run_if_binding_active(
        database_path, user_id, device_id, pending_fingerprint, discard_if_unclaimed
    ):
        raise CredentialError(
            "migration_refused", "Staging could not be discarded safely."
        )
    return {"status": "staging_discarded"}


def _read_hidden_secret(prompt):
    if os.name == "nt" and sys.stdin is not sys.__stdin__:
        raise CredentialError("secret_input_unavailable", "Hidden secret input is unavailable.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt) as exc:
        raise CredentialError("secret_input_unavailable", "Hidden secret input is unavailable.") from exc


def _read_new_passphrase():
    passphrase = _read_hidden_secret("New credential passphrase: ")
    confirmation = _read_hidden_secret("Confirm credential passphrase: ")
    if passphrase != confirmation:
        raise CredentialError("passphrase_policy", "Passphrase confirmation does not match.")
    return passphrase


def build_parser():
    parser = argparse.ArgumentParser(description="Use local public-key authenticator credentials.")
    parser.add_argument("--credential-directory", type=Path)
    parser.add_argument("--database", type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)

    enroll = subparsers.add_parser("enroll", help="Create a credential and bind a new authenticator.")
    enroll.add_argument("user_id")
    enroll.add_argument("device_id")
    enroll.add_argument("authorization_id")

    retry = subparsers.add_parser("retry-enrollment", help="Retry enrollment with the same credential.")
    retry.add_argument("user_id")
    retry.add_argument("device_id")
    retry.add_argument("authorization_id")

    login_parser = subparsers.add_parser("login", help="Unlock a credential and authenticate.")
    login_parser.add_argument("user_id")
    login_parser.add_argument("device_id")

    status = subparsers.add_parser("credential-status", help="Show nonsecret local credential state.")
    status.add_argument("user_id")
    status.add_argument("device_id")

    inspect = subparsers.add_parser("legacy-inspect", help="Inspect explicit legacy key material.")
    inspect.add_argument("user_id")
    inspect.add_argument("device_id")
    inspect.add_argument("--legacy-directory", type=Path, required=True)

    migrate = subparsers.add_parser("legacy-migrate", help="Migrate one active exact legacy binding.")
    migrate.add_argument("user_id")
    migrate.add_argument("device_id")
    migrate.add_argument("--legacy-directory", type=Path, required=True)

    resume = subparsers.add_parser("legacy-resume", help="Resume claimed legacy cleanup.")
    resume.add_argument("user_id")
    resume.add_argument("device_id")
    resume.add_argument("--legacy-directory", type=Path, required=True)

    discard = subparsers.add_parser("legacy-discard-staging", help="Discard verified unclaimed migration staging.")
    discard.add_argument("user_id")
    discard.add_argument("device_id")
    discard.add_argument("--legacy-directory", type=Path, required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    credential_directory = args.credential_directory
    try:
        if args.command == "enroll":
            result = register_device(
                args.user_id,
                args.device_id,
                args.authorization_id,
                _read_hidden_secret("Enrollment authorization secret: "),
                _read_new_passphrase(),
                credential_directory,
            )
        elif args.command == "retry-enrollment":
            result = retry_device_enrollment(
                args.user_id,
                args.device_id,
                args.authorization_id,
                _read_hidden_secret("Enrollment authorization secret: "),
                _read_hidden_secret("Credential passphrase: "),
                credential_directory,
            )
        elif args.command == "login":
            result = login(
                args.user_id,
                args.device_id,
                _read_hidden_secret("Credential passphrase: "),
                credential_directory,
            )
        elif args.command == "credential-status":
            state, _, _ = describe_local_state(
                args.user_id, args.device_id, credential_directory
            )
            validation = (
                "not_present"
                if state == "absent"
                else "invalid_or_conflicting"
                if state == "invalid_or_conflicting"
                else "structurally_recognized_not_unlocked"
            )
            result = {
                "status": state,
                "credential_validation": validation,
                "user_id": args.user_id,
                "device_id": args.device_id,
            }
        elif args.command == "legacy-inspect":
            result = inspect_legacy_credential(
                args.user_id, args.device_id, args.legacy_directory
            )
        elif args.command == "legacy-migrate":
            if args.database is None:
                raise ValueError("--database is required for legacy migration.")
            result = migrate_legacy_credential(
                args.user_id,
                args.device_id,
                _read_new_passphrase(),
                args.database,
                args.legacy_directory,
                credential_directory,
            )
        elif args.command == "legacy-resume":
            if args.database is None:
                raise ValueError("--database is required for legacy cleanup.")
            result = resume_legacy_cleanup(
                args.user_id,
                args.device_id,
                _read_hidden_secret("Credential passphrase: "),
                args.database,
                args.legacy_directory,
                credential_directory,
            )
        else:
            if args.database is None:
                raise ValueError("--database is required for staging discard.")
            result = discard_unclaimed_staging(
                args.user_id,
                args.device_id,
                _read_hidden_secret("Credential passphrase: "),
                args.database,
                args.legacy_directory,
                credential_directory,
            )
    except (CredentialError, DatabaseError, ValueError, OSError, requests.RequestException) as exc:
        print(json.dumps({"status": "error", "code": getattr(exc, "code", "local_error"), "error": str(exc)}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    successful_statuses = {
        "created",
        "reconciled",
        "success",
        "legacy_migrated",
        "legacy_inspected",
        "staging_discarded",
        "current",
        "absent",
        "pending_unclaimed",
    }
    return 0 if result.get("status") in successful_statuses else 1


if __name__ == "__main__":
    raise SystemExit(main())
