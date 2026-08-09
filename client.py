import os
import base64
import re
import requests

from crypto_utils import (
    generate_rsa_keypair,
    sign_challenge,
    sign_enrollment_proof,
    public_key_b64_from_private_key,
    generate_aes_key,
    encrypt_private_key,
    decrypt_private_key,
    validate_rsa_public_key,
)

BASE_URL = "http://127.0.0.1:5000"
REQUEST_TIMEOUT_SECONDS = 5
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _validate_identifier(value, field_name):
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 1-64 characters using letters, numbers, '.', '_' or '-'."
        )
    return value


def _device_key_paths(user_id: str, device_id: str):
    """
    build filenames for this user/device pair.
    """
    u = user_id.replace(" ", "_")
    d = device_id.replace(" ", "_")

    priv_file = f"privkey_{u}_{d}.enc"
    aes_file = f"aeskey_{u}_{d}.bin"
    return priv_file, aes_file


def _remove_key_files(paths):
    failures = []
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            failures.append(path)

    if failures:
        raise OSError(f"Could not remove local key files: {', '.join(failures)}")


def _write_new_key_files(priv_file, aes_file, encrypted_private_key, aes_key):
    created_files = []
    try:
        with open(priv_file, "x", encoding="utf-8") as file:
            created_files.append(priv_file)
            file.write(encrypted_private_key)

        with open(aes_file, "xb") as file:
            created_files.append(aes_file)
            file.write(aes_key)
    except (OSError, UnicodeError):
        try:
            _remove_key_files(created_files)
        except OSError as cleanup_error:
            raise OSError(
                "Local key creation failed and its partial files could not be removed."
            ) from cleanup_error
        raise


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


def _enrollment_warning(message):
    return {
        "error": message,
        "warning": (
            "Enrollment outcome is uncertain or denied; local key files were preserved. "
            "Use trusted administrator inventory before manual cleanup."
        ),
    }


def _submit_enrollment(payload, expected_fingerprint):
    """Send a proof-bound enrollment request and validate only authoritative success."""
    response = requests.post(
        f"{BASE_URL}/authenticator/bind",
        json=payload,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    try:
        response_data = response.json()
    except ValueError:
        return _enrollment_warning(
            f"Enrollment response could not be parsed (HTTP {response.status_code})."
        )

    if not response.ok:
        return _enrollment_warning("Enrollment was not confirmed by the server.")

    if not isinstance(response_data, dict):
        return _enrollment_warning("Enrollment response could not be validated.")
    if (
        response_data.get("status") not in {"created", "reconciled"}
        or response_data.get("user_id") != payload["user_id"]
        or response_data.get("device_id") != payload["device_id"]
        or response_data.get("public_key_fingerprint") != expected_fingerprint
        or response_data.get("binding_state") not in {"active", "revoked"}
    ):
        return _enrollment_warning("Enrollment response could not be validated.")
    return response_data


def register_device(user_id, device_id, authorization_id, authorization_secret):
    """
    Bind a new authenticator:
       generate RSA + AES keys
       encrypt private key locally
       prove possession with an administrator-issued authorization
    """
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    _validate_enrollment_authorization(authorization_id, authorization_secret)
    priv_file, aes_file = _device_key_paths(user_id, device_id)

    if os.path.exists(priv_file) or os.path.exists(aes_file):
        raise FileExistsError(
            "Refusing to replace existing local key files. "
            "Key rotation is not implemented yet."
        )

    # RSA keys
    priv_pem, _ = generate_rsa_keypair()

    # AES key for local storage protection
    aes_key = generate_aes_key()

    # encrypt private key with AES-GCM
    enc_priv_b64 = encrypt_private_key(aes_key, priv_pem)

    # Create both files before contacting the server. If either write fails,
    # no server-side device is created. Exclusive modes prevent overwriting.
    _write_new_key_files(priv_file, aes_file, enc_priv_b64, aes_key)

    try:
        payload, fingerprint = _build_enrollment_payload(
            priv_pem,
            user_id,
            device_id,
            authorization_id,
            authorization_secret,
        )
    except Exception:
        # No request was sent, so only the newly created local files are safe to remove.
        _remove_key_files((priv_file, aes_file))
        raise

    # Once requests.post starts, every outcome keeps the complete key pair. A
    # committed binding can lose its response and be reconciled by exact retry.
    response_data = _submit_enrollment(payload, fingerprint)

    if response_data.get("status") in {"created", "reconciled"}:
        print(f"[+] encrypted private key -> {priv_file}")
        print(f"[+] AES key -> {aes_file}")

    return response_data


def retry_device_enrollment(user_id, device_id, authorization_id, authorization_secret):
    """Retry enrollment with the existing key without replacing local material."""
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")
    _validate_enrollment_authorization(authorization_id, authorization_secret)
    private_key_pem = _load_private_key(user_id, device_id)
    payload, fingerprint = _build_enrollment_payload(
        private_key_pem,
        user_id,
        device_id,
        authorization_id,
        authorization_secret,
    )
    return _submit_enrollment(payload, fingerprint)


def _load_private_key(user_id: str, device_id: str) -> bytes:
    """
    load AES key and encrypted private key for this device,
    decrypt, and return PEM bytes
    """
    priv_file, aes_file = _device_key_paths(user_id, device_id)

    if not os.path.exists(priv_file) or not os.path.exists(aes_file):
        raise FileNotFoundError(
            f"Local key files not found for '{user_id}' / '{device_id}' "
            f"(expected {priv_file} and {aes_file})"
        )

    with open(aes_file, "rb") as f:
        aes_key = f.read()

    with open(priv_file, "r", encoding="utf-8") as f:
        enc_priv_b64 = f.read().strip()

    return decrypt_private_key(aes_key, enc_priv_b64)


def login(user_id, device_id, legacy_private_key_pem=None):
    """
    Passwordless login:
      1 ask server for a challenge
      2 decrypt private key from disk
      3 sign challenge
      4 send signature back
    legacy_private_key_pem is ignored kept for GUI only
    """
    user_id = _validate_identifier(user_id, "user_id")
    device_id = _validate_identifier(device_id, "device_id")

    # request challenge
    resp = requests.post(f"{BASE_URL}/login/request_challenge", json={
        "user_id": user_id,
        "device_id": device_id
    }, timeout=REQUEST_TIMEOUT_SECONDS)

    data = resp.json()

    # server might return an error instead of a challenge
    if "challenge" not in data:
        return data

    challenge_b64 = data["challenge"]
    challenge = base64.b64decode(challenge_b64)

    # load private key from disk and sign
    priv_pem = _load_private_key(user_id, device_id)
    signature = sign_challenge(priv_pem, challenge)


    signature_b64 = base64.b64encode(signature).decode()

    resp2 = requests.post(f"{BASE_URL}/login/verify", json={
        "user_id": user_id,
        "device_id": device_id,
        "challenge": challenge_b64,
        "signature": signature_b64
    }, timeout=REQUEST_TIMEOUT_SECONDS)

    return resp2.json()
