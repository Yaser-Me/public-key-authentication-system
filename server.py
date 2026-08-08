import base64
import binascii
import os

from flask import Flask, jsonify, request

from crypto_utils import (
    validate_rsa_public_key,
    verify_enrollment_proof,
    verify_signature,
)
from db_utils import (
    DatabaseError,
    EnrollmentDeniedError,
    bind_authenticator,
    consume_device_challenge,
    get_database_status,
    get_default_database_path,
    get_device,
    issue_device_challenge,
    validate_identifier as validate_state_identifier,
)


app = Flask(__name__)
app.config["DATABASE_PATH"] = str(get_default_database_path())
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

MAX_PUBLIC_KEY_B64_LENGTH = 8192
MAX_SIGNATURE_B64_LENGTH = 8192
MAX_AUTHORIZATION_ID_LENGTH = 128
MAX_AUTHORIZATION_SECRET_LENGTH = 512


class RequestValidationError(ValueError):
    """A request field is missing or malformed."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _database_path():
    return app.config["DATABASE_PATH"]


def _error(message, code, status_code):
    return jsonify({"error": message, "code": code}), status_code


def _request_json(required_fields):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise RequestValidationError(
            "A JSON object is required.",
            "invalid_json",
        )

    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise RequestValidationError(
            f"Missing required field: {missing_fields[0]}",
            "missing_field",
        )
    return data


def _validate_identifier(value, field_name):
    try:
        return validate_state_identifier(value, field_name)
    except ValueError as exc:
        raise RequestValidationError(
            f"{field_name} must be 1-64 characters using letters, numbers, '.', '_' or '-'.",
            "invalid_identifier",
        ) from exc


def _validate_authorization_field(value, field_name, maximum_length):
    if not isinstance(value, str) or not value or len(value) > maximum_length:
        raise RequestValidationError(
            f"{field_name} is invalid.",
            "invalid_enrollment_request",
        )
    return value


def _validate_base64(value, field_name, max_encoded_length, expected_length=None):
    if not isinstance(value, str) or not value or len(value) > max_encoded_length:
        raise RequestValidationError(
            f"{field_name} is not valid base64.",
            "invalid_base64",
        )

    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RequestValidationError(
            f"{field_name} is not valid base64.",
            "invalid_base64",
        ) from exc

    if not decoded or (expected_length is not None and len(decoded) != expected_length):
        raise RequestValidationError(
            f"{field_name} has an invalid length.",
            "invalid_length",
        )
    return decoded


@app.errorhandler(DatabaseError)
def handle_database_error(error):
    app.logger.error("Local state operation failed: %s", error)
    return _error("Local state is unavailable.", "state_unavailable", 503)


@app.errorhandler(413)
def handle_request_too_large(error):
    return _error("The request body is too large.", "request_too_large", 413)


@app.route("/")
def home():
    return jsonify(
        {
            "message": "Passwordless Auth Server Running",
            "endpoints": [
                "/authenticator/bind",
                "/login/request_challenge",
                "/login/verify",
            ],
        }
    )


@app.route("/health")
def health():
    status = get_database_status(_database_path())
    if not status["initialized"]:
        return jsonify({"status": "NOT_READY", "state": status["integrity"]}), 503
    return jsonify({"status": "OK"})


@app.route("/authenticator/bind", methods=["POST"])
def bind_authenticator_route():
    try:
        data = _request_json(
            (
                "user_id",
                "device_id",
                "authorization_id",
                "authorization_secret",
                "public_key_b64",
                "enrollment_proof",
            )
        )
        user_id = _validate_identifier(data["user_id"], "user_id")
        device_id = _validate_identifier(data["device_id"], "device_id")
        authorization_id = _validate_authorization_field(
            data["authorization_id"], "authorization_id", MAX_AUTHORIZATION_ID_LENGTH
        )
        authorization_secret = _validate_authorization_field(
            data["authorization_secret"],
            "authorization_secret",
            MAX_AUTHORIZATION_SECRET_LENGTH,
        )
        public_key_b64 = data["public_key_b64"]
        if not isinstance(public_key_b64, str) or len(public_key_b64) > MAX_PUBLIC_KEY_B64_LENGTH:
            raise RequestValidationError(
                "public_key_b64 is not a supported RSA public key.",
                "invalid_public_key",
            )
        try:
            canonical_public_key_b64, fingerprint = validate_rsa_public_key(public_key_b64)
        except ValueError as exc:
            raise RequestValidationError(
                "public_key_b64 is not a supported RSA public key.",
                "invalid_public_key",
            ) from exc
        enrollment_proof = _validate_base64(
            data["enrollment_proof"],
            "enrollment_proof",
            max_encoded_length=MAX_SIGNATURE_B64_LENGTH,
        )
    except RequestValidationError as exc:
        return _error(str(exc), exc.code, 400)

    if not verify_enrollment_proof(
        canonical_public_key_b64,
        enrollment_proof,
        authorization_id,
        user_id,
        device_id,
        fingerprint,
    ):
        return _error("Enrollment denied.", "enrollment_denied", 403)

    try:
        result = bind_authenticator(
            _database_path(),
            user_id,
            device_id,
            canonical_public_key_b64,
            fingerprint,
            authorization_id,
            authorization_secret,
        )
    except EnrollmentDeniedError:
        return _error("Enrollment denied.", "enrollment_denied", 403)

    return jsonify(
        {
            "status": result["outcome"],
            "user_id": user_id,
            "device_id": device_id,
            "public_key_fingerprint": result["public_key_fingerprint"],
            "binding_state": result["binding_state"],
        }
    )


@app.route("/register_device", methods=["POST"])
def legacy_register_device_route():
    """Keep old clients from mutating identity state through the retired route."""
    return _error("Enrollment denied.", "enrollment_denied", 403)


@app.route("/login/request_challenge", methods=["POST"])
def request_challenge():
    try:
        data = _request_json(("user_id", "device_id"))
        user_id = _validate_identifier(data["user_id"], "user_id")
        device_id = _validate_identifier(data["device_id"], "device_id")
    except RequestValidationError as exc:
        return _error(str(exc), exc.code, 400)

    challenge = os.urandom(32)
    challenge_b64 = base64.b64encode(challenge).decode("ascii")

    if not issue_device_challenge(
        _database_path(),
        user_id,
        device_id,
        challenge_b64,
    ):
        return _error("Unknown or revoked device.", "authentication_denied", 403)

    return jsonify({"challenge": challenge_b64})


@app.route("/login/verify", methods=["POST"])
def verify_login():
    try:
        data = _request_json(("user_id", "device_id", "challenge", "signature"))
        user_id = _validate_identifier(data["user_id"], "user_id")
        device_id = _validate_identifier(data["device_id"], "device_id")
        challenge_b64 = data["challenge"]
        signature_b64 = data["signature"]
        challenge = _validate_base64(
            challenge_b64,
            "challenge",
            max_encoded_length=128,
            expected_length=32,
        )
        signature = _validate_base64(
            signature_b64,
            "signature",
            max_encoded_length=MAX_SIGNATURE_B64_LENGTH,
        )
    except RequestValidationError as exc:
        return _error(str(exc), exc.code, 400)

    device = get_device(_database_path(), user_id, device_id)
    if not device:
        return _error("Unknown device.", "authentication_denied", 403)
    if device["revoked"]:
        return _error("Device revoked.", "authentication_denied", 403)

    stored_challenge_b64 = device["challenge"]
    if not stored_challenge_b64:
        return _error("No challenge found.", "authentication_denied", 403)
    if stored_challenge_b64 != challenge_b64:
        return _error("Challenge mismatch.", "authentication_denied", 403)

    if not verify_signature(device["public_key_b64"], signature, challenge):
        return _error("Invalid signature.", "authentication_denied", 403)

    if not consume_device_challenge(
        _database_path(),
        user_id,
        device_id,
        challenge_b64,
    ):
        return _error("Challenge no longer valid.", "authentication_denied", 403)

    return jsonify({"status": "success", "message": "Login OK"})


@app.route("/device/revoke", methods=["POST"])
def revoke_device_route():
    """Retired because authenticator revocation is trusted local administration."""
    return _error(
        "Authenticator revocation is available through the local administration CLI.",
        "administration_required",
        403,
    )


if __name__ == "__main__":
    print("[+] Server running on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", debug=False)
