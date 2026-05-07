from flask import Flask, request, jsonify
import base64
import os
import secrets
import hashlib  # for SHA-256 on the server side

from crypto_utils import verify_signature
from db_utils import (
    load_database,
    save_database,
    get_user,
    register_device,
    get_device,
    list_devices,
    set_device_challenge,
    revoke_device
)

app = Flask(__name__)

# Load the JSON "database" once at startup
db = load_database()


def _compute_device_hash_server(user_id: str, device_id: str, public_key_b64: str) -> str:
    """
    Recompute the SHA-256 device binding hash on the server side:
        user_id || device_id || public_key_pem
    using the stored base64-encoded public key.
    """
    public_pem = base64.b64decode(public_key_b64)
    h = hashlib.sha256()
    h.update(user_id.encode("utf-8"))
    h.update(device_id.encode("utf-8"))
    h.update(public_pem)
    return h.hexdigest()


@app.route("/")
def home():
    return jsonify({
        "message": "Passwordless Auth Server Running",
        "endpoints": ["/register_device", "/login/request_challenge", "/login/verify", "/device/revoke"]
    })


@app.route("/health")
def health():
    return jsonify({"status": "OK"})


@app.route("/register_device", methods=["POST"])
def register():
    data = request.json
    user_id = data["user_id"]
    device_id = data["device_id"]
    public_key_b64 = data["public_key_b64"]

    # integrity hash should normally come from the client (SHA-256 binding)
    integrity_hash = data.get("integrity_hash")

    # Fallback for old clients: if no integrity hash is supplied, generate one.
    # For this project, the GUI client always sends a real integrity_hash.
    if integrity_hash is None:
        integrity_hash = secrets.token_hex(32)

    register_device(db, user_id, device_id, public_key_b64, integrity_hash)
    save_database(db)

    return jsonify({
        "status": "success",
        "integrity_hash": integrity_hash,
        "message": f"Device '{device_id}' registered for '{user_id}'"
    })


@app.route("/login/request_challenge", methods=["POST"])
def request_challenge():
    data = request.json
    user_id = data["user_id"]
    device_id = data["device_id"]

    device = get_device(db, user_id, device_id)

    # Unknown or revoked device: no challenge
    if not device or device.get("revoked"):
        return jsonify({"error": "Unknown or revoked device"}), 403

    # device integrity check using SHA-256 binding hash
    stored_hash = device.get("integrity_hash")
    public_key_b64 = device.get("public_key_b64")

    if stored_hash and public_key_b64:
        expected_hash = _compute_device_hash_server(user_id, device_id, public_key_b64)
        if stored_hash != expected_hash:
            return jsonify({"error": "Device integrity check failed"}), 403

    # If integrity is OK, generate a fresh challenge
    challenge = os.urandom(32)
    challenge_b64 = base64.b64encode(challenge).decode()

    set_device_challenge(db, user_id, device_id, challenge_b64)
    save_database(db)

    return jsonify({"challenge": challenge_b64})


@app.route("/login/verify", methods=["POST"])
def verify_login():
    """
    Verify the client's signature over the server-issued challenge.

    Behaviour matches the report:
    - Checks revocation status before verification.
    - Ensures the provided challenge matches the stored challenge.
    - Clears the stored challenge only after successful verification.
    """
    data = request.json
    user_id = data["user_id"]
    device_id = data["device_id"]
    challenge_b64 = data["challenge"]
    signature_b64 = data["signature"]

    device = get_device(db, user_id, device_id)

    # Device must exist
    if not device:
        return jsonify({"error": "Unknown device"}), 403

    # Enforce revocation BEFORE any signature verification,
    # as described in the report.
    if device.get("revoked"):
        return jsonify({"error": "Device revoked"}), 403

    # There must be a stored challenge for this device
    stored_challenge_b64 = device.get("challenge")
    if not stored_challenge_b64:
        return jsonify({"error": "No challenge found"}), 403

    # The client-supplied challenge must match the stored challenge exactly.
    # This ensures the challenge has not been tampered with or substituted.
    if stored_challenge_b64 != challenge_b64:
        return jsonify({"error": "Challenge mismatch"}), 403

    # Decode signature and challenge for cryptographic verification
    try:
        signature = base64.b64decode(signature_b64)
        challenge = base64.b64decode(challenge_b64)
    except Exception:
        return jsonify({"error": "Invalid base64 in challenge or signature"}), 400

    public_key_b64 = device["public_key_b64"]

    # Verify the digital signature over the original challenge
    if verify_signature(public_key_b64, signature, challenge):
        # On success, clear the challenge so it cannot be reused.
        device["challenge"] = None
        save_database(db)
        return jsonify({"status": "success", "message": "Login OK"})
    else:
        return jsonify({"error": "Invalid signature"}), 403


@app.route("/device/revoke", methods=["POST"])
def revoke_device_route():
    """
    Revoke a specific device for a user.

    JSON example:
        { "user_id": "student1", "device_id": "laptop1" }

    After revocation:
    - The device cannot obtain new challenges.
    - Any outstanding challenge is cleared in db_utils.revoke_device.
    - /login/verify will also reject the device immediately.
    """
    data = request.json
    user_id = data.get("user_id")
    device_id = data.get("device_id")

    if not user_id or not device_id:
        return jsonify({"error": "user_id and device_id are required"}), 400

    device = get_device(db, user_id, device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    revoke_device(db, user_id, device_id)
    save_database(db)

    return jsonify({
        "status": "revoked",
        "message": f"Device '{device_id}' for user '{user_id}' has been revoked"
    })


if __name__ == "__main__":
    print("[+] Server running on http://127.0.0.1:5000")
    app.run(debug=True)
