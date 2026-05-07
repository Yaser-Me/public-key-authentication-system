import json
import os

DB_FILE = "database.json"


def load_database():
    """
    Safely load the JSON database.
    Returns an empty dict if the file does not exist or is corrupted.
    """
    if not os.path.exists(DB_FILE):
        return {}

    if os.path.getsize(DB_FILE) == 0:
        return {}

    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_database(db):
    """Write DB content back to the JSON file."""
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)


def get_user(db, user_id):
    """Get user entry if exists, otherwise None."""
    return db.get(user_id)


def register_device(db, user_id, device_id, public_key_b64, integrity_hash):
    """
    Add a new device under the user entry.
    Creates the user entry if it doesn't exist yet.
    """
    if user_id not in db:
        db[user_id] = {"devices": {}}

    db[user_id]["devices"][device_id] = {
        "public_key_b64": public_key_b64,
        "integrity_hash": integrity_hash,
        "challenge": None,
        "revoked": False
    }

    return db


def get_device(db, user_id, device_id):
    """Return the device dict if it exists, or None."""
    if user_id not in db:
        return None
    return db[user_id]["devices"].get(device_id)


def list_devices(db, user_id):
    """Return all devices registered for a user."""
    if user_id not in db:
        return {}
    return db[user_id]["devices"]


def set_device_challenge(db, user_id, device_id, challenge_b64):
    """Store the generated login challenge for this device."""
    device = get_device(db, user_id, device_id)
    if device:
        device["challenge"] = challenge_b64
    return db


def revoke_device(db, user_id, device_id):
    """
    Mark a registered device as revoked and clear any outstanding challenge.

    This matches the report's description:
    - A revoked device cannot obtain new challenges.
    - Any existing challenge is invalidated immediately.
    - /login/verify will reject before signature verification.
    """
    device = get_device(db, user_id, device_id)
    if device:
        device["revoked"] = True
        device["challenge"] = None  # ← required for full report consistency
    return db
