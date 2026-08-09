"""Local passphrase-protected credential files for the CLI client.

Credential-v1 deliberately accepts one small, application-owned format.  Keeping
the format and the filesystem rules here prevents the HTTP client from having to
reason about encryption, temporary files, and partial local state.
"""

import base64
import binascii
import hashlib
import json
import os
import stat
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from crypto_utils import validate_rsa_public_key
from db_utils import validate_identifier


CREDENTIAL_FORMAT = "PKAS-CREDENTIAL-V1"
AAD_DOMAIN = b"PKAS-CREDENTIAL-AAD-V1"
PATH_DOMAIN = b"PKAS-CREDENTIAL-PATH-V1"
MAX_CREDENTIAL_BYTES = 16 * 1024
SALT_BYTES = 16
NONCE_BYTES = 12
DERIVED_KEY_BYTES = 32
ARGON2_MEMORY_KIB = 65536
ARGON2_ITERATIONS = 3
ARGON2_LANES = 4


class CredentialError(Exception):
    """A bounded local credential error suitable for CLI/UI reporting."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _validate_scope(user_id, device_id):
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")


def _validate_fingerprint(fingerprint):
    if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
        raise CredentialError("invalid_credential", "Credential fingerprint is invalid.")
    value = fingerprint[len("SHA256:") :]
    if len(value) != 43:
        raise CredentialError("invalid_credential", "Credential fingerprint is invalid.")
    try:
        decoded = base64.b64decode(value + "=", validate=True)
    except binascii.Error as exc:
        raise CredentialError("invalid_credential", "Credential fingerprint is invalid.") from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise CredentialError("invalid_credential", "Credential fingerprint is invalid.")


def _passphrase_bytes(passphrase, creating=False):
    if not isinstance(passphrase, str):
        raise CredentialError("invalid_passphrase", "A passphrase is required.")
    normalized = unicodedata.normalize("NFC", passphrase)
    encoded = normalized.encode("utf-8")
    if not encoded or len(encoded) > 1024:
        raise CredentialError("invalid_passphrase", "Passphrase length is not supported.")
    if creating and len(normalized) < 15:
        raise CredentialError(
            "passphrase_policy",
            "Choose a passphrase with at least 15 characters.",
        )
    return encoded


def get_default_credential_directory():
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "PublicKeyAuthenticationSystem" / "credentials"
    return Path.home() / ".local" / "share" / "PublicKeyAuthenticationSystem" / "credentials"


def _scope_digest(user_id, device_id):
    values = (user_id.encode("utf-8"), device_id.encode("utf-8"))
    encoded = b"".join(len(value).to_bytes(4, "big") + value for value in values)
    return hashlib.sha256(PATH_DOMAIN + encoded).hexdigest()


def credential_paths(user_id, device_id, credential_directory=None):
    """Return safe current/pending locations without using identifiers as names."""
    _validate_scope(user_id, device_id)
    root = Path(credential_directory or get_default_credential_directory())
    digest = _scope_digest(user_id, device_id)
    return root / f"{digest}.credential.json", root / f"{digest}.pending.json"


def _ensure_directory(path):
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise CredentialError("storage_unavailable", "Credential storage is unavailable.") from exc
    if not path.is_dir() or path.is_symlink():
        raise CredentialError("storage_unavailable", "Credential storage is unavailable.")


def _require_regular_file(path):
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        raise CredentialError("credential_missing", "Credential file does not exist.")
    except OSError as exc:
        raise CredentialError("storage_unavailable", "Credential storage is unavailable.") from exc
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        raise CredentialError("invalid_credential", "Credential path is not a regular file.")


def _read_bounded(path):
    _require_regular_file(path)
    try:
        with path.open("rb") as credential_file:
            data = credential_file.read(MAX_CREDENTIAL_BYTES + 1)
    except OSError as exc:
        raise CredentialError("storage_unavailable", "Credential could not be read.") from exc
    if len(data) > MAX_CREDENTIAL_BYTES:
        raise CredentialError("invalid_credential", "Credential is too large.")
    return data


def _strict_b64(value, field_name):
    if not isinstance(value, str):
        raise CredentialError("invalid_credential", f"Credential {field_name} is invalid.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CredentialError("invalid_credential", f"Credential {field_name} is invalid.") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CredentialError("invalid_credential", f"Credential {field_name} is invalid.")
    return decoded


def _reject_duplicate_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("invalid_credential", "Credential contains duplicate fields.")
        result[key] = value
    return result


def _parse_envelope(data):
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_reject_duplicate_object
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialError("invalid_credential", "Credential format is invalid.") from exc
    required_fields = {
        "format",
        "user_id",
        "device_id",
        "public_key_fingerprint",
        "salt_b64",
        "nonce_b64",
        "ciphertext_b64",
    }
    if not isinstance(value, dict) or set(value) != required_fields:
        raise CredentialError("invalid_credential", "Credential format is not supported.")
    if any(not isinstance(item, str) for item in value.values()):
        raise CredentialError("invalid_credential", "Credential format is invalid.")
    if value["format"] != CREDENTIAL_FORMAT:
        raise CredentialError("invalid_credential", "Credential format is not supported.")
    try:
        _validate_scope(value["user_id"], value["device_id"])
    except ValueError as exc:
        raise CredentialError("invalid_credential", "Credential scope is invalid.") from exc
    _validate_fingerprint(value["public_key_fingerprint"])
    salt = _strict_b64(value["salt_b64"], "salt")
    nonce = _strict_b64(value["nonce_b64"], "nonce")
    ciphertext = _strict_b64(value["ciphertext_b64"], "ciphertext")
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise CredentialError("invalid_credential", "Credential cryptographic fields are invalid.")
    if not 17 <= len(ciphertext) <= 8192:
        raise CredentialError("invalid_credential", "Credential ciphertext is invalid.")
    return value, salt, nonce, ciphertext


def _length_field(value):
    return len(value).to_bytes(4, "big") + value


def credential_aad(user_id, device_id, fingerprint, salt, nonce):
    """Return credential-v1 authenticated context without JSON formatting dependence."""
    fields = (
        CREDENTIAL_FORMAT.encode("utf-8"),
        user_id.encode("utf-8"),
        device_id.encode("utf-8"),
        fingerprint.encode("utf-8"),
        salt,
        nonce,
    )
    return AAD_DOMAIN + b"".join(_length_field(field) for field in fields)


def _derive_key(passphrase, salt):
    try:
        return Argon2id(
            salt=salt,
            length=DERIVED_KEY_BYTES,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
        ).derive(_passphrase_bytes(passphrase))
    except UnsupportedAlgorithm as exc:
        raise CredentialError("storage_unavailable", "Argon2id is unavailable in this environment.") from exc


def _rsa_private_key(private_key_pem):
    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise CredentialError("invalid_credential", "Private key material is invalid.") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise CredentialError("invalid_credential", "Only RSA private keys of at least 2048 bits are supported.")
    return key


def _private_key_details_from_key(key):
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64, fingerprint = validate_rsa_public_key(
        base64.b64encode(public_pem).decode("ascii")
    )
    private_key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return private_key_pem, public_key_b64, fingerprint


def create_credential_bytes(private_key_pem, user_id, device_id, passphrase):
    """Create one credential-v1 envelope and return its bytes and fingerprint."""
    _validate_scope(user_id, device_id)
    passphrase_bytes = _passphrase_bytes(passphrase, creating=True)
    key = _rsa_private_key(private_key_pem)
    _, _, fingerprint = _private_key_details_from_key(key)
    private_key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    try:
        derived_key = Argon2id(
            salt=salt,
            length=DERIVED_KEY_BYTES,
            iterations=ARGON2_ITERATIONS,
            lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
        ).derive(passphrase_bytes)
    except UnsupportedAlgorithm as exc:
        raise CredentialError("storage_unavailable", "Argon2id is unavailable in this environment.") from exc
    ciphertext = AESGCM(derived_key).encrypt(
        nonce,
        private_key_der,
        credential_aad(user_id, device_id, fingerprint, salt, nonce),
    )
    envelope = {
        "format": CREDENTIAL_FORMAT,
        "user_id": user_id,
        "device_id": device_id,
        "public_key_fingerprint": fingerprint,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CREDENTIAL_BYTES:
        raise CredentialError("invalid_credential", "Credential is too large.")
    return encoded, fingerprint


def load_credential_bytes(data, user_id, device_id, passphrase):
    """Unlock credential-v1 bytes and return PEM, canonical public key, fingerprint."""
    envelope, salt, nonce, ciphertext = _parse_envelope(data)
    _validate_scope(user_id, device_id)
    if envelope["user_id"] != user_id or envelope["device_id"] != device_id:
        raise CredentialError("invalid_credential", "Credential scope does not match this authenticator.")
    derived_key = _derive_key(passphrase, salt)
    try:
        private_key_der = AESGCM(derived_key).decrypt(
            nonce,
            ciphertext,
            credential_aad(
                envelope["user_id"],
                envelope["device_id"],
                envelope["public_key_fingerprint"],
                salt,
                nonce,
            ),
        )
    except InvalidTag as exc:
        raise CredentialError(
            "credential_unlock_failed_or_corrupt",
            "Credential unlock failed or the credential is corrupt.",
        ) from exc
    try:
        key = serialization.load_der_private_key(private_key_der, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise CredentialError(
            "credential_unlock_failed_or_corrupt",
            "Credential unlock failed or the credential is corrupt.",
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise CredentialError(
            "credential_unlock_failed_or_corrupt",
            "Credential unlock failed or the credential is corrupt.",
        )
    private_key_pem, public_key_b64, fingerprint = _private_key_details_from_key(key)
    if fingerprint != envelope["public_key_fingerprint"]:
        raise CredentialError(
            "credential_unlock_failed_or_corrupt",
            "Credential unlock failed or the credential is corrupt.",
        )
    return private_key_pem, public_key_b64, fingerprint


def load_credential(path, user_id, device_id, passphrase):
    return load_credential_bytes(_read_bounded(path), user_id, device_id, passphrase)


def _write_temporary(path, content):
    _ensure_directory(path.parent)
    temporary = path.parent / f".{path.name}.{os.urandom(12).hex()}.tmp"
    try:
        with temporary.open("xb") as credential_file:
            credential_file.write(content)
            credential_file.flush()
            os.fsync(credential_file.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
    except OSError as exc:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise CredentialError("storage_unavailable", "Credential could not be written.") from exc
    return temporary


def publish_credential(path, content, user_id, device_id, passphrase):
    """Create path exactly once from validated bytes; never replace an occupant."""
    temporary = _write_temporary(path, content)
    try:
        load_credential(temporary, user_id, device_id, passphrase)
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CredentialError("credential_exists", "Credential location is already occupied.") from exc
        except OSError as exc:
            raise CredentialError("storage_unavailable", "Credential could not be published safely.") from exc
        load_credential(path, user_id, device_id, passphrase)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # The complete published file remains usable; a random temporary link
            # is not used for normal credential discovery.
            pass


def credentials_are_same(current_path, pending_path, user_id, device_id, passphrase):
    """Require both migration links to unlock to the same credential identity."""
    current = load_credential(current_path, user_id, device_id, passphrase)
    pending = load_credential(pending_path, user_id, device_id, passphrase)
    try:
        same_file = os.path.samefile(current_path, pending_path)
    except OSError as exc:
        raise CredentialError("storage_unavailable", "Credential links could not be inspected.") from exc
    return same_file and current[2] == pending[2]


def _is_structurally_recognized(path, user_id, device_id):
    """Check nonsecret envelope structure without deriving a passphrase key."""
    try:
        envelope, _, _, _ = _parse_envelope(_read_bounded(path))
    except CredentialError as exc:
        if exc.code in {"credential_missing", "invalid_credential"}:
            return False
        raise
    return envelope["user_id"] == user_id and envelope["device_id"] == device_id


def describe_local_state(user_id, device_id, credential_directory=None):
    """Describe recognized nonsecret local state without decrypting a credential."""
    current_path, pending_path = credential_paths(user_id, device_id, credential_directory)
    current_exists = current_path.exists() or current_path.is_symlink()
    pending_exists = pending_path.exists() or pending_path.is_symlink()
    if not current_exists and not pending_exists:
        return "absent", current_path, pending_path
    current_valid = current_exists and _is_structurally_recognized(
        current_path, user_id, device_id
    )
    pending_valid = pending_exists and _is_structurally_recognized(
        pending_path, user_id, device_id
    )
    if current_exists and not current_valid:
        return "invalid_or_conflicting", current_path, pending_path
    if pending_exists and not pending_valid:
        return "invalid_or_conflicting", current_path, pending_path
    if current_valid and not pending_exists:
        return "current", current_path, pending_path
    if not current_exists and pending_valid:
        return "pending_unclaimed", current_path, pending_path
    return "mixed_or_conflicting", current_path, pending_path
