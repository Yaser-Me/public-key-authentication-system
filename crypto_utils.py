import base64
import binascii
import hashlib
import os

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RSA key generation & signatures

ENROLLMENT_PROOF_DOMAIN = b"PKAS-ENROLLMENT-PROOF-V1"


def _enrollment_proof_message(authorization_id, user_id, device_id, fingerprint):
    """Encode enrollment context unambiguously before signing it."""
    values = (authorization_id, user_id, device_id, fingerprint)
    encoded_values = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Enrollment proof fields must be text.")
        encoded = value.encode("utf-8")
        encoded_values.append(len(encoded).to_bytes(4, "big") + encoded)
    return ENROLLMENT_PROOF_DOMAIN + b"".join(encoded_values)


def generate_rsa_keypair():
    """
    Generate an RSA 2048-bit key pair.
    Returns (private_key_pem_bytes, public_key_pem_bytes).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def sign_challenge(private_key_pem: bytes, challenge: bytes) -> bytes:
    """
    Sign a challenge using RSA + SHA-256.
    private_key_pem: private key in PEM format (bytes).
    challenge: random bytes from server.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        challenge,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def sign_enrollment_proof(
    private_key_pem: bytes, authorization_id, user_id, device_id, fingerprint
) -> bytes:
    """Sign the fixed proof-v1 enrollment context with RSA-PSS and SHA-256."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Only RSA private keys can create enrollment proofs.")
    return private_key.sign(
        _enrollment_proof_message(authorization_id, user_id, device_id, fingerprint),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        ),
        hashes.SHA256(),
    )


def parse_rsa_public_key(public_key_b64: str):
    """Validate and normalize a base64-encoded RSA public key."""
    if not isinstance(public_key_b64, str) or not public_key_b64:
        raise ValueError("A public key is required.")

    try:
        public_pem = base64.b64decode(public_key_b64, validate=True)
        public_key = serialization.load_pem_public_key(public_pem)
    except (binascii.Error, TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("The public key is not valid base64-encoded PEM.") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported.")
    if public_key.key_size < 2048:
        raise ValueError("RSA public keys must be at least 2048 bits.")

    canonical_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    canonical_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    canonical_b64 = base64.b64encode(canonical_pem).decode("ascii")
    fingerprint_digest = hashlib.sha256(canonical_der).digest()
    fingerprint = (
        "SHA256:"
        + base64.b64encode(fingerprint_digest).decode("ascii").rstrip("=")
    )
    return public_key, canonical_b64, fingerprint


def validate_rsa_public_key(public_key_b64: str):
    """Return the canonical public key and SHA-256 fingerprint."""
    _, canonical_b64, fingerprint = parse_rsa_public_key(public_key_b64)
    return canonical_b64, fingerprint


def verify_signature(public_key_b64: str, signature: bytes, challenge: bytes) -> bool:
    """
    Verify RSA signature of a challenge.
    public_key_b64: base64-encoded PEM public key (string).
    signature: raw signature bytes.
    challenge: original challenge bytes.
    Returns True if valid, False otherwise.
    """
    try:
        public_key, _, _ = parse_rsa_public_key(public_key_b64)
        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def verify_enrollment_proof(
    public_key_b64: str,
    signature: bytes,
    authorization_id,
    user_id,
    device_id,
    fingerprint,
) -> bool:
    """Verify the dedicated RSA-PSS enrollment proof without changing login."""
    try:
        public_key, _, _ = parse_rsa_public_key(public_key_b64)
        public_key.verify(
            signature,
            _enrollment_proof_message(
                authorization_id,
                user_id,
                device_id,
                fingerprint,
            ),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def public_key_b64_from_private_key(private_key_pem: bytes) -> str:
    """Return the canonical public-key representation for an existing client key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Only RSA private keys are supported.")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    canonical_b64, _ = validate_rsa_public_key(
        base64.b64encode(public_pem).decode("ascii")
    )
    return canonical_b64


# -----------------------------
# AES-256-GCM for private key protection
# -----------------------------

def generate_aes_key() -> bytes:
    """
    Generate a random 256-bit AES key (32 bytes).
    This key stays on the client and is used to encrypt the private key at rest.
    """
    return os.urandom(32)


def encrypt_private_key(aes_key: bytes, private_key_pem: bytes) -> str:
    """
    Encrypt the private key PEM using AES-256-GCM.
    Returns a base64 string containing nonce || ciphertext || tag.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # recommended size for GCM nonce
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, associated_data=None)

    # Store nonce + ciphertext together, then base64 encode
    data = nonce + ciphertext
    return base64.b64encode(data).decode()


def decrypt_private_key(aes_key: bytes, enc_data_b64: str) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted private key (base64(nonce || ciphertext || tag)).
    Returns the original private key PEM bytes.
    """
    data = base64.b64decode(enc_data_b64)
    nonce = data[:12]
    ciphertext = data[12:]

    aesgcm = AESGCM(aes_key)
    private_key_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return private_key_pem
