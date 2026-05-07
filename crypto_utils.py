import os
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RSA key generation & signatures


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


def verify_signature(public_key_b64: str, signature: bytes, challenge: bytes) -> bool:
    """
    Verify RSA signature of a challenge.
    public_key_b64: base64-encoded PEM public key (string).
    signature: raw signature bytes.
    challenge: original challenge bytes.
    Returns True if valid, False otherwise.
    """
    public_pem = base64.b64decode(public_key_b64)
    public_key = serialization.load_pem_public_key(public_pem)

    try:
        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


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


# -----------------------------
# SHA-256 device binding hash
# -----------------------------

def compute_device_hash(user_id: str, device_id: str, public_key_pem: bytes) -> str:
    """
    Compute a SHA-256 integrity hash binding:
        user_id || device_id || public_key_pem

    This can be stored on the server to detect tampering or device cloning.
    Returns hex string.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(user_id.encode("utf-8"))
    digest.update(device_id.encode("utf-8"))
    digest.update(public_key_pem)
    return digest.finalize().hex()
