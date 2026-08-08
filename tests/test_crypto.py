import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from crypto_utils import (
    decrypt_private_key,
    encrypt_private_key,
    generate_aes_key,
    generate_rsa_keypair,
    sign_challenge,
    validate_rsa_public_key,
    verify_signature,
)


class CryptoTests(unittest.TestCase):
    def test_signature_round_trip(self):
        private_key, public_key = generate_rsa_keypair()
        challenge = b"ci-signature-test"
        signature = sign_challenge(private_key, challenge)

        self.assertTrue(
            verify_signature(
                base64.b64encode(public_key).decode(),
                signature,
                challenge,
            )
        )

    def test_modified_challenge_is_rejected(self):
        private_key, public_key = generate_rsa_keypair()
        signature = sign_challenge(private_key, b"original")

        self.assertFalse(
            verify_signature(
                base64.b64encode(public_key).decode(),
                signature,
                b"modified",
            )
        )

    def test_private_key_encryption_round_trip(self):
        private_key, _ = generate_rsa_keypair()
        aes_key = generate_aes_key()
        encrypted = encrypt_private_key(aes_key, private_key)

        self.assertEqual(decrypt_private_key(aes_key, encrypted), private_key)

    def test_rsa_public_key_validation_returns_stable_fingerprint(self):
        _, public_key = generate_rsa_keypair()
        public_key_b64 = base64.b64encode(public_key).decode("ascii")

        canonical_b64, first_fingerprint = validate_rsa_public_key(public_key_b64)
        _, second_fingerprint = validate_rsa_public_key(canonical_b64)

        self.assertEqual(first_fingerprint, second_fingerprint)
        self.assertTrue(first_fingerprint.startswith("SHA256:"))

    def test_non_rsa_and_malformed_public_keys_are_rejected(self):
        ed25519_public_key = ed25519.Ed25519PrivateKey.generate().public_key()
        ed25519_pem = ed25519_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with self.assertRaises(ValueError):
            validate_rsa_public_key(base64.b64encode(ed25519_pem).decode("ascii"))

        small_rsa_public_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        ).public_key()
        small_rsa_pem = small_rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaises(ValueError):
            validate_rsa_public_key(base64.b64encode(small_rsa_pem).decode("ascii"))

        with self.assertRaises(ValueError):
            validate_rsa_public_key("!!!!")
        self.assertFalse(verify_signature("!!!!", b"signature", b"challenge"))


if __name__ == "__main__":
    unittest.main()

