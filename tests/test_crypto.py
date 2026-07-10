import base64
import unittest

from crypto_utils import (
    decrypt_private_key,
    encrypt_private_key,
    generate_aes_key,
    generate_rsa_keypair,
    sign_challenge,
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


if __name__ == "__main__":
    unittest.main()

