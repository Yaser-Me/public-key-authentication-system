import base64
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from crypto_utils import (
    _enrollment_proof_message,
    decrypt_private_key,
    encrypt_private_key,
    generate_aes_key,
    generate_rsa_keypair,
    public_key_b64_from_private_key,
    sign_challenge,
    sign_enrollment_proof,
    validate_rsa_public_key,
    verify_enrollment_proof,
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

    def test_enrollment_proof_uses_pss_and_binds_every_context_field(self):
        private_key, public_key = generate_rsa_keypair()
        public_key_b64 = base64.b64encode(public_key).decode("ascii")
        context = ("grant-123", "student1", "laptop1", "SHA256:fingerprint")
        signature = sign_enrollment_proof(private_key, *context)

        self.assertTrue(verify_enrollment_proof(public_key_b64, signature, *context))
        for changed_context in (
            ("grant-456", "student1", "laptop1", "SHA256:fingerprint"),
            ("grant-123", "student2", "laptop1", "SHA256:fingerprint"),
            ("grant-123", "student1", "tablet1", "SHA256:fingerprint"),
            ("grant-123", "student1", "laptop1", "SHA256:other"),
        ):
            with self.subTest(changed_context=changed_context):
                self.assertFalse(
                    verify_enrollment_proof(public_key_b64, signature, *changed_context)
                )

    def test_enrollment_proof_v1_encoding_and_pss_parameters_are_independent(self):
        private_key_pem, public_key_pem = generate_rsa_keypair()
        context = ("grant-123", "student1", "laptop1", "SHA256:fingerprint")
        expected_message = (
            b"PKAS-ENROLLMENT-PROOF-V1"
            b"\x00\x00\x00\x09grant-123"
            b"\x00\x00\x00\x08student1"
            b"\x00\x00\x00\x07laptop1"
            b"\x00\x00\x00\x12SHA256:fingerprint"
        )
        self.assertEqual(_enrollment_proof_message(*context), expected_message)

        project_signature = sign_enrollment_proof(private_key_pem, *context)
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            project_signature,
            expected_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        independent_signature = private_key.sign(
            expected_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
        public_key_b64 = base64.b64encode(public_key_pem).decode("ascii")
        self.assertNotEqual(project_signature, independent_signature)
        self.assertTrue(
            verify_enrollment_proof(public_key_b64, independent_signature, *context)
        )

    def test_enrollment_proof_rejects_wrong_key_and_legacy_signature(self):
        private_key, public_key = generate_rsa_keypair()
        wrong_private_key, _ = generate_rsa_keypair()
        public_key_b64 = base64.b64encode(public_key).decode("ascii")
        context = ("grant-123", "student1", "laptop1", "SHA256:fingerprint")

        wrong_signature = sign_enrollment_proof(wrong_private_key, *context)
        legacy_signature = sign_challenge(private_key, b"not enrollment proof v1")

        self.assertFalse(
            verify_enrollment_proof(public_key_b64, wrong_signature, *context)
        )
        self.assertFalse(
            verify_enrollment_proof(public_key_b64, legacy_signature, *context)
        )

    def test_private_key_encryption_round_trip(self):
        private_key, _ = generate_rsa_keypair()
        aes_key = generate_aes_key()
        encrypted = encrypt_private_key(aes_key, private_key)

        self.assertEqual(decrypt_private_key(aes_key, encrypted), private_key)

    def test_rsa_public_key_validation_returns_stable_fingerprint(self):
        private_key, public_key = generate_rsa_keypair()
        public_key_b64 = base64.b64encode(public_key).decode("ascii")

        canonical_b64, first_fingerprint = validate_rsa_public_key(public_key_b64)
        _, second_fingerprint = validate_rsa_public_key(canonical_b64)

        self.assertEqual(first_fingerprint, second_fingerprint)
        self.assertTrue(first_fingerprint.startswith("SHA256:"))
        self.assertEqual(public_key_b64_from_private_key(private_key), canonical_b64)

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
