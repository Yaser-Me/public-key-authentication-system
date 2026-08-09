import base64
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

import credential_store
from credential_store import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_KIB,
    CredentialError,
    MAX_CREDENTIAL_BYTES,
    create_credential_bytes,
    credential_paths,
    load_credential,
    load_credential_bytes,
    publish_credential,
)
from crypto_utils import generate_rsa_keypair


PASSPHRASE = "correct horse battery"


def independent_aad(envelope, salt, nonce):
    fields = (
        b"PKAS-CREDENTIAL-V1",
        envelope["user_id"].encode("utf-8"),
        envelope["device_id"].encode("utf-8"),
        envelope["public_key_fingerprint"].encode("utf-8"),
        salt,
        nonce,
    )
    return b"PKAS-CREDENTIAL-AAD-V1" + b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self._temp_dir.name)
        self.user_id = "student1"
        self.device_id = "laptop1"
        self.private_key_pem, _ = generate_rsa_keypair()

    def tearDown(self):
        self._temp_dir.cleanup()

    def _credential(self):
        return create_credential_bytes(
            self.private_key_pem, self.user_id, self.device_id, PASSPHRASE
        )

    def test_v1_contract_is_independently_decryptable(self):
        credential_bytes, expected_fingerprint = self._credential()
        envelope = json.loads(credential_bytes)
        salt = base64.b64decode(envelope["salt_b64"], validate=True)
        nonce = base64.b64decode(envelope["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext_b64"], validate=True)
        self.assertEqual(len(salt), 16)
        self.assertEqual(len(nonce), 12)

        derived_key = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        ).derive(PASSPHRASE.encode("utf-8"))
        private_key_der = AESGCM(derived_key).decrypt(
            nonce, ciphertext, independent_aad(envelope, salt, nonce)
        )
        private_key = serialization.load_der_private_key(private_key_der, password=None)
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(public_der).digest()
        ).decode("ascii").rstrip("=")

        self.assertEqual(envelope["format"], "PKAS-CREDENTIAL-V1")
        self.assertEqual(fingerprint, expected_fingerprint)
        self.assertEqual(ARGON2_MEMORY_KIB, 65536)
        self.assertEqual(ARGON2_ITERATIONS, 3)
        self.assertEqual(ARGON2_LANES, 4)

    def test_scope_tamper_unknown_fields_and_wrong_passphrase_fail_closed(self):
        credential_bytes, _ = self._credential()
        envelope = json.loads(credential_bytes)
        envelope["device_id"] = "other-device"
        tampered = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(CredentialError):
            load_credential_bytes(tampered, self.user_id, "other-device", PASSPHRASE)

        envelope = json.loads(credential_bytes)
        envelope["memory_cost"] = "1"
        injected = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        with patch("credential_store.Argon2id", side_effect=AssertionError("KDF used")):
            with self.assertRaises(CredentialError):
                load_credential_bytes(injected, self.user_id, self.device_id, PASSPHRASE)

        with self.assertRaises(CredentialError) as failed_unlock:
            load_credential_bytes(
                credential_bytes, self.user_id, self.device_id, "different passphrase"
            )
        self.assertEqual(failed_unlock.exception.code, "credential_unlock_failed_or_corrupt")

    def test_argon2_memory_failure_is_classified_without_creating_a_credential(self):
        with patch("credential_store.Argon2id", side_effect=MemoryError):
            with self.assertRaises(CredentialError) as error:
                create_credential_bytes(
                    self.private_key_pem, self.user_id, self.device_id, PASSPHRASE
                )
        self.assertEqual(error.exception.code, "storage_unavailable")

    def test_bounded_reader_requests_only_limit_plus_one(self):
        path = self.root / "oversized.credential"
        path.write_bytes(b"x")
        calls = []

        class TrackedFile:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                calls.append(size)
                return b"x" * size

        with patch.object(Path, "open", return_value=TrackedFile()):
            with self.assertRaises(CredentialError) as error:
                credential_store._read_bounded(path)
        self.assertEqual(error.exception.code, "invalid_credential")
        self.assertEqual(calls, [MAX_CREDENTIAL_BYTES + 1])

    def test_existing_final_content_is_not_replaced(self):
        credential_bytes, _ = self._credential()
        path = self.root / "occupied.credential"
        path.write_bytes(b"corrupt occupant")
        with self.assertRaises(CredentialError) as error:
            publish_credential(
                path, credential_bytes, self.user_id, self.device_id, PASSPHRASE
            )
        self.assertEqual(error.exception.code, "credential_exists")
        self.assertEqual(path.read_bytes(), b"corrupt occupant")

    def test_real_hard_link_race_has_one_complete_winner(self):
        first_bytes, _ = self._credential()
        second_key, _ = generate_rsa_keypair()
        second_bytes, _ = create_credential_bytes(
            second_key, self.user_id, self.device_id, PASSPHRASE
        )
        path = self.root / "race.credential"
        barrier = threading.Barrier(2)
        original_link = credential_store.os.link
        original_argon2id = credential_store.Argon2id
        errors = []
        kdf_lock = threading.Lock()

        class SerializedArgon2id:
            def __init__(self, *args, **kwargs):
                self._argon2id = original_argon2id(*args, **kwargs)

            def derive(self, passphrase):
                # This test measures hard-link publication concurrency. Keep the
                # real KDF but avoid exhausting constrained CI runners first.
                with kdf_lock:
                    return self._argon2id.derive(passphrase)

        def link_with_barrier(source, destination):
            barrier.wait(timeout=5)
            return original_link(source, destination)

        def publish(content):
            try:
                publish_credential(path, content, self.user_id, self.device_id, PASSPHRASE)
            except CredentialError as exc:
                errors.append(exc.code)

        with patch.object(credential_store, "Argon2id", SerializedArgon2id), patch.object(
            credential_store.os, "link", side_effect=link_with_barrier
        ):
            first = threading.Thread(target=publish, args=(first_bytes,))
            second = threading.Thread(target=publish, args=(second_bytes,))
            first.start()
            second.start()
            first.join(15)
            second.join(15)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, ["credential_exists"])
        _, _, fingerprint = load_credential(path, self.user_id, self.device_id, PASSPHRASE)
        self.assertIn(fingerprint, {
            json.loads(first_bytes)["public_key_fingerprint"],
            json.loads(second_bytes)["public_key_fingerprint"],
        })

    def test_scope_paths_do_not_alias_case_or_separator_values(self):
        first = credential_paths("student1", "laptop1", self.root)[0]
        second = credential_paths("student1", "Laptop1", self.root)[0]
        third = credential_paths("student1", "laptop-1", self.root)[0]
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)
        self.assertEqual(first.parent, self.root)


if __name__ == "__main__":
    unittest.main()
