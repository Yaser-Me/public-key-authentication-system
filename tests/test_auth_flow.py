import base64
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db_utils
from crypto_utils import (
    compute_device_hash,
    generate_rsa_keypair,
    sign_challenge,
)


class AuthenticationFlowTests(unittest.TestCase):
    """Characterize the current Flask authentication behavior."""

    @classmethod
    def setUpClass(cls):
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._database_path = Path(cls._temp_dir.name) / "database.json"
        cls._db_file_patch = patch.object(
            db_utils,
            "DB_FILE",
            str(cls._database_path),
        )
        cls._db_file_patch.start()

        # Import only after redirecting DB_FILE so server startup cannot read the
        # repository's database.json.
        cls.server = importlib.import_module("server")
        cls._original_db = cls.server.db
        cls._original_testing = cls.server.app.config["TESTING"]
        cls.server.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        cls.server.db = cls._original_db
        cls.server.app.config["TESTING"] = cls._original_testing
        cls._db_file_patch.stop()
        cls._temp_dir.cleanup()

    def setUp(self):
        self.server.db = {}
        self._database_path.unlink(missing_ok=True)
        self.client = self.server.app.test_client()
        self.user_id = "student1"
        self.device_id = "laptop1"

    def _register_device(self):
        private_key, public_key = generate_rsa_keypair()
        public_key_b64 = base64.b64encode(public_key).decode()
        integrity_hash = compute_device_hash(
            self.user_id,
            self.device_id,
            public_key,
        )
        response = self.client.post(
            "/register_device",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "public_key_b64": public_key_b64,
                "integrity_hash": integrity_hash,
            },
        )
        self.assertEqual(response.status_code, 200)
        return private_key, public_key_b64, integrity_hash, response

    def _request_challenge(self):
        return self.client.post(
            "/login/request_challenge",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
            },
        )

    def _signed_login_payload(self, private_key, challenge_b64):
        challenge = base64.b64decode(challenge_b64, validate=True)
        signature = sign_challenge(private_key, challenge)
        return {
            "user_id": self.user_id,
            "device_id": self.device_id,
            "challenge": challenge_b64,
            "signature": base64.b64encode(signature).decode(),
        }

    def test_device_registration(self):
        _, public_key_b64, integrity_hash, response = self._register_device()

        self.assertEqual(response.get_json()["status"], "success")
        device = self.server.db[self.user_id]["devices"][self.device_id]
        self.assertEqual(device["public_key_b64"], public_key_b64)
        self.assertEqual(device["integrity_hash"], integrity_hash)
        self.assertIsNone(device["challenge"])
        self.assertFalse(device["revoked"])
        self.assertTrue(self._database_path.exists())

    def test_challenge_issuance(self):
        self._register_device()

        response = self._request_challenge()

        self.assertEqual(response.status_code, 200)
        challenge_b64 = response.get_json()["challenge"]
        self.assertEqual(len(base64.b64decode(challenge_b64, validate=True)), 32)
        device = self.server.db[self.user_id]["devices"][self.device_id]
        self.assertEqual(device["challenge"], challenge_b64)

    def test_valid_authentication(self):
        private_key, _, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")
        device = self.server.db[self.user_id]["devices"][self.device_id]
        self.assertIsNone(device["challenge"])

    def test_invalid_signature_is_rejected_and_challenge_remains(self):
        self._register_device()
        wrong_private_key, _ = generate_rsa_keypair()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(wrong_private_key, challenge_b64)

        response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "Invalid signature")
        device = self.server.db[self.user_id]["devices"][self.device_id]
        self.assertEqual(device["challenge"], challenge_b64)

    def test_successful_challenge_replay_is_rejected(self):
        private_key, _, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        first_response = self.client.post("/login/verify", json=payload)
        replay_response = self.client.post("/login/verify", json=payload)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(replay_response.status_code, 403)
        self.assertEqual(replay_response.get_json()["error"], "No challenge found")

    def test_revoked_device_is_rejected(self):
        private_key, _, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        revoke_response = self.client.post(
            "/device/revoke",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
            },
        )
        challenge_response = self._request_challenge()
        verify_response = self.client.post("/login/verify", json=payload)

        self.assertEqual(revoke_response.status_code, 200)
        device = self.server.db[self.user_id]["devices"][self.device_id]
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])
        self.assertEqual(challenge_response.status_code, 403)
        self.assertEqual(
            challenge_response.get_json()["error"],
            "Unknown or revoked device",
        )
        self.assertEqual(verify_response.status_code, 403)
        self.assertEqual(verify_response.get_json()["error"], "Device revoked")


if __name__ == "__main__":
    unittest.main()
