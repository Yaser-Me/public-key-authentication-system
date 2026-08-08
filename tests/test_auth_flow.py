import base64
import concurrent.futures
import importlib
import tempfile
import unittest
from pathlib import Path

from crypto_utils import (
    generate_rsa_keypair,
    sign_challenge,
    validate_rsa_public_key,
)
from db_utils import get_database_status, get_device, get_user, initialize_database


class AuthenticationFlowTests(unittest.TestCase):
    """Exercise the Flask authentication flow against isolated SQLite state."""

    @classmethod
    def setUpClass(cls):
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._database_path = Path(cls._temp_dir.name) / "identity_lab.sqlite3"
        cls.server = importlib.import_module("server")
        cls._original_database_path = cls.server.app.config["DATABASE_PATH"]
        cls._original_testing = cls.server.app.config["TESTING"]
        cls.server.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        cls.server.app.config["DATABASE_PATH"] = cls._original_database_path
        cls.server.app.config["TESTING"] = cls._original_testing
        cls._temp_dir.cleanup()

    def setUp(self):
        self._database_path.unlink(missing_ok=True)
        initialize_database(self._database_path)
        self.server.app.config["DATABASE_PATH"] = str(self._database_path)
        self.client = self.server.app.test_client()
        self.user_id = "student1"
        self.device_id = "laptop1"

    def _registration_payload(self, public_key):
        return {
            "user_id": self.user_id,
            "device_id": self.device_id,
            "public_key_b64": base64.b64encode(public_key).decode("ascii"),
        }

    def _register_device(self):
        private_key, public_key = generate_rsa_keypair()
        payload = self._registration_payload(public_key)
        response = self.client.post("/register_device", json=payload)
        self.assertEqual(response.status_code, 200)
        return private_key, public_key, response

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
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def test_device_registration(self):
        _, public_key, response = self._register_device()
        canonical_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )

        body = response.get_json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["public_key_fingerprint"], fingerprint)

        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertEqual(device["public_key_b64"], canonical_key_b64)
        self.assertEqual(device["public_key_fingerprint"], fingerprint)
        self.assertIsNone(device["challenge"])
        self.assertFalse(device["revoked"])

        status = get_database_status(self._database_path)
        self.assertTrue(status["initialized"])
        self.assertEqual(status["users"], 1)
        self.assertEqual(status["devices"], 1)

    def test_legacy_client_integrity_hash_is_ignored(self):
        _, public_key = generate_rsa_keypair()
        payload = self._registration_payload(public_key)
        payload["integrity_hash"] = "client-controlled-legacy-value"

        registration_response = self.client.post("/register_device", json=payload)
        self.assertEqual(registration_response.status_code, 200)

        response = self._request_challenge()

        self.assertEqual(response.status_code, 200)
        self.assertIn("challenge", response.get_json())

    def test_duplicate_registration_cannot_replace_or_reactivate_device(self):
        _, original_public_key, _ = self._register_device()
        original_key_b64, _ = validate_rsa_public_key(
            base64.b64encode(original_public_key).decode("ascii")
        )
        revoke_response = self.client.post(
            "/device/revoke",
            json={"user_id": self.user_id, "device_id": self.device_id},
        )
        self.assertEqual(revoke_response.status_code, 200)

        _, replacement_public_key = generate_rsa_keypair()
        duplicate_response = self.client.post(
            "/register_device",
            json=self._registration_payload(replacement_public_key),
        )

        self.assertEqual(duplicate_response.status_code, 409)
        self.assertEqual(
            duplicate_response.get_json()["code"],
            "device_already_registered",
        )
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertEqual(device["public_key_b64"], original_key_b64)
        self.assertTrue(device["revoked"])

    def test_public_key_cannot_be_reused_for_another_device(self):
        _, public_key, _ = self._register_device()
        response = self.client.post(
            "/register_device",
            json={
                "user_id": self.user_id,
                "device_id": "tablet1",
                "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            },
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "device_already_registered")
        self.assertIsNone(get_device(self._database_path, self.user_id, "tablet1"))
        self.assertEqual(get_database_status(self._database_path)["devices"], 1)

    def test_challenge_issuance(self):
        self._register_device()

        response = self._request_challenge()

        self.assertEqual(response.status_code, 200)
        challenge_b64 = response.get_json()["challenge"]
        self.assertEqual(len(base64.b64decode(challenge_b64, validate=True)), 32)
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertEqual(device["challenge"], challenge_b64)

    def test_valid_authentication(self):
        private_key, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertIsNone(device["challenge"])

    def test_invalid_signature_is_rejected_and_challenge_remains(self):
        self._register_device()
        wrong_private_key, _ = generate_rsa_keypair()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(wrong_private_key, challenge_b64)

        response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "Invalid signature.")
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertEqual(device["challenge"], challenge_b64)

    def test_malformed_signature_is_rejected_and_challenge_remains(self):
        self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]

        response = self.client.post(
            "/login/verify",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "challenge": challenge_b64,
                "signature": "!!!!",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["code"], "invalid_base64")
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertEqual(device["challenge"], challenge_b64)

    def test_successful_challenge_replay_is_rejected(self):
        private_key, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        first_response = self.client.post("/login/verify", json=payload)
        replay_response = self.client.post("/login/verify", json=payload)

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(replay_response.status_code, 403)
        self.assertEqual(replay_response.get_json()["error"], "No challenge found.")

    def test_only_one_concurrent_verification_succeeds(self):
        private_key, _, _ = self._register_device()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        def verify_once():
            with self.server.app.test_client() as test_client:
                return test_client.post("/login/verify", json=payload).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: verify_once(), range(2)))

        self.assertEqual(sorted(results), [200, 403])
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertIsNone(device["challenge"])

    def test_revoked_device_is_rejected(self):
        private_key, _, _ = self._register_device()
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
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])
        self.assertEqual(challenge_response.status_code, 403)
        self.assertEqual(challenge_response.get_json()["code"], "authentication_denied")
        self.assertEqual(verify_response.status_code, 403)
        self.assertEqual(verify_response.get_json()["error"], "Device revoked.")

    def test_bad_registration_requests_return_400_without_creating_state(self):
        _, public_key = generate_rsa_keypair()
        valid_public_key_b64 = base64.b64encode(public_key).decode("ascii")
        requests_to_reject = [
            None,
            {},
            {"user_id": "student1"},
            {
                "user_id": "",
                "device_id": "laptop1",
                "public_key_b64": valid_public_key_b64,
            },
            {
                "user_id": "student 1",
                "device_id": "laptop1",
                "public_key_b64": valid_public_key_b64,
            },
            {
                "user_id": "student1",
                "device_id": "laptop1",
                "public_key_b64": "!!!!",
            },
        ]

        for body in requests_to_reject:
            with self.subTest(body=body):
                if body is None:
                    response = self.client.post(
                        "/register_device",
                        data="not-json",
                        content_type="text/plain",
                    )
                else:
                    response = self.client.post("/register_device", json=body)
                self.assertEqual(response.status_code, 400)

        self.assertIsNone(get_user(self._database_path, self.user_id))
        self.assertEqual(get_database_status(self._database_path)["devices"], 0)

    def test_oversized_request_is_rejected(self):
        response = self.client.post(
            "/register_device",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "public_key_b64": "A" * (17 * 1024),
            },
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()["code"], "request_too_large")
        self.assertEqual(get_database_status(self._database_path)["devices"], 0)

    def test_missing_or_corrupt_database_fails_closed(self):
        self._database_path.unlink()

        missing_response = self.client.post(
            "/register_device",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "public_key_b64": base64.b64encode(generate_rsa_keypair()[1]).decode("ascii"),
            },
        )

        self.assertEqual(missing_response.status_code, 503)
        self.assertEqual(missing_response.get_json()["code"], "state_unavailable")
        self.assertFalse(self._database_path.exists())

        self._database_path.write_bytes(b"not a sqlite database")
        corrupt_response = self.client.get("/health")
        self.assertEqual(corrupt_response.status_code, 503)
        self.assertEqual(corrupt_response.get_json()["status"], "NOT_READY")
        self.assertEqual(self._database_path.read_bytes(), b"not a sqlite database")


if __name__ == "__main__":
    unittest.main()
