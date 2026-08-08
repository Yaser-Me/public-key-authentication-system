import base64
import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from crypto_utils import (
    generate_rsa_keypair,
    sign_challenge,
    sign_enrollment_proof,
    validate_rsa_public_key,
)
from db_utils import (
    create_identity,
    get_database_status,
    get_device,
    initialize_database,
    issue_enrollment_authorization,
    register_device,
    revoke_authenticator,
)


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self._database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"
        initialize_database(self._database_path)
        self.server = server
        self.server.app.config.update(
            TESTING=True,
            DATABASE_PATH=str(self._database_path),
        )
        self.client = self.server.app.test_client()
        self.user_id = "student1"
        self.device_id = "laptop1"

    def tearDown(self):
        self._temp_dir.cleanup()

    def _create_identity(self, user_id=None):
        user_id = user_id or self.user_id
        create_identity(self._database_path, user_id)
        return user_id

    def _issue_authorization(self, user_id=None, device_id=None):
        return issue_enrollment_authorization(
            self._database_path,
            user_id or self.user_id,
            device_id or self.device_id,
        )

    def _binding_payload(self, private_key, public_key, authorization, user_id=None, device_id=None):
        user_id = user_id or self.user_id
        device_id = device_id or self.device_id
        canonical_public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        proof = sign_enrollment_proof(
            private_key,
            authorization["authorization_id"],
            user_id,
            device_id,
            fingerprint,
        )
        return {
            "user_id": user_id,
            "device_id": device_id,
            "authorization_id": authorization["authorization_id"],
            "authorization_secret": authorization["authorization_secret"],
            "public_key_b64": canonical_public_key_b64,
            "enrollment_proof": base64.b64encode(proof).decode("ascii"),
        }, fingerprint

    def _bind(self, user_id=None, device_id=None):
        user_id = user_id or self.user_id
        device_id = device_id or self.device_id
        self._create_identity(user_id)
        authorization = self._issue_authorization(user_id, device_id)
        private_key, public_key = generate_rsa_keypair()
        payload, fingerprint = self._binding_payload(
            private_key, public_key, authorization, user_id, device_id
        )
        response = self.client.post("/authenticator/bind", json=payload)
        self.assertEqual(response.status_code, 200)
        return private_key, public_key, authorization, payload, fingerprint, response

    def _request_challenge(self, user_id=None, device_id=None):
        return self.client.post(
            "/login/request_challenge",
            json={
                "user_id": user_id or self.user_id,
                "device_id": device_id or self.device_id,
            },
        )

    def _signed_login_payload(self, private_key, challenge_b64):
        challenge = base64.b64decode(challenge_b64, validate=True)
        return {
            "user_id": self.user_id,
            "device_id": self.device_id,
            "challenge": challenge_b64,
            "signature": base64.b64encode(sign_challenge(private_key, challenge)).decode(
                "ascii"
            ),
        }

    def _authorization_row(self, authorization_id):
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                "SELECT * FROM enrollment_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        finally:
            connection.close()

    def test_authorized_binding_creates_authenticator_and_returns_fingerprint(self):
        _, _, _, _, fingerprint, response = self._bind()

        data = response.get_json()
        self.assertEqual(data["status"], "created")
        self.assertEqual(data["public_key_fingerprint"], fingerprint)
        self.assertEqual(data["binding_state"], "active")
        self.assertEqual(get_device(self._database_path, self.user_id, self.device_id)["public_key_fingerprint"], fingerprint)

    def test_anonymous_legacy_routes_cannot_mutate_identity_or_revocation_state(self):
        _, public_key = generate_rsa_keypair()
        legacy_registration = self.client.post(
            "/register_device",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "public_key_b64": base64.b64encode(public_key).decode("ascii"),
            },
        )
        self.assertEqual(legacy_registration.status_code, 403)
        self.assertEqual(get_database_status(self._database_path)["users"], 0)

        self._bind()
        legacy_revoke = self.client.post(
            "/device/revoke", json={"user_id": self.user_id, "device_id": self.device_id}
        )
        self.assertEqual(legacy_revoke.status_code, 403)
        self.assertFalse(get_device(self._database_path, self.user_id, self.device_id)["revoked"])

    def test_binding_rejects_malformed_requests_without_creating_state(self):
        requests_to_reject = [
            None,
            {},
            {"user_id": "student 1"},
            {
                "user_id": self.user_id,
                "device_id": self.device_id,
                "authorization_id": "grant",
                "authorization_secret": "secret",
                "public_key_b64": "!!!!",
                "enrollment_proof": "!!!!",
            },
        ]
        for body in requests_to_reject:
            with self.subTest(body=body):
                if body is None:
                    response = self.client.post(
                        "/authenticator/bind", data="not-json", content_type="text/plain"
                    )
                else:
                    response = self.client.post("/authenticator/bind", json=body)
                self.assertEqual(response.status_code, 400)
        self.assertEqual(get_database_status(self._database_path)["users"], 0)

    def test_binding_requires_existing_identity_valid_scope_and_proof(self):
        private_key, public_key = generate_rsa_keypair()
        fake_authorization = {
            "authorization_id": "unknown-grant",
            "authorization_secret": "unknown-secret",
        }
        payload, _ = self._binding_payload(private_key, public_key, fake_authorization)
        response = self.client.post("/authenticator/bind", json=payload)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["code"], "enrollment_denied")
        self.assertEqual(get_database_status(self._database_path)["users"], 0)

        self._create_identity()
        authorization = self._issue_authorization()
        wrong_private_key, _ = generate_rsa_keypair()
        wrong_proof_payload, _ = self._binding_payload(
            wrong_private_key, public_key, authorization
        )
        wrong_proof = self.client.post("/authenticator/bind", json=wrong_proof_payload)
        self.assertEqual(wrong_proof.status_code, 403)
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

        wrong_scope_payload, _ = self._binding_payload(
            private_key, public_key, authorization, device_id="tablet1"
        )
        wrong_scope = self.client.post("/authenticator/bind", json=wrong_scope_payload)
        self.assertEqual(wrong_scope.status_code, 403)
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

    def test_modified_context_and_duplicate_key_are_denied_without_consumption(self):
        existing_private_key, public_key, _, _, _, _ = self._bind()
        authorization = self._issue_authorization(device_id="tablet1")
        duplicate_payload, _ = self._binding_payload(
            existing_private_key, public_key, authorization, device_id="tablet1"
        )
        duplicate = self.client.post("/authenticator/bind", json=duplicate_payload)
        self.assertEqual(duplicate.status_code, 403)
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

        authorization = self._issue_authorization(device_id="tablet2")
        private_key, public_key = generate_rsa_keypair()
        modified_payload, _ = self._binding_payload(
            private_key, public_key, authorization, device_id="tablet2"
        )
        modified_payload["device_id"] = "tablet3"
        modified = self.client.post("/authenticator/bind", json=modified_payload)
        self.assertEqual(modified.status_code, 403)
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

    def test_exact_retry_reconciles_without_second_binding_and_reports_revocation(self):
        private_key, _, authorization, payload, fingerprint, created = self._bind()
        original_proof = payload["enrollment_proof"]
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute(
                "UPDATE enrollment_authorizations SET expires_at = ? WHERE authorization_id = ?",
                ("2000-01-01T00:00:00+00:00", authorization["authorization_id"]),
            )
            connection.commit()
        finally:
            connection.close()
        payload["enrollment_proof"] = base64.b64encode(
            sign_enrollment_proof(
                private_key,
                authorization["authorization_id"],
                self.user_id,
                self.device_id,
                fingerprint,
            )
        ).decode("ascii")
        retry = self.client.post("/authenticator/bind", json=payload)
        self.assertEqual(created.get_json()["status"], "created")
        self.assertNotEqual(payload["enrollment_proof"], original_proof)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.get_json()["status"], "reconciled")
        self.assertEqual(get_database_status(self._database_path)["devices"], 1)

        revoke_authenticator(
            self._database_path,
            self.user_id,
            self.device_id,
            "suspected_compromise",
        )
        payload["enrollment_proof"] = base64.b64encode(
            sign_enrollment_proof(
                private_key,
                authorization["authorization_id"],
                self.user_id,
                self.device_id,
                fingerprint,
            )
        ).decode("ascii")
        after_revoke = self.client.post("/authenticator/bind", json=payload)
        self.assertEqual(after_revoke.status_code, 200)
        self.assertEqual(after_revoke.get_json()["status"], "reconciled")
        self.assertEqual(after_revoke.get_json()["binding_state"], "revoked")
        self.assertEqual(after_revoke.get_json()["public_key_fingerprint"], fingerprint)
        self.assertIsNotNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

    def test_grant_consumption_failure_rolls_back_and_returns_state_unavailable(self):
        self._create_identity()
        authorization = self._issue_authorization()
        private_key, public_key = generate_rsa_keypair()
        payload, _ = self._binding_payload(private_key, public_key, authorization)
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER force_grant_consumption_failure
                BEFORE UPDATE OF consumed_at ON enrollment_authorizations
                WHEN NEW.consumed_at IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'forced grant consumption failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        response = self.client.post("/authenticator/bind", json=payload)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")
        self.assertIsNone(get_device(self._database_path, self.user_id, self.device_id))
        self.assertIsNone(
            self._authorization_row(authorization["authorization_id"])["consumed_at"]
        )

    def test_only_one_new_binding_exists_when_identical_requests_race(self):
        self._create_identity()
        authorization = self._issue_authorization()
        private_key, public_key = generate_rsa_keypair()
        payload, _ = self._binding_payload(private_key, public_key, authorization)

        def bind_once():
            with self.server.app.test_client() as test_client:
                return test_client.post("/authenticator/bind", json=payload).get_json()["status"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: bind_once(), range(2)))

        self.assertIn("created", outcomes)
        self.assertTrue(set(outcomes).issubset({"created", "reconciled"}))
        self.assertEqual(get_database_status(self._database_path)["devices"], 1)

    def test_challenge_issuance_and_valid_authentication_are_preserved(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_response = self._request_challenge()
        self.assertEqual(challenge_response.status_code, 200)
        challenge_b64 = challenge_response.get_json()["challenge"]
        self.assertEqual(len(base64.b64decode(challenge_b64, validate=True)), 32)

        response = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, challenge_b64)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")
        self.assertIsNone(get_device(self._database_path, self.user_id, self.device_id)["challenge"])

    def test_invalid_signature_and_replay_are_rejected_and_challenge_is_consumed_once(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        wrong_private_key, _ = generate_rsa_keypair()
        invalid_payload = self._signed_login_payload(wrong_private_key, challenge_b64)
        invalid = self.client.post("/login/verify", json=invalid_payload)
        self.assertEqual(invalid.status_code, 403)
        self.assertEqual(get_device(self._database_path, self.user_id, self.device_id)["challenge"], challenge_b64)

        valid_payload = self._signed_login_payload(private_key, challenge_b64)
        first = self.client.post("/login/verify", json=valid_payload)
        replay = self.client.post("/login/verify", json=valid_payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 403)

    def test_concurrent_verification_still_allows_one_success(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        def verify_once():
            with self.server.app.test_client() as test_client:
                return test_client.post("/login/verify", json=payload).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: verify_once(), range(2)))

        self.assertEqual(sorted(results), [200, 403])
        self.assertIsNone(get_device(self._database_path, self.user_id, self.device_id)["challenge"])

    def test_trusted_revocation_invalidates_challenge_and_blocks_new_authentication(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)

        self.assertEqual(
            revoke_authenticator(
                self._database_path,
                self.user_id,
                self.device_id,
                "lost",
            ),
            "revoked",
        )
        challenge_response = self._request_challenge()
        verify_response = self.client.post("/login/verify", json=payload)

        self.assertTrue(get_device(self._database_path, self.user_id, self.device_id)["revoked"])
        self.assertIsNone(get_device(self._database_path, self.user_id, self.device_id)["challenge"])
        self.assertEqual(challenge_response.status_code, 403)
        self.assertEqual(verify_response.status_code, 403)

    def test_revocation_wins_before_blocked_challenge_issuance_transition(self):
        self._bind()
        issuance_reached = threading.Event()
        allow_issuance = threading.Event()
        result = {}
        real_issue = self.server.issue_device_challenge

        def delayed_issue(*args):
            issuance_reached.set()
            self.assertTrue(allow_issuance.wait(timeout=2))
            return real_issue(*args)

        def request_challenge():
            with self.server.app.test_client() as test_client:
                result["response"] = test_client.post(
                    "/login/request_challenge",
                    json={"user_id": self.user_id, "device_id": self.device_id},
                )

        with patch.object(self.server, "issue_device_challenge", side_effect=delayed_issue):
            thread = threading.Thread(target=request_challenge)
            thread.start()
            self.assertTrue(issuance_reached.wait(timeout=2))
            revoke_authenticator(
                self._database_path,
                self.user_id,
                self.device_id,
                "lost",
            )
            allow_issuance.set()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertEqual(result["response"].status_code, 403)
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])

    def test_revocation_wins_before_blocked_verification_consumption_transition(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_b64 = self._request_challenge().get_json()["challenge"]
        payload = self._signed_login_payload(private_key, challenge_b64)
        consumption_reached = threading.Event()
        allow_consumption = threading.Event()
        result = {}
        real_consume = self.server.consume_device_challenge

        def delayed_consume(*args):
            consumption_reached.set()
            self.assertTrue(allow_consumption.wait(timeout=2))
            return real_consume(*args)

        def verify():
            with self.server.app.test_client() as test_client:
                result["response"] = test_client.post("/login/verify", json=payload)

        with patch.object(self.server, "consume_device_challenge", side_effect=delayed_consume):
            thread = threading.Thread(target=verify)
            thread.start()
            self.assertTrue(consumption_reached.wait(timeout=2))
            revoke_authenticator(
                self._database_path,
                self.user_id,
                self.device_id,
                "suspected_compromise",
            )
            allow_consumption.set()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())

        self.assertEqual(result["response"].status_code, 403)
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])

    def test_verification_committed_before_revocation_remains_an_earlier_success(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_b64 = self._request_challenge().get_json()["challenge"]

        verification = self.client.post(
            "/login/verify",
            json=self._signed_login_payload(private_key, challenge_b64),
        )
        revoked = revoke_authenticator(
            self._database_path,
            self.user_id,
            self.device_id,
            "lost",
        )

        self.assertEqual(verification.status_code, 200)
        self.assertEqual(revoked, "revoked")
        device = get_device(self._database_path, self.user_id, self.device_id)
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])

    def test_oversized_request_and_missing_state_fail_safely(self):
        oversized = self.client.post(
            "/authenticator/bind",
            json={"enrollment_proof": "A" * (17 * 1024)},
        )
        self.assertEqual(oversized.status_code, 413)

        self._create_identity()
        authorization = self._issue_authorization()
        private_key, public_key = generate_rsa_keypair()
        payload, _ = self._binding_payload(private_key, public_key, authorization)
        self._database_path.unlink()
        missing = self.client.post("/authenticator/bind", json=payload)
        self.assertEqual(missing.status_code, 503)
        self.assertEqual(missing.get_json()["code"], "state_unavailable")


if __name__ == "__main__":
    unittest.main()
