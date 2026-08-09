import base64
import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import db_utils
import server
from crypto_utils import (
    AUTHENTICATION_PROTOCOL,
    generate_rsa_keypair,
    sign_challenge,
    sign_authentication_proof,
    sign_enrollment_proof,
    validate_rsa_public_key,
)
from db_utils import (
    create_identity,
    get_database_status,
    get_authentication_challenge,
    get_device,
    initialize_database,
    issue_enrollment_authorization,
    list_security_events,
    prepare_authenticator_replacement,
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
                "protocol": AUTHENTICATION_PROTOCOL,
                "user_id": user_id or self.user_id,
                "device_id": device_id or self.device_id,
            },
        )

    def _signed_login_payload(self, private_key, challenge):
        nonce = base64.b64decode(challenge["nonce"], validate=True)
        return {
            "protocol": AUTHENTICATION_PROTOCOL,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(
                sign_authentication_proof(
                    private_key,
                    challenge["challenge_id"],
                    nonce,
                    challenge["user_id"],
                    challenge["device_id"],
                    challenge["public_key_fingerprint"],
                )
            ).decode("ascii"),
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

        # The trigger is deliberate failure injection; production schema validation
        # rejects persisted triggers before normal operations.
        with patch.object(db_utils, "_reject_unsupported_schema_extensions"):
            response = self.client.post("/authenticator/bind", json=payload)
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute("DROP TRIGGER force_grant_consumption_failure")
            connection.commit()
        finally:
            connection.close()

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

    def test_v2_challenge_issuance_and_valid_authentication(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge_response = self._request_challenge()
        self.assertEqual(challenge_response.status_code, 200)
        challenge = challenge_response.get_json()
        self.assertEqual(challenge["protocol"], AUTHENTICATION_PROTOCOL)
        self.assertEqual(len(challenge["challenge_id"]), 43)
        self.assertEqual(len(base64.b64decode(challenge["nonce"], validate=True)), 32)

        response = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, challenge)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "success")
        self.assertIsNotNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )
        challenge_events = [
            event
            for event in list_security_events(self._database_path)
            if event["interaction_id"] == challenge["challenge_id"]
        ]
        self.assertEqual(
            [(event["event_type"], event["reason_code"]) for event in challenge_events],
            [
                ("authentication.challenge_issued", "issued"),
                ("authentication.succeeded", "proof_verified"),
            ],
        )

    def test_invalid_signature_and_replay_are_rejected_and_challenge_is_consumed_once(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        wrong_private_key, _ = generate_rsa_keypair()
        invalid_payload = self._signed_login_payload(wrong_private_key, challenge)
        invalid = self.client.post("/login/verify", json=invalid_payload)
        self.assertEqual(invalid.status_code, 403)
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

        valid_payload = self._signed_login_payload(private_key, challenge)
        first = self.client.post("/login/verify", json=valid_payload)
        replay = self.client.post("/login/verify", json=valid_payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 403)

    def test_multiple_independent_challenges_remain_usable_once_each(self):
        private_key, _, _, _, _, _ = self._bind()
        first_challenge = self._request_challenge().get_json()
        second_challenge = self._request_challenge().get_json()

        first = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, first_challenge)
        )
        second = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, second_challenge)
        )

        self.assertNotEqual(first_challenge["challenge_id"], second_challenge["challenge_id"])
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

    def test_replacement_keeps_old_revoked_and_other_authenticator_usable(self):
        old_private, _, _, _, old_fingerprint, _ = self._bind(device_id="old1")
        other_private, _, _, _, other_fingerprint, _ = self._bind(device_id="other1")
        old_challenge = self._request_challenge(device_id="old1").get_json()
        old_payload = self._signed_login_payload(old_private, old_challenge)

        replacement = prepare_authenticator_replacement(
            self._database_path,
            self.user_id,
            "old1",
            "replacement1",
            "suspected_compromise",
        )
        replacement_private, replacement_public = generate_rsa_keypair()
        binding_payload, replacement_fingerprint = self._binding_payload(
            replacement_private,
            replacement_public,
            replacement,
            device_id="replacement1",
        )
        invalid_payload = dict(binding_payload)
        invalid_payload["enrollment_proof"] = base64.b64encode(b"invalid").decode(
            "ascii"
        )
        failed_replacement = self.client.post(
            "/authenticator/bind", json=invalid_payload
        )
        self.assertEqual(failed_replacement.status_code, 403)
        self.assertTrue(get_device(self._database_path, self.user_id, "old1")["revoked"])
        self.assertIsNone(get_device(self._database_path, self.user_id, "replacement1"))
        binding_response = self.client.post("/authenticator/bind", json=binding_payload)

        old_response = self.client.post("/login/verify", json=old_payload)
        replacement_challenge = self._request_challenge(device_id="replacement1").get_json()
        replacement_response = self.client.post(
            "/login/verify",
            json=self._signed_login_payload(replacement_private, replacement_challenge),
        )
        other_challenge = self._request_challenge(device_id="other1").get_json()
        other_response = self.client.post(
            "/login/verify",
            json=self._signed_login_payload(other_private, other_challenge),
        )

        self.assertEqual(replacement["status"], "prepared")
        self.assertEqual(binding_response.status_code, 200)
        self.assertEqual(old_response.status_code, 403)
        self.assertEqual(replacement_response.status_code, 200)
        self.assertEqual(other_response.status_code, 200)
        self.assertTrue(get_device(self._database_path, self.user_id, "old1")["revoked"])
        self.assertIsNotNone(get_device(self._database_path, self.user_id, "replacement1"))
        self.assertEqual(
            get_device(self._database_path, self.user_id, "old1")[
                "public_key_fingerprint"
            ],
            old_fingerprint,
        )
        self.assertFalse(
            get_device(self._database_path, self.user_id, "other1")["revoked"]
        )
        self.assertEqual(
            get_device(self._database_path, self.user_id, "other1")[
                "public_key_fingerprint"
            ],
            other_fingerprint,
        )
        self.assertNotEqual(replacement_fingerprint, old_fingerprint)
        self.assertNotEqual(replacement_fingerprint, other_fingerprint)
        replacement_events = list_security_events(
            self._database_path,
            user_id=self.user_id,
            device_id="old1",
            event_type="authenticator.replacement_prepared",
        )
        self.assertEqual(len(replacement_events), 1)
        self.assertEqual(replacement_events[0]["device_id"], "old1")
        self.assertEqual(replacement_events[0]["related_device_id"], "replacement1")
        self.assertEqual(replacement_events[0]["reason_code"], "suspected_compromise")
        self.assertEqual(
            list_security_events(
                self._database_path,
                device_id="other1",
                event_type="authenticator.replacement_prepared",
            ),
            [],
        )

    def test_concurrent_verification_allows_one_success(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        payload = self._signed_login_payload(private_key, challenge)

        def verify_once():
            with self.server.app.test_client() as test_client:
                return test_client.post("/login/verify", json=payload).status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: verify_once(), range(2)))

        self.assertEqual(sorted(results), [200, 403])
        self.assertIsNotNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )
        challenge_events = [
            event
            for event in list_security_events(self._database_path)
            if event["interaction_id"] == challenge["challenge_id"]
        ]
        self.assertEqual(
            [(event["event_type"], event["reason_code"]) for event in challenge_events],
            [
                ("authentication.challenge_issued", "issued"),
                ("authentication.succeeded", "proof_verified"),
                ("authentication.denied", "challenge_replayed"),
            ],
        )

    def test_trusted_revocation_invalidates_challenge_and_blocks_new_authentication(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        payload = self._signed_login_payload(private_key, challenge)

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
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])
        )
        self.assertEqual(challenge_response.status_code, 403)
        self.assertEqual(verify_response.status_code, 403)

    def test_revocation_wins_before_blocked_challenge_issuance_transition(self):
        self._bind()
        issuance_reached = threading.Event()
        allow_issuance = threading.Event()
        result = {}
        real_issue = self.server.issue_authentication_challenge

        def delayed_issue(*args):
            issuance_reached.set()
            self.assertTrue(allow_issuance.wait(timeout=2))
            return real_issue(*args)

        def request_challenge():
            with self.server.app.test_client() as test_client:
                result["response"] = test_client.post(
                    "/login/request_challenge",
                    json={
                        "protocol": AUTHENTICATION_PROTOCOL,
                        "user_id": self.user_id,
                        "device_id": self.device_id,
                    },
                )

        with patch.object(self.server, "issue_authentication_challenge", side_effect=delayed_issue):
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
        relevant_events = [
            (event["event_type"], event["reason_code"])
            for event in list_security_events(
                self._database_path, user_id=self.user_id, device_id=self.device_id
            )
            if event["event_type"]
            in {"authenticator.revoked", "authentication.denied"}
        ]
        self.assertEqual(
            relevant_events[-2:],
            [
                ("authenticator.revoked", "lost"),
                ("authentication.denied", "binding_revoked"),
            ],
        )

    def test_revocation_wins_before_blocked_verification_consumption_transition(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        payload = self._signed_login_payload(private_key, challenge)
        consumption_reached = threading.Event()
        allow_consumption = threading.Event()
        result = {}
        real_consume = self.server.consume_authentication_challenge

        def delayed_consume(*args):
            consumption_reached.set()
            self.assertTrue(allow_consumption.wait(timeout=2))
            return real_consume(*args)

        def verify():
            with self.server.app.test_client() as test_client:
                result["response"] = test_client.post("/login/verify", json=payload)

        with patch.object(self.server, "consume_authentication_challenge", side_effect=delayed_consume):
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
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])
        )
        relevant_events = [
            (event["event_type"], event["reason_code"])
            for event in list_security_events(self._database_path)
            if event["event_type"]
            in {"authenticator.revoked", "authentication.denied"}
        ]
        self.assertEqual(
            relevant_events[-2:],
            [
                ("authenticator.revoked", "suspected_compromise"),
                ("authentication.denied", "challenge_unavailable"),
            ],
        )

    def test_verification_committed_before_revocation_remains_an_earlier_success(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()

        verification = self.client.post(
            "/login/verify",
            json=self._signed_login_payload(private_key, challenge),
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
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])
        )
        relevant_events = [
            (event["event_type"], event["reason_code"])
            for event in list_security_events(self._database_path)
            if event["event_type"]
            in {"authentication.succeeded", "authenticator.revoked"}
        ]
        self.assertEqual(
            relevant_events[-2:],
            [
                ("authentication.succeeded", "proof_verified"),
                ("authenticator.revoked", "lost"),
            ],
        )

    def test_legacy_login_requests_cannot_downgrade_authentication(self):
        private_key, _, _, _, _, _ = self._bind()
        legacy_request = self.client.post(
            "/login/request_challenge",
            json={"user_id": self.user_id, "device_id": self.device_id},
        )
        legacy_verify = self.client.post(
            "/login/verify",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "challenge": base64.b64encode(b"x" * 32).decode("ascii"),
                "signature": base64.b64encode(b"legacy").decode("ascii"),
            },
        )

        self.assertEqual(legacy_request.status_code, 400)
        self.assertEqual(legacy_verify.status_code, 400)
        self.assertEqual(get_database_status(self._database_path)["devices"], 1)

    def test_context_tampering_and_legacy_signature_preserve_the_challenge(self):
        private_key, _, _, _, fingerprint, _ = self._bind()
        challenge = self._request_challenge().get_json()
        nonce = base64.b64decode(challenge["nonce"], validate=True)
        wrong_context_signature = sign_authentication_proof(
            private_key,
            challenge["challenge_id"],
            nonce,
            "student2",
            self.device_id,
            fingerprint,
        )
        tampered = self.client.post(
            "/login/verify",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "challenge_id": challenge["challenge_id"],
                "signature": base64.b64encode(wrong_context_signature).decode("ascii"),
            },
        )
        legacy_signature = self.client.post(
            "/login/verify",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "challenge_id": challenge["challenge_id"],
                "signature": base64.b64encode(
                    sign_challenge(private_key, b"legacy raw challenge")
                ).decode("ascii"),
            },
        )

        self.assertEqual(tampered.status_code, 403)
        self.assertEqual(legacy_signature.status_code, 403)
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_expired_v2_challenge_is_denied_without_consumption(self):
        private_key, _, _, _, _, _ = self._bind()
        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:00:00+00:00"):
            challenge = self._request_challenge().get_json()
        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:05:00+00:00"):
            response = self.client.post(
                "/login/verify", json=self._signed_login_payload(private_key, challenge)
            )

        self.assertEqual(response.status_code, 403)
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_malformed_v2_login_input_fails_without_state_change(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        valid_payload = self._signed_login_payload(private_key, challenge)
        requests = (
            (
                "/login/request_challenge",
                {"protocol": AUTHENTICATION_PROTOCOL, "user_id": self.user_id, "device_id": self.device_id, "extra": "x"},
            ),
            (
                "/login/verify",
                {"protocol": "PKAS-AUTH-V1", "challenge_id": challenge["challenge_id"], "signature": valid_payload["signature"]},
            ),
            (
                "/login/verify",
                {"protocol": AUTHENTICATION_PROTOCOL, "challenge_id": "!" * 43, "signature": valid_payload["signature"]},
            ),
            (
                "/login/verify",
                {"protocol": AUTHENTICATION_PROTOCOL, "challenge_id": challenge["challenge_id"], "signature": "!!!"},
            ),
        )
        for endpoint, payload in requests:
            with self.subTest(endpoint=endpoint, payload=payload):
                self.assertEqual(self.client.post(endpoint, json=payload).status_code, 400)
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_challenge_consumption_database_failure_is_state_unavailable(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER force_challenge_consumption_failure
                BEFORE UPDATE OF consumed_at ON authentication_challenges
                WHEN NEW.consumed_at IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'forced challenge consumption failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        # The trigger is deliberate failure injection; production schema validation
        # rejects persisted triggers before normal operations.
        with patch.object(db_utils, "_reject_unsupported_schema_extensions"):
            response = self.client.post(
                "/login/verify", json=self._signed_login_payload(private_key, challenge)
            )
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute("DROP TRIGGER force_challenge_consumption_failure")
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_inconsistent_challenge_binding_state_fails_closed(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute(
                "UPDATE authentication_challenges SET public_key_fingerprint = ? "
                "WHERE challenge_id = ?",
                ("SHA256:inconsistent", challenge["challenge_id"]),
            )
            connection.commit()
        finally:
            connection.close()

        response = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, challenge)
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")

    def test_corrupted_stored_key_or_fingerprint_is_state_unavailable(self):
        private_key, _, _, _, _, _ = self._bind()
        challenge = self._request_challenge().get_json()
        connection = sqlite3.connect(self._database_path)
        try:
            connection.execute(
                "UPDATE devices SET public_key_b64 = ? WHERE user_id = ? AND device_id = ?",
                ("not-a-public-key", self.user_id, self.device_id),
            )
            connection.commit()
        finally:
            connection.close()

        response = self.client.post(
            "/login/verify", json=self._signed_login_payload(private_key, challenge)
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")
        self.assertIsNone(
            get_authentication_challenge(self._database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

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
