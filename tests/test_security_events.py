import base64
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db_utils
import server
from crypto_utils import (
    AUTHENTICATION_PROTOCOL,
    generate_rsa_keypair,
    sign_authentication_proof,
    sign_enrollment_proof,
    validate_rsa_public_key,
)
from db_utils import (
    DatabaseOperationError,
    bind_authenticator,
    create_identity,
    get_authentication_challenge,
    get_database_status,
    get_device,
    get_user,
    initialize_database,
    issue_authentication_challenge,
    issue_enrollment_authorization,
    list_security_events,
    migrate_database,
    prepare_authenticator_replacement,
    record_security_observation,
    revoke_authenticator,
)


class SecurityEventTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"
        initialize_database(self.database_path)
        server.app.config.update(TESTING=True, DATABASE_PATH=str(self.database_path))
        self.client = server.app.test_client()
        self.user_id = "student1"
        self.device_id = "laptop1"

    def tearDown(self):
        self._temp_dir.cleanup()

    def _enroll(self):
        create_identity(self.database_path, self.user_id)
        authorization = issue_enrollment_authorization(
            self.database_path, self.user_id, self.device_id
        )
        private_key, public_key = generate_rsa_keypair()
        public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        proof = sign_enrollment_proof(
            private_key,
            authorization["authorization_id"],
            self.user_id,
            self.device_id,
            fingerprint,
        )
        response = self.client.post(
            "/authenticator/bind",
            json={
                "user_id": self.user_id,
                "device_id": self.device_id,
                "authorization_id": authorization["authorization_id"],
                "authorization_secret": authorization["authorization_secret"],
                "public_key_b64": public_key_b64,
                "enrollment_proof": base64.b64encode(proof).decode("ascii"),
            },
        )
        self.assertEqual(response.status_code, 200)
        return private_key, public_key_b64, fingerprint, authorization

    def _challenge_and_payload(self, private_key):
        response = self.client.post(
            "/login/request_challenge",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "user_id": self.user_id,
                "device_id": self.device_id,
            },
        )
        self.assertEqual(response.status_code, 200)
        challenge = response.get_json()
        signature = sign_authentication_proof(
            private_key,
            challenge["challenge_id"],
            base64.b64decode(challenge["nonce"], validate=True),
            challenge["user_id"],
            challenge["device_id"],
            challenge["public_key_fingerprint"],
        )
        return challenge, {
            "protocol": AUTHENTICATION_PROTOCOL,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def test_real_lifecycle_events_preserve_security_meaning_without_secrets(self):
        private_key, public_key_b64, fingerprint, authorization = self._enroll()
        challenge, valid_payload = self._challenge_and_payload(private_key)

        invalid_signature = dict(valid_payload)
        invalid_signature["signature"] = base64.b64encode(b"not-a-signature").decode(
            "ascii"
        )
        self.assertEqual(
            self.client.post("/login/verify", json=invalid_signature).status_code, 403
        )
        self.assertEqual(
            self.client.post("/login/verify", json=valid_payload).status_code, 200
        )
        self.assertEqual(
            self.client.post("/login/verify", json=valid_payload).status_code, 403
        )
        self.assertEqual(
            revoke_authenticator(
                self.database_path, self.user_id, self.device_id, "lost"
            ),
            "revoked",
        )
        self.assertEqual(
            self.client.post(
                "/login/request_challenge",
                json={
                    "protocol": AUTHENTICATION_PROTOCOL,
                    "user_id": self.user_id,
                    "device_id": self.device_id,
                },
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                "/login/request_challenge",
                json={
                    "protocol": "PKAS-AUTH-V1",
                    "user_id": self.user_id,
                    "device_id": self.device_id,
                },
            ).status_code,
            400,
        )

        events = list_security_events(
            self.database_path, user_id=self.user_id, device_id=self.device_id
        )
        event_pairs = [
            (event["event_type"], event["reason_code"]) for event in events
        ]
        self.assertEqual(
            event_pairs,
            [
                ("enrollment.authorization_issued", "issued"),
                ("authenticator.bound", "created"),
                ("authentication.challenge_issued", "issued"),
                ("authentication.denied", "invalid_signature"),
                ("authentication.succeeded", "proof_verified"),
                ("authentication.denied", "challenge_replayed"),
                ("authenticator.revoked", "lost"),
                ("authentication.denied", "binding_revoked"),
            ],
        )
        identity_events = list_security_events(
            self.database_path, user_id=self.user_id, event_type="identity.created"
        )
        self.assertEqual(len(identity_events), 1)
        success = next(
            event for event in events if event["event_type"] == "authentication.succeeded"
        )
        self.assertEqual(success["actor_kind"], "authenticator")
        self.assertEqual(success["actor_assurance"], "cryptographically_verified")
        self.assertEqual(success["interaction_id"], challenge["challenge_id"])
        revoked_attempt = events[-1]
        self.assertEqual(revoked_attempt["actor_assurance"], "unverified_claim")
        self.assertEqual(revoked_attempt["public_key_fingerprint"], fingerprint)

        protocol_events = list_security_events(
            self.database_path, event_type="authentication.protocol_rejected"
        )
        self.assertEqual(len(protocol_events), 1)
        self.assertEqual(protocol_events[0]["reason_code"], "unsupported_protocol")

        serialized = json.dumps(list_security_events(self.database_path), sort_keys=True)
        for sensitive_value in (
            authorization["authorization_id"],
            authorization["authorization_secret"],
            hashlib.sha256(
                authorization["authorization_secret"].encode("utf-8")
            ).hexdigest(),
            public_key_b64,
            challenge["nonce"],
            valid_payload["signature"],
        ):
            self.assertNotIn(sensitive_value, serialized)

    def test_event_failure_rolls_back_authoritative_state_transitions(self):
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced identity evidence failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                create_identity(self.database_path, self.user_id)
        self.assertIsNone(get_user(self.database_path, self.user_id))

        create_identity(self.database_path, self.user_id)
        authorization = issue_enrollment_authorization(
            self.database_path, self.user_id, self.device_id
        )
        _, public_key = generate_rsa_keypair()
        public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced binding evidence failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                bind_authenticator(
                    self.database_path,
                    self.user_id,
                    self.device_id,
                    public_key_b64,
                    fingerprint,
                    authorization["authorization_id"],
                    authorization["authorization_secret"],
                )
        self.assertIsNone(get_device(self.database_path, self.user_id, self.device_id))
        connection = sqlite3.connect(self.database_path)
        try:
            authorization_row = connection.execute(
                "SELECT consumed_at FROM enrollment_authorizations WHERE authorization_id = ?",
                (authorization["authorization_id"],),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNone(authorization_row[0])

    def test_authentication_event_failure_rolls_back_challenge_consumption(self):
        private_key, _, _, _ = self._enroll()
        challenge, payload = self._challenge_and_payload(private_key)
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced authentication evidence failure"),
        ):
            response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")
        self.assertIsNone(
            get_authentication_challenge(
                self.database_path, challenge["challenge_id"]
            )["consumed_at"]
        )
        self.assertEqual(
            list_security_events(
                self.database_path, event_type="authentication.succeeded"
            ),
            [],
        )

    def test_denial_evidence_failure_is_state_unavailable_not_false_denial(self):
        private_key, _, _, _ = self._enroll()
        challenge, valid_payload = self._challenge_and_payload(private_key)
        invalid_payload = dict(valid_payload)
        invalid_payload["signature"] = base64.b64encode(b"invalid").decode("ascii")

        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced denial evidence failure"),
        ):
            response = self.client.post("/login/verify", json=invalid_payload)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["code"], "state_unavailable")
        self.assertIsNone(
            get_authentication_challenge(
                self.database_path, challenge["challenge_id"]
            )["consumed_at"]
        )

    def test_replacement_event_failure_preserves_old_binding_and_challenge(self):
        private_key, _, _, _ = self._enroll()
        challenge, _ = self._challenge_and_payload(private_key)
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced replacement evidence failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                prepare_authenticator_replacement(
                    self.database_path,
                    self.user_id,
                    self.device_id,
                    "replacement1",
                    "suspected_compromise",
                )

        self.assertFalse(
            get_device(self.database_path, self.user_id, self.device_id)["revoked"]
        )
        self.assertIsNotNone(
            get_authentication_challenge(self.database_path, challenge["challenge_id"])
        )
        connection = sqlite3.connect(self.database_path)
        try:
            replacement_grants = connection.execute(
                "SELECT COUNT(*) FROM enrollment_authorizations WHERE user_id = ? AND device_id = ?",
                (self.user_id, "replacement1"),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(replacement_grants, 0)

    def test_expiry_is_distinguishable_and_uses_authoritative_consume_time(self):
        private_key, _, _, _ = self._enroll()
        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:00:00+00:00"):
            challenge = issue_authentication_challenge(
                self.database_path,
                self.user_id,
                self.device_id,
                lifetime_seconds=60,
            )
        payload = {
            "protocol": AUTHENTICATION_PROTOCOL,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(
                sign_authentication_proof(
                    private_key,
                    challenge["challenge_id"],
                    base64.b64decode(challenge["nonce_b64"], validate=True),
                    self.user_id,
                    self.device_id,
                    challenge["public_key_fingerprint"],
                )
            ).decode("ascii"),
        }
        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:01:00+00:00"):
            response = self.client.post("/login/verify", json=payload)

        self.assertEqual(response.status_code, 403)
        events = list_security_events(
            self.database_path, event_type="authentication.denied"
        )
        self.assertEqual(events[-1]["reason_code"], "challenge_expired")
        self.assertEqual(events[-1]["interaction_id"], challenge["challenge_id"])
        self.assertIsNone(
            get_authentication_challenge(
                self.database_path, challenge["challenge_id"]
            )["consumed_at"]
        )

    def test_v3_migration_is_atomic_and_preserves_state_without_fake_history(self):
        create_identity(self.database_path, self.user_id)
        _, public_key = generate_rsa_keypair()
        public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        db_utils.register_device(
            self.database_path,
            self.user_id,
            self.device_id,
            public_key_b64,
            fingerprint,
        )
        challenge = issue_authentication_challenge(
            self.database_path, self.user_id, self.device_id
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TABLE security_events")
            connection.execute("PRAGMA user_version = 3")
            connection.commit()
        finally:
            connection.close()

        self.assertEqual(
            get_database_status(self.database_path)["integrity"], "migration_required"
        )
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced migration evidence failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                migrate_database(self.database_path)
        failed_status = get_database_status(self.database_path)
        self.assertEqual(failed_status["schema_version"], 3)
        self.assertEqual(failed_status["integrity"], "migration_required")
        connection = sqlite3.connect(self.database_path)
        try:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'security_events'"
                ).fetchone()
            )
        finally:
            connection.close()

        self.assertTrue(migrate_database(self.database_path))
        self.assertEqual(get_database_status(self.database_path)["schema_version"], 4)
        self.assertEqual(
            get_device(self.database_path, self.user_id, self.device_id)[
                "public_key_fingerprint"
            ],
            fingerprint,
        )
        self.assertEqual(
            get_authentication_challenge(
                self.database_path, challenge["challenge_id"]
            )["nonce_b64"],
            challenge["nonce_b64"],
        )
        events = list_security_events(self.database_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "state.migrated")
        self.assertEqual(events[0]["reason_code"], "schema_v3_to_v4")

    def test_counterfeit_v4_evidence_schema_fails_closed(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TABLE security_events")
            connection.execute(
                """
                CREATE TABLE security_events (
                    event_id INTEGER,
                    occurred_at TEXT,
                    event_type TEXT,
                    outcome TEXT,
                    reason_code TEXT,
                    actor_kind TEXT,
                    actor_assurance TEXT,
                    user_id TEXT,
                    device_id TEXT,
                    related_device_id TEXT,
                    public_key_fingerprint TEXT,
                    interaction_id TEXT
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")

    def test_untrusted_event_fields_are_rejected_before_structured_output(self):
        before = list_security_events(self.database_path)
        with self.assertRaises(ValueError):
            record_security_observation(
                self.database_path,
                "authentication.denied",
                "invalid_signature\nforged",
            )
        with self.assertRaises(ValueError):
            record_security_observation(
                self.database_path,
                "authentication.denied",
                "invalid_signature",
                challenge_id="not-a-valid-challenge",
            )
        with self.assertRaises(ValueError):
            list_security_events(self.database_path, event_type="auth\nforged")
        self.assertEqual(list_security_events(self.database_path), before)

    def test_unverified_request_fields_cannot_persist_bearer_secret_values(self):
        create_identity(self.database_path, self.user_id)
        authorization = issue_enrollment_authorization(
            self.database_path, self.user_id, self.device_id
        )
        secret = authorization["authorization_secret"]
        while not secret[0].isalnum():
            authorization = issue_enrollment_authorization(
                self.database_path, self.user_id, self.device_id
            )
            secret = authorization["authorization_secret"]

        unknown_challenge_response = self.client.post(
            "/login/verify",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "challenge_id": secret,
                "signature": base64.b64encode(b"invalid").decode("ascii"),
            },
        )
        unknown_identity_response = self.client.post(
            "/login/request_challenge",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "user_id": secret,
                "device_id": self.device_id,
            },
        )
        unknown_binding_response = self.client.post(
            "/login/request_challenge",
            json={
                "protocol": AUTHENTICATION_PROTOCOL,
                "user_id": self.user_id,
                "device_id": secret,
            },
        )
        _, public_key = generate_rsa_keypair()
        public_key_b64, _ = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        invalid_enrollment_response = self.client.post(
            "/authenticator/bind",
            json={
                "user_id": secret,
                "device_id": self.device_id,
                "authorization_id": authorization["authorization_id"],
                "authorization_secret": secret,
                "public_key_b64": public_key_b64,
                "enrollment_proof": base64.b64encode(b"invalid").decode("ascii"),
            },
        )

        self.assertEqual(unknown_challenge_response.status_code, 403)
        self.assertEqual(unknown_identity_response.status_code, 403)
        self.assertEqual(unknown_binding_response.status_code, 403)
        self.assertEqual(invalid_enrollment_response.status_code, 403)
        events = list_security_events(self.database_path)
        self.assertNotIn(secret, json.dumps(events, sort_keys=True))
        unknown_challenge_event = next(
            event
            for event in events
            if event["reason_code"] == "challenge_unavailable"
        )
        self.assertIsNone(unknown_challenge_event["interaction_id"])
        binding_not_found_events = [
            event for event in events if event["reason_code"] == "binding_not_found"
        ]
        self.assertEqual(len(binding_not_found_events), 2)
        for event in binding_not_found_events:
            self.assertIsNone(event["user_id"])
            self.assertIsNone(event["device_id"])

    def test_v4_rejects_event_suppression_trigger_and_missing_event_index(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER suppress_identity_event
                BEFORE INSERT ON security_events
                WHEN NEW.event_type = 'identity.created'
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        with self.assertRaises(db_utils.DatabaseSchemaError):
            create_identity(self.database_path, self.user_id)

        connection = sqlite3.connect(self.database_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM users WHERE user_id = ?", (self.user_id,)
                ).fetchone()[0],
                0,
            )
            connection.execute("DROP TRIGGER suppress_identity_event")
            connection.execute("DROP INDEX security_events_scope_index")
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")

    def test_v4_requires_all_application_indexes_and_rejects_views(self):
        changes = (
            "DROP INDEX enrollment_authorizations_scope_index",
            "DROP INDEX authentication_challenges_binding_index",
            "CREATE VIEW exposed_event_view AS SELECT * FROM security_events",
        )
        for position, schema_change in enumerate(changes):
            with self.subTest(schema_change=schema_change):
                database_path = Path(self._temp_dir.name) / f"schema-change-{position}.sqlite3"
                initialize_database(database_path)
                connection = sqlite3.connect(database_path)
                try:
                    connection.execute(schema_change)
                    connection.commit()
                finally:
                    connection.close()

                status = get_database_status(database_path)
                self.assertFalse(status["initialized"])
                self.assertEqual(status["integrity"], "unavailable")

    def test_unsupported_v3_trigger_cannot_be_promoted_to_v4(self):
        database_path = Path(self._temp_dir.name) / "triggered-v3.sqlite3"
        initialize_database(database_path)
        connection = sqlite3.connect(database_path)
        try:
            connection.execute("DROP TABLE security_events")
            connection.execute(
                """
                CREATE TRIGGER suppress_user_insert
                BEFORE INSERT ON users
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
            connection.execute("PRAGMA user_version = 3")
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(db_utils.DatabaseSchemaError):
            migrate_database(database_path)
        connection = sqlite3.connect(database_path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                    "AND name = 'security_events'"
                ).fetchone()
            )
            self.assertIsNotNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_schema WHERE type = 'trigger' "
                    "AND name = 'suppress_user_insert'"
                ).fetchone()
            )
        finally:
            connection.close()

    def test_event_insert_verification_detects_suppression_before_commit(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER suppress_identity_event
                BEFORE INSERT ON security_events
                WHEN NEW.event_type = 'identity.created'
                BEGIN
                    SELECT RAISE(IGNORE);
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        with patch.object(db_utils, "_reject_unsupported_schema_extensions"):
            with self.assertRaises(DatabaseOperationError):
                create_identity(self.database_path, self.user_id)

        connection = sqlite3.connect(self.database_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM users WHERE user_id = ?", (self.user_id,)
                ).fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_initialization_event_failure_leaves_no_partial_trusted_state(self):
        database_path = Path(self._temp_dir.name) / "failed-init.sqlite3"
        with patch.object(
            db_utils,
            "_insert_security_event",
            side_effect=sqlite3.DatabaseError("forced initialization evidence failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                initialize_database(database_path)

        self.assertFalse(database_path.exists())
        self.assertTrue(initialize_database(database_path))
        events = list_security_events(database_path)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "state.initialized")


if __name__ == "__main__":
    unittest.main()
