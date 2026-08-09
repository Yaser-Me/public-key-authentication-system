import base64
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import db_utils
import server
from crypto_utils import (
    AUTHENTICATION_PROTOCOL,
    generate_rsa_keypair,
    sign_authentication_proof,
    validate_rsa_public_key,
)
from db_utils import (
    DatabaseOperationError,
    analyze_security_events,
    bind_authenticator,
    create_identity,
    get_device,
    get_user,
    initialize_database,
    issue_enrollment_authorization,
    list_security_events,
    prepare_authenticator_replacement,
    revoke_authenticator,
)


class SecurityAnalysisTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"
        initialize_database(self.database_path)
        server.app.config.update(TESTING=True, DATABASE_PATH=str(self.database_path))
        self.client = server.app.test_client()
        self.user_id = "student1"
        self.base_time = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
        self.wrong_private_key, _ = generate_rsa_keypair()

    def tearDown(self):
        self._temp_dir.cleanup()

    def _timestamp(self, seconds):
        return (self.base_time + timedelta(seconds=seconds)).isoformat()

    def _enroll(self, device_id):
        if get_user(self.database_path, self.user_id) is None:
            create_identity(self.database_path, self.user_id)
        authorization = issue_enrollment_authorization(
            self.database_path, self.user_id, device_id
        )
        private_key, public_key = generate_rsa_keypair()
        public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        result = bind_authenticator(
            self.database_path,
            self.user_id,
            device_id,
            public_key_b64,
            fingerprint,
            authorization["authorization_id"],
            authorization["authorization_secret"],
        )
        self.assertEqual(result["outcome"], "created")
        return private_key, fingerprint, authorization

    def _request_challenge(self, device_id, seconds):
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(seconds)):
            response = self.client.post(
                "/login/request_challenge",
                json={
                    "protocol": AUTHENTICATION_PROTOCOL,
                    "user_id": self.user_id,
                    "device_id": device_id,
                },
            )
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def _authentication_payload(self, private_key, challenge):
        signature = sign_authentication_proof(
            private_key,
            challenge["challenge_id"],
            base64.b64decode(challenge["nonce"], validate=True),
            challenge["user_id"],
            challenge["device_id"],
            challenge["public_key_fingerprint"],
        )
        return {
            "protocol": AUTHENTICATION_PROTOCOL,
            "challenge_id": challenge["challenge_id"],
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def _submit_invalid_signature(self, challenge, seconds):
        payload = self._authentication_payload(self.wrong_private_key, challenge)
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(seconds)):
            response = self.client.post("/login/verify", json=payload)
        self.assertEqual(response.status_code, 403)
        return payload["signature"]

    def _submit_valid_signature(self, private_key, challenge, seconds):
        payload = self._authentication_payload(private_key, challenge)
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(seconds)):
            response = self.client.post("/login/verify", json=payload)
        return response, payload

    def test_invalid_signature_finding_uses_distinct_interactions_at_window_boundary(self):
        _, fingerprint, authorization = self._enroll("laptop1")
        signatures = []
        nonces = []
        for seconds in (0, 300, 600):
            challenge = self._request_challenge("laptop1", seconds)
            nonces.append(challenge["nonce"])
            signatures.append(self._submit_invalid_signature(challenge, seconds))

        result = analyze_security_events(
            self.database_path, self.user_id, device_id="laptop1"
        )
        findings = [
            finding
            for finding in result["findings"]
            if finding["finding_type"] == "repeated_invalid_authentication_proofs"
        ]
        invalid_events = [
            event
            for event in result["timeline"]
            if event["reason_code"] == "invalid_signature"
        ]

        self.assertTrue(result["complete"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["evidence_event_ids"],
            [event["event_id"] for event in invalid_events],
        )
        self.assertEqual(findings[0]["public_key_fingerprint"], fingerprint)
        self.assertIn("not cryptographically attributed", findings[0]["limitation"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(authorization["authorization_secret"], serialized)
        for signature in signatures:
            self.assertNotIn(signature, serialized)
        for nonce in nonces:
            self.assertNotIn(nonce, serialized)

    def test_repeated_attempts_for_one_interaction_do_not_satisfy_policy(self):
        self._enroll("laptop1")
        challenge = self._request_challenge("laptop1", 0)
        for seconds in (0, 60, 120):
            self._submit_invalid_signature(challenge, seconds)

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertEqual(result["findings"], [])
        self.assertEqual(
            sum(
                event["reason_code"] == "invalid_signature"
                for event in result["timeline"]
            ),
            3,
        )

    def test_invalid_signature_policy_does_not_cross_bindings(self):
        self._enroll("laptop1")
        self._enroll("phone1")
        for index, device_id in enumerate(("laptop1", "phone1", "laptop1")):
            challenge = self._request_challenge(device_id, index * 60)
            self._submit_invalid_signature(challenge, index * 60)

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertEqual(result["findings"], [])

    def test_invalid_signature_activity_just_outside_window_does_not_trigger(self):
        self._enroll("laptop1")
        for seconds in (0, 300, 601):
            challenge = self._request_challenge("laptop1", seconds)
            self._submit_invalid_signature(challenge, seconds)

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertEqual(result["findings"], [])

    def test_replay_finding_links_prior_success_and_preserves_benign_explanation(self):
        private_key, fingerprint, _ = self._enroll("laptop1")
        challenge = self._request_challenge("laptop1", 0)
        success, payload = self._submit_valid_signature(private_key, challenge, 10)
        self.assertEqual(success.status_code, 200)
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(20)):
            replay = self.client.post("/login/verify", json=payload)
        self.assertEqual(replay.status_code, 403)

        result = analyze_security_events(self.database_path, self.user_id)
        finding = next(
            finding
            for finding in result["findings"]
            if finding["finding_type"] == "challenge_replay_after_success"
        )
        evidence_events = [
            event
            for event in result["timeline"]
            if event["event_id"] in finding["evidence_event_ids"]
        ]

        self.assertEqual(
            [(event["event_type"], event["reason_code"]) for event in evidence_events],
            [
                ("authentication.succeeded", "proof_verified"),
                ("authentication.denied", "challenge_replayed"),
            ],
        )
        self.assertEqual(finding["public_key_fingerprint"], fingerprint)
        self.assertIn("response uncertainty", finding["limitation"])

    def test_expiry_alone_is_timeline_context_not_a_finding(self):
        private_key, _, _ = self._enroll("laptop1")
        challenge = self._request_challenge("laptop1", 0)
        response, _ = self._submit_valid_signature(private_key, challenge, 300)
        self.assertEqual(response.status_code, 403)

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertTrue(
            any(event["reason_code"] == "challenge_expired" for event in result["timeline"])
        )
        self.assertEqual(result["findings"], [])

    def test_post_revocation_finding_does_not_claim_key_use_or_cross_bindings(self):
        _, old_fingerprint, _ = self._enroll("laptop1")
        _, unaffected_fingerprint, _ = self._enroll("phone1")
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(0)):
            self.assertEqual(
                revoke_authenticator(
                    self.database_path, self.user_id, "laptop1", "lost"
                ),
                "revoked",
            )
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(10)):
            denied = self.client.post(
                "/login/request_challenge",
                json={
                    "protocol": AUTHENTICATION_PROTOCOL,
                    "user_id": self.user_id,
                    "device_id": "laptop1",
                },
            )
        self.assertEqual(denied.status_code, 403)

        result = analyze_security_events(self.database_path, self.user_id)
        finding = next(
            finding
            for finding in result["findings"]
            if finding["finding_type"] == "post_revocation_targeting"
        )

        self.assertEqual(finding["device_id"], "laptop1")
        self.assertEqual(finding["public_key_fingerprint"], old_fingerprint)
        self.assertNotEqual(finding["public_key_fingerprint"], unaffected_fingerprint)
        self.assertIn("does not prove", finding["limitation"])
        self.assertFalse(get_device(self.database_path, self.user_id, "phone1")["revoked"])

    def test_replacement_preparation_is_authoritative_revocation_evidence(self):
        self._enroll("old1")
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(0)):
            prepared = prepare_authenticator_replacement(
                self.database_path,
                self.user_id,
                "old1",
                "replacement1",
                "suspected_compromise",
            )
        self.assertEqual(prepared["status"], "prepared")
        with patch.object(db_utils, "utc_now", return_value=self._timestamp(10)):
            denied = self.client.post(
                "/login/request_challenge",
                json={
                    "protocol": AUTHENTICATION_PROTOCOL,
                    "user_id": self.user_id,
                    "device_id": "old1",
                },
            )
        self.assertEqual(denied.status_code, 403)

        result = analyze_security_events(
            self.database_path, self.user_id, device_id="old1"
        )
        finding = next(
            finding
            for finding in result["findings"]
            if finding["finding_type"] == "post_revocation_targeting"
        )
        evidence = [
            event
            for event in result["timeline"]
            if event["event_id"] in finding["evidence_event_ids"]
        ]

        self.assertEqual(
            [event["event_type"] for event in evidence],
            ["authenticator.replacement_prepared", "authentication.denied"],
        )

    def test_revocation_without_later_targeting_does_not_create_finding(self):
        self._enroll("laptop1")
        revoke_authenticator(self.database_path, self.user_id, "laptop1", "lost")

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertEqual(result["findings"], [])

    def test_bounded_analysis_reports_truncation_and_does_not_write_state(self):
        create_identity(self.database_path, self.user_id)
        for device_id in ("one", "two", "three"):
            issue_enrollment_authorization(
                self.database_path, self.user_id, device_id
            )
        before = list_security_events(self.database_path, user_id=self.user_id)

        result = analyze_security_events(self.database_path, self.user_id, limit=2)
        after = list_security_events(self.database_path, user_id=self.user_id)

        self.assertFalse(result["complete"])
        self.assertEqual(result["events_examined"], 2)
        self.assertIn("earlier activity", result["completeness_note"])
        self.assertEqual(result["timeline"], before[-2:])
        self.assertEqual(after, before)

    def test_corrupt_selected_event_timestamp_fails_closed(self):
        create_identity(self.database_path, self.user_id)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "UPDATE security_events SET occurred_at = 'not-a-timestamp' "
                "WHERE user_id = ?",
                (self.user_id,),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(DatabaseOperationError):
            analyze_security_events(self.database_path, self.user_id)

    def test_inconsistent_finding_event_semantics_fail_closed(self):
        self._enroll("laptop1")
        challenge = self._request_challenge("laptop1", 0)
        self._submit_invalid_signature(challenge, 10)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                UPDATE security_events
                SET actor_assurance = 'cryptographically_verified'
                WHERE reason_code = 'invalid_signature'
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(DatabaseOperationError):
            analyze_security_events(self.database_path, self.user_id)

    def test_corrupt_related_binding_cannot_cross_analysis_scope(self):
        self._enroll("laptop1")
        for seconds in (0, 60, 120):
            challenge = self._request_challenge("laptop1", seconds)
            self._submit_invalid_signature(challenge, seconds)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                UPDATE security_events
                SET related_device_id = 'phone1'
                WHERE reason_code = 'invalid_signature'
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(DatabaseOperationError):
            analyze_security_events(
                self.database_path, self.user_id, device_id="phone1"
            )

    def test_minimum_parseable_timestamp_does_not_escape_controlled_analysis(self):
        self._enroll("laptop1")
        for seconds in (0, 60, 120):
            challenge = self._request_challenge("laptop1", seconds)
            self._submit_invalid_signature(challenge, seconds)
        connection = sqlite3.connect(self.database_path)
        try:
            first_invalid_event_id = connection.execute(
                """
                SELECT MIN(event_id)
                FROM security_events
                WHERE reason_code = 'invalid_signature'
                """
            ).fetchone()[0]
            connection.execute(
                "UPDATE security_events SET occurred_at = ? WHERE event_id = ?",
                ("0001-01-01T00:00:00+00:00", first_invalid_event_id),
            )
            connection.commit()
        finally:
            connection.close()

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertEqual(result["findings"], [])

    def test_analysis_scope_excludes_other_identities(self):
        create_identity(self.database_path, self.user_id)
        create_identity(self.database_path, "student2")
        issue_enrollment_authorization(self.database_path, self.user_id, "laptop1")
        issue_enrollment_authorization(self.database_path, "student2", "phone1")

        result = analyze_security_events(self.database_path, self.user_id)

        self.assertTrue(result["timeline"])
        self.assertTrue(
            all(event["user_id"] == self.user_id for event in result["timeline"])
        )


if __name__ == "__main__":
    unittest.main()
