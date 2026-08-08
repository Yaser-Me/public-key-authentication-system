import base64
import concurrent.futures
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import db_utils
from crypto_utils import generate_rsa_keypair, validate_rsa_public_key
from db_utils import (
    DatabaseOperationError,
    DatabaseSchemaError,
    consume_device_challenge,
    get_database_status,
    get_default_database_path,
    get_device,
    get_user,
    initialize_database,
    issue_device_challenge,
    register_device,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"
        initialize_database(self.database_path)

    def tearDown(self):
        self._temp_dir.cleanup()

    def _public_key_values(self):
        _, public_key = generate_rsa_keypair()
        return validate_rsa_public_key(base64.b64encode(public_key).decode("ascii"))

    def test_initialization_is_idempotent_and_reports_status(self):
        self.assertFalse(initialize_database(self.database_path))

        status = get_database_status(self.database_path)

        self.assertTrue(status["initialized"])
        self.assertEqual(status["schema_version"], 1)
        self.assertEqual(status["integrity"], "ok")
        self.assertEqual(status["users"], 0)
        self.assertEqual(status["devices"], 0)

    def test_default_path_uses_local_app_data_and_allows_override(self):
        local_app_data = self.database_path.parent / "Local App Data"
        override = self.database_path.parent / "explicit.sqlite3"

        with patch.dict(
            os.environ,
            {"LOCALAPPDATA": str(local_app_data), "PKAS_DATABASE_PATH": ""},
            clear=False,
        ):
            default_path = get_default_database_path()

        with patch.dict(
            os.environ,
            {"PKAS_DATABASE_PATH": str(override)},
            clear=False,
        ):
            override_path = get_default_database_path()

        self.assertEqual(
            default_path,
            local_app_data / "PublicKeyAuthenticationSystem" / "identity_lab.sqlite3",
        )
        self.assertEqual(override_path, override)

    def test_database_path_supports_spaces_hash_and_unicode(self):
        special_path = self.database_path.parent / "state # اختبار.sqlite3"

        self.assertTrue(initialize_database(special_path))

        status = get_database_status(special_path)
        self.assertTrue(status["initialized"])
        self.assertEqual(status["path"], str(special_path.resolve()))

    def test_registration_rolls_back_user_when_device_insert_fails(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER force_device_insert_failure
                BEFORE INSERT ON devices
                BEGIN
                    SELECT RAISE(ABORT, 'forced device insert failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        public_key_b64, fingerprint = self._public_key_values()

        with self.assertRaises(DatabaseOperationError):
            register_device(
                self.database_path,
                "rollback-user",
                "rollback-device",
                public_key_b64,
                fingerprint,
            )

        self.assertIsNone(get_user(self.database_path, "rollback-user"))
        status = get_database_status(self.database_path)
        self.assertEqual(status["users"], 0)
        self.assertEqual(status["devices"], 0)

    def test_challenge_is_consumed_once_across_concurrent_connections(self):
        public_key_b64, fingerprint = self._public_key_values()
        register_device(
            self.database_path,
            "student1",
            "laptop1",
            public_key_b64,
            fingerprint,
        )
        challenge_b64 = base64.b64encode(b"x" * 32).decode("ascii")
        self.assertTrue(
            issue_device_challenge(
                self.database_path,
                "student1",
                "laptop1",
                challenge_b64,
            )
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    consume_device_challenge,
                    self.database_path,
                    "student1",
                    "laptop1",
                    challenge_b64,
                )
                for _ in range(2)
            ]
            results = [future.result() for future in futures]

        self.assertEqual(sorted(results), [False, True])
        device = get_device(self.database_path, "student1", "laptop1")
        self.assertIsNone(device["challenge"])

    def test_corrupt_state_is_not_replaced(self):
        self.database_path.unlink()
        corrupt_bytes = b"not a sqlite database"
        self.database_path.write_bytes(corrupt_bytes)

        with self.assertRaises(DatabaseSchemaError):
            initialize_database(self.database_path)

        self.assertEqual(self.database_path.read_bytes(), corrupt_bytes)
        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")

    def test_unsupported_schema_is_reported_and_not_replaced(self):
        self.database_path.unlink()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("PRAGMA user_version = 2")
            connection.commit()
        finally:
            connection.close()
        original_bytes = self.database_path.read_bytes()

        status = get_database_status(self.database_path)
        with self.assertRaises(DatabaseSchemaError):
            initialize_database(self.database_path)

        self.assertFalse(status["initialized"])
        self.assertIn("Unsupported database schema version 2", status["error"])
        self.assertEqual(self.database_path.read_bytes(), original_bytes)

    def test_schema_failure_removes_partial_file_and_allows_retry(self):
        self.database_path.unlink()

        with patch.object(db_utils, "SCHEMA_VERSION", "1; INVALID"):
            with self.assertRaises(DatabaseOperationError):
                initialize_database(self.database_path)

        self.assertFalse(self.database_path.exists())
        self.assertTrue(initialize_database(self.database_path))
        self.assertTrue(get_database_status(self.database_path)["initialized"])

    def test_invalid_parent_path_uses_database_error_and_preserves_file(self):
        blocking_file = self.database_path.parent / "not-a-directory"
        blocking_file.write_text("preserve me", encoding="utf-8")

        with self.assertRaises(DatabaseOperationError):
            initialize_database(blocking_file / "state.sqlite3")

        self.assertEqual(blocking_file.read_text(encoding="utf-8"), "preserve me")

    def test_foreign_key_violation_fails_integrity_check(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                INSERT INTO devices (
                    user_id,
                    device_id,
                    public_key_b64,
                    public_key_fingerprint,
                    challenge_b64,
                    revoked,
                    created_at,
                    revoked_at
                ) VALUES (?, ?, ?, ?, NULL, 0, ?, NULL)
                """,
                ("missing-user", "device1", "public-key", "fingerprint", "now"),
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)

        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        self.assertIn("invalid device ownership", status["error"])


if __name__ == "__main__":
    unittest.main()
