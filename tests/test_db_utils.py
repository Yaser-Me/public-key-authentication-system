import base64
import concurrent.futures
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import db_utils
from crypto_utils import generate_rsa_keypair, validate_rsa_public_key
from db_utils import (
    DatabaseMigrationRequiredError,
    DatabaseOperationError,
    DatabaseSchemaError,
    DuplicateDeviceError,
    EnrollmentDeniedError,
    EnrollmentStateError,
    bind_authenticator,
    cancel_enrollment_authorization,
    consume_authentication_challenge,
    create_identity,
    get_database_status,
    get_authentication_challenge,
    get_default_database_path,
    get_device,
    get_user,
    initialize_database,
    issue_authentication_challenge,
    issue_enrollment_authorization,
    list_authenticator_inventory,
    migrate_database,
    prepare_authenticator_replacement,
    register_device,
    revoke_authenticator,
    run_if_binding_active,
)


def create_v1_database(database_path):
    """Create the historical v1 shape for migration tests only."""
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "CREATE TABLE users (user_id TEXT PRIMARY KEY, created_at TEXT NOT NULL)"
        )
        connection.execute(
            """
            CREATE TABLE devices (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL UNIQUE,
                challenge_b64 TEXT,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                PRIMARY KEY (user_id, device_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                CHECK (
                    (revoked = 0 AND revoked_at IS NULL)
                    OR (revoked = 1 AND revoked_at IS NOT NULL)
                )
            )
            """
        )
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    finally:
        connection.close()


def create_v2_database(database_path):
    """Create the exact fresh Milestone 2 schema for the v2-to-v3 test."""
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "CREATE TABLE users (user_id TEXT PRIMARY KEY, created_at TEXT NOT NULL)"
        )
        connection.execute(db_utils.V2_DEVICES_TABLE_SQL)
        connection.execute(db_utils.ENROLLMENT_AUTHORIZATIONS_TABLE_SQL)
        connection.execute(
            "CREATE INDEX enrollment_authorizations_scope_index "
            "ON enrollment_authorizations (user_id, device_id)"
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
    finally:
        connection.close()


def create_counterfeit_database(
    database_path, version, omitted_constraint, check_style="supported"
):
    """Create supported-looking state with missing or counterfeit constraints."""
    unique = "" if omitted_constraint == "device_unique" else " UNIQUE"
    if omitted_constraint == "lifecycle_checks" or check_style == "probe_specific":
        revoked_column_check = ""
    elif check_style == "always_true":
        revoked_column_check = " CHECK ((revoked IN (0, 1)) OR 1 = 1)"
    else:
        revoked_column_check = " CHECK (revoked IN (0, 1))"
    device_constraints = []
    if omitted_constraint != "device_primary_key":
        device_constraints.append("PRIMARY KEY (user_id, device_id)")
    if omitted_constraint != "device_foreign_key":
        device_constraints.append(
            "FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE"
        )
    if omitted_constraint == "lifecycle_checks":
        pass
    elif check_style == "probe_specific":
        device_constraints.append(
            "CHECK (device_id NOT IN ('invalid-state', 'invalid-time'))"
        )
    elif check_style == "always_true":
        if version == 2:
            device_constraints.append(
                "CHECK (((revoked = 0 AND revoked_at IS NULL AND "
                "revocation_reason IS NULL) OR (revoked = 1 AND "
                "revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)) "
                "OR 1 = 1)"
            )
        else:
            device_constraints.append(
                "CHECK (((revoked = 0 AND revoked_at IS NULL) OR "
                "(revoked = 1 AND revoked_at IS NOT NULL)) OR 1 = 1)"
            )
    else:
        device_constraints.append(
            "CHECK ((revoked = 0 AND revoked_at IS NULL) "
            "OR (revoked = 1 AND revoked_at IS NOT NULL))"
        )
    extra_device_column = "revocation_reason TEXT," if version == 2 else ""
    device_constraint_sql = ", ".join(device_constraints)

    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "CREATE TABLE users (user_id TEXT PRIMARY KEY, created_at TEXT NOT NULL)"
        )
        connection.execute(
            f"""
            CREATE TABLE devices (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL{unique},
                challenge_b64 TEXT,
                revoked INTEGER NOT NULL DEFAULT 0{revoked_column_check},
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                {extra_device_column}
                {device_constraint_sql}
            )
            """
        )
        if version == 2:
            authorization_primary_key = (
                "" if omitted_constraint == "authorization_primary_key" else " PRIMARY KEY"
            )
            authorization_constraints = []
            if omitted_constraint != "authorization_foreign_key":
                authorization_constraints.append(
                    "FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE"
                )
            if omitted_constraint == "lifecycle_checks":
                pass
            elif check_style == "probe_specific":
                authorization_constraints.append(
                    "CHECK (authorization_id NOT IN "
                    "('invalid-pair', 'invalid-cancelled'))"
                )
            elif check_style == "always_true":
                authorization_constraints.extend(
                    (
                        "CHECK (((consumed_at IS NULL AND "
                        "consumed_public_key_fingerprint IS NULL) OR "
                        "(consumed_at IS NOT NULL AND "
                        "consumed_public_key_fingerprint IS NOT NULL)) OR 1 = 1)",
                        "CHECK ((cancelled_at IS NULL OR consumed_at IS NULL) "
                        "OR 1 = 1)",
                    )
                )
            else:
                authorization_constraints.extend(
                    (
                        "CHECK ((consumed_at IS NULL AND "
                        "consumed_public_key_fingerprint IS NULL) OR "
                        "(consumed_at IS NOT NULL AND "
                        "consumed_public_key_fingerprint IS NOT NULL))",
                        "CHECK (cancelled_at IS NULL OR consumed_at IS NULL)",
                    )
                )
            authorization_constraint_sql = ", ".join(authorization_constraints)
            connection.execute(
                f"""
                CREATE TABLE enrollment_authorizations (
                    authorization_id TEXT{authorization_primary_key},
                    secret_digest TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    cancelled_at TEXT,
                    consumed_at TEXT,
                    consumed_public_key_fingerprint TEXT,
                    {authorization_constraint_sql}
                )
                """
            )
            connection.execute(
                "CREATE INDEX enrollment_authorizations_scope_index "
                "ON enrollment_authorizations (user_id, device_id)"
            )
        connection.execute(f"PRAGMA user_version = {version}")
        connection.commit()
    finally:
        connection.close()


def add_forbidden_lifecycle_state(database_path, version):
    """Prove a counterfeit schema permits state rejected by the real schema."""
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO users (user_id, created_at) VALUES ('user1', 'time')"
        )
        if version == 2:
            connection.execute(
                "INSERT INTO devices (user_id, device_id, public_key_b64, "
                "public_key_fingerprint, revoked, created_at, revoked_at, "
                "revocation_reason) VALUES "
                "('user1', 'other-device', 'key', 'fingerprint', 7, "
                "'time', NULL, NULL)"
            )
            connection.execute(
                "INSERT INTO enrollment_authorizations "
                "(authorization_id, secret_digest, user_id, device_id, "
                "created_at, expires_at, consumed_at, "
                "consumed_public_key_fingerprint) VALUES "
                "('other-grant', 'digest', 'user1', 'new-device', "
                "'time', 'later', 'time', NULL)"
            )
        else:
            connection.execute(
                "INSERT INTO devices (user_id, device_id, public_key_b64, "
                "public_key_fingerprint, revoked, created_at, revoked_at) "
                "VALUES ('user1', 'other-device', 'key', 'fingerprint', 7, "
                "'time', NULL)"
            )
        connection.commit()
    finally:
        connection.close()


def replace_authorization_table_with_counterfeit_checks(database_path, check_style):
    """Keep canonical devices while weakening only authorization lifecycle checks."""
    if check_style == "probe_specific":
        checks = (
            "CHECK (authorization_id NOT IN "
            "('invalid-pair', 'invalid-cancelled'))"
        )
    else:
        checks = (
            "CHECK (((consumed_at IS NULL AND "
            "consumed_public_key_fingerprint IS NULL) OR "
            "(consumed_at IS NOT NULL AND "
            "consumed_public_key_fingerprint IS NOT NULL)) OR 1 = 1), "
            "CHECK ((cancelled_at IS NULL OR consumed_at IS NULL) OR 1 = 1)"
        )

    connection = sqlite3.connect(database_path)
    try:
        connection.execute("DROP TABLE enrollment_authorizations")
        connection.execute(
            f"""
            CREATE TABLE enrollment_authorizations (
                authorization_id TEXT PRIMARY KEY,
                secret_digest TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                cancelled_at TEXT,
                consumed_at TEXT,
                consumed_public_key_fingerprint TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                {checks}
            )
            """
        )
        connection.execute(
            "CREATE INDEX enrollment_authorizations_scope_index "
            "ON enrollment_authorizations (user_id, device_id)"
        )
        connection.execute(
            "INSERT INTO users (user_id, created_at) VALUES ('user1', 'time')"
        )
        connection.execute(
            "INSERT INTO enrollment_authorizations "
            "(authorization_id, secret_digest, user_id, device_id, created_at, "
            "expires_at, consumed_at, consumed_public_key_fingerprint) VALUES "
            "('other-grant', 'digest', 'user1', 'new-device', 'time', "
            "'later', 'time', NULL)"
        )
        connection.commit()
    finally:
        connection.close()


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

    def _create_identity(self, user_id="student1"):
        self.assertTrue(create_identity(self.database_path, user_id))
        return user_id

    def _issue(self, user_id="student1", device_id="laptop1"):
        return issue_enrollment_authorization(self.database_path, user_id, device_id)

    def _authorization_row(self, authorization_id):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                "SELECT * FROM enrollment_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        finally:
            connection.close()

    def test_initialization_is_idempotent_and_reports_v3_status(self):
        self.assertFalse(initialize_database(self.database_path))

        status = get_database_status(self.database_path)

        self.assertTrue(status["initialized"])
        self.assertEqual(status["schema_version"], 3)
        self.assertEqual(status["integrity"], "ok")
        self.assertEqual(status["users"], 0)
        self.assertEqual(status["devices"], 0)

    def test_initialization_schema_validation_failure_cleans_up_and_can_retry(self):
        database_path = self.database_path.parent / "initialization-retry.sqlite3"
        with patch.object(
            db_utils,
            "_validate_v3_schema",
            side_effect=DatabaseSchemaError("forced validation failure"),
        ):
            with self.assertRaises(DatabaseOperationError):
                initialize_database(database_path)

        self.assertFalse(database_path.exists())
        self.assertTrue(initialize_database(database_path))
        self.assertTrue(get_database_status(database_path)["initialized"])

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

    def test_v1_migration_preserves_state_and_marks_history_honestly(self):
        self.database_path.unlink()
        create_v1_database(self.database_path)
        active_key, active_fingerprint = self._public_key_values()
        revoked_key, revoked_fingerprint = self._public_key_values()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "INSERT INTO users (user_id, created_at) VALUES ('student1', '2026-01-01T00:00:00+00:00')"
            )
            connection.execute(
                """
                INSERT INTO devices VALUES (?, ?, ?, ?, ?, 0, ?, NULL)
                """,
                (
                    "student1",
                    "laptop1",
                    active_key,
                    active_fingerprint,
                    "Y2hhbGxlbmdl",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            connection.execute(
                """
                INSERT INTO devices VALUES (?, ?, ?, ?, NULL, 1, ?, ?)
                """,
                (
                    "student1",
                    "old1",
                    revoked_key,
                    revoked_fingerprint,
                    "2026-01-01T00:00:00+00:00",
                    "2026-01-02T00:00:00+00:00",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "migration_required")
        self.assertEqual(status["schema_version"], 1)
        with self.assertRaises(DatabaseMigrationRequiredError):
            get_device(self.database_path, "student1", "laptop1")

        self.assertTrue(migrate_database(self.database_path))
        self.assertTrue(get_database_status(self.database_path)["initialized"])
        self.assertEqual(
            get_user(self.database_path, "student1")["created_at"],
            "2026-01-01T00:00:00+00:00",
        )
        active = get_device(self.database_path, "student1", "laptop1")
        self.assertEqual(active["public_key_b64"], active_key)
        self.assertEqual(active["public_key_fingerprint"], active_fingerprint)
        # A v1 challenge was signed by the retired login protocol and is not
        # carried into the v3 authentication challenge table.
        self.assertIsNone(active["challenge"])
        self.assertEqual(active["created_at"], "2026-01-01T00:00:00+00:00")
        self.assertIsNone(active["revoked_at"])
        historical = get_device(self.database_path, "student1", "old1")
        self.assertTrue(historical["revoked"])
        self.assertEqual(historical["public_key_b64"], revoked_key)
        self.assertEqual(historical["public_key_fingerprint"], revoked_fingerprint)
        self.assertEqual(historical["created_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(historical["revoked_at"], "2026-01-02T00:00:00+00:00")
        self.assertIsNone(historical["revocation_reason"])

    def test_v2_migration_preserves_lifecycle_state_and_retires_legacy_challenge(self):
        self.database_path.unlink()
        create_v2_database(self.database_path)
        public_key_b64, fingerprint = self._public_key_values()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "INSERT INTO users VALUES (?, ?)",
                ("student1", "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                """
                INSERT INTO devices VALUES (?, ?, ?, ?, ?, 0, ?, NULL, NULL)
                """,
                (
                    "student1",
                    "laptop1",
                    public_key_b64,
                    fingerprint,
                    "Y2hhbGxlbmdl",
                    "2026-01-01T00:00:00+00:00",
                ),
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["schema_version"], 2)
        self.assertEqual(status["integrity"], "migration_required")
        self.assertTrue(migrate_database(self.database_path))

        current = get_database_status(self.database_path)
        self.assertTrue(current["initialized"])
        self.assertEqual(current["schema_version"], 3)
        migrated = get_device(self.database_path, "student1", "laptop1")
        self.assertEqual(migrated["public_key_b64"], public_key_b64)
        self.assertEqual(migrated["public_key_fingerprint"], fingerprint)
        self.assertIsNone(migrated["challenge"])
        self.assertFalse(migrate_database(self.database_path))

    def test_failed_v2_to_v3_migration_preserves_retryable_v2_state(self):
        self.database_path.unlink()
        create_v2_database(self.database_path)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "INSERT INTO users VALUES (?, ?)",
                ("student1", "2026-01-01T00:00:00+00:00"),
            )
            connection.commit()
        finally:
            connection.close()

        def fail_after_legacy_challenge_clear(connection):
            connection.execute("UPDATE devices SET challenge_b64 = NULL")
            raise sqlite3.DatabaseError("forced v3 migration failure")

        with patch.object(
            db_utils,
            "_apply_v3_schema_changes",
            side_effect=fail_after_legacy_challenge_clear,
        ):
            with self.assertRaises(DatabaseOperationError):
                migrate_database(self.database_path)

        connection = sqlite3.connect(self.database_path)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            table = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'authentication_challenges'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, 2)
        self.assertIsNone(table)
        self.assertEqual(get_database_status(self.database_path)["integrity"], "migration_required")
        self.assertTrue(migrate_database(self.database_path))

    def test_counterfeit_v3_challenge_schema_fails_closed(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TABLE authentication_challenges")
            connection.execute(
                """
                CREATE TABLE authentication_challenges (
                    challenge_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    FOREIGN KEY (user_id, device_id)
                        REFERENCES devices(user_id, device_id) ON DELETE CASCADE,
                    CHECK (consumed_at IS NULL OR 1 = 1)
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        with self.assertRaises(DatabaseSchemaError):
            migrate_database(self.database_path)

    def test_failed_migration_rolls_back_to_v1_and_can_retry(self):
        self.database_path.unlink()
        create_v1_database(self.database_path)

        def fail_after_partial_schema_change(connection):
            connection.execute("ALTER TABLE devices ADD COLUMN revocation_reason TEXT")
            raise sqlite3.DatabaseError("forced migration failure")

        with patch.object(
            db_utils, "_apply_v2_schema_changes", side_effect=fail_after_partial_schema_change
        ):
            with self.assertRaises(DatabaseOperationError):
                migrate_database(self.database_path)

        connection = sqlite3.connect(self.database_path)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)")}
        finally:
            connection.close()
        self.assertEqual(version, 1)
        self.assertNotIn("revocation_reason", columns)
        self.assertEqual(get_database_status(self.database_path)["integrity"], "migration_required")
        self.assertTrue(migrate_database(self.database_path))

    def test_migration_validates_v2_constraints_before_commit(self):
        self.database_path.unlink()
        create_v1_database(self.database_path)

        def apply_incomplete_v2_schema(connection):
            connection.execute("ALTER TABLE devices ADD COLUMN revocation_reason TEXT")
            connection.execute(
                """
                CREATE TABLE enrollment_authorizations (
                    authorization_id TEXT,
                    secret_digest TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    cancelled_at TEXT,
                    consumed_at TEXT,
                    consumed_public_key_fingerprint TEXT
                )
                """
            )
            connection.execute("PRAGMA user_version = 2")

        with patch.object(
            db_utils,
            "_apply_v2_schema_changes",
            side_effect=apply_incomplete_v2_schema,
        ):
            with self.assertRaises(DatabaseSchemaError):
                migrate_database(self.database_path)

        connection = sqlite3.connect(self.database_path)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            device_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(devices)")
            }
            authorization_table = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'enrollment_authorizations'"
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(version, 1)
        self.assertNotIn("revocation_reason", device_columns)
        self.assertIsNone(authorization_table)
        self.assertEqual(get_database_status(self.database_path)["integrity"], "migration_required")

    def test_corrupt_and_unsupported_state_are_not_replaced(self):
        self.database_path.unlink()
        corrupt_bytes = b"not a sqlite database"
        self.database_path.write_bytes(corrupt_bytes)

        with self.assertRaises(DatabaseSchemaError):
            initialize_database(self.database_path)
        self.assertEqual(self.database_path.read_bytes(), corrupt_bytes)

        self.database_path.unlink()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("PRAGMA user_version = 99")
            connection.commit()
        finally:
            connection.close()
        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertIn("Unsupported database schema version 99", status["error"])

    def test_claimed_v2_state_without_required_tables_fails_closed(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TABLE enrollment_authorizations")
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        self.assertIn("expected lifecycle schema", status["error"])
        with self.assertRaises(DatabaseSchemaError):
            migrate_database(self.database_path)

    def test_claimed_v1_state_without_expected_schema_is_not_migration_ready(self):
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TABLE enrollment_authorizations")
            connection.execute("DROP TABLE devices")
            connection.execute("DROP TABLE users")
            connection.execute("PRAGMA user_version = 1")
            connection.commit()
        finally:
            connection.close()

        status = get_database_status(self.database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        self.assertIn("expected lifecycle schema", status["error"])
        with self.assertRaises(DatabaseSchemaError):
            migrate_database(self.database_path)

    def test_same_column_v1_state_missing_security_constraints_is_rejected(self):
        for omitted_constraint in (
            "device_primary_key",
            "device_unique",
            "device_foreign_key",
            "lifecycle_checks",
        ):
            with self.subTest(omitted_constraint=omitted_constraint):
                database_path = self.database_path.parent / f"bad-v1-{omitted_constraint}.sqlite3"
                create_counterfeit_database(database_path, 1, omitted_constraint)

                status = get_database_status(database_path)
                self.assertFalse(status["initialized"])
                self.assertEqual(status["integrity"], "unavailable")
                with self.assertRaises(DatabaseSchemaError):
                    migrate_database(database_path)

    def test_same_column_v2_state_missing_security_constraints_is_rejected(self):
        for omitted_constraint in (
            "device_primary_key",
            "device_unique",
            "device_foreign_key",
            "authorization_primary_key",
            "authorization_foreign_key",
            "lifecycle_checks",
        ):
            with self.subTest(omitted_constraint=omitted_constraint):
                database_path = self.database_path.parent / f"bad-v2-{omitted_constraint}.sqlite3"
                create_counterfeit_database(database_path, 2, omitted_constraint)

                status = get_database_status(database_path)
                self.assertFalse(status["initialized"])
                self.assertEqual(status["integrity"], "unavailable")

    def test_probe_specific_v1_checks_are_rejected_without_migration(self):
        database_path = self.database_path.parent / "probe-specific-v1.sqlite3"
        create_counterfeit_database(
            database_path, 1, None, check_style="probe_specific"
        )
        add_forbidden_lifecycle_state(database_path, 1)

        connection = sqlite3.connect(database_path)
        try:
            original_definition = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'devices'"
            ).fetchone()[0]
        finally:
            connection.close()

        status = get_database_status(database_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")
        with self.assertRaises(DatabaseSchemaError):
            migrate_database(database_path)

        connection = sqlite3.connect(database_path)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            current_definition = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'devices'"
            ).fetchone()[0]
            device_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(devices)")
            }
            authorization_table = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'enrollment_authorizations'"
            ).fetchone()
            forbidden_state = connection.execute(
                "SELECT revoked FROM devices WHERE device_id = 'other-device'"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(version, 1)
        self.assertEqual(current_definition, original_definition)
        self.assertNotIn("revocation_reason", device_columns)
        self.assertIsNone(authorization_table)
        self.assertEqual(forbidden_state, 7)

    def test_probe_specific_v2_device_and_authorization_checks_are_rejected(self):
        device_path = self.database_path.parent / "probe-specific-v2-device.sqlite3"
        create_counterfeit_database(
            device_path, 2, None, check_style="probe_specific"
        )
        add_forbidden_lifecycle_state(device_path, 2)

        device_status = get_database_status(device_path)
        self.assertFalse(device_status["initialized"])
        self.assertEqual(device_status["integrity"], "unavailable")

        authorization_path = (
            self.database_path.parent / "probe-specific-v2-authorization.sqlite3"
        )
        initialize_database(authorization_path)
        replace_authorization_table_with_counterfeit_checks(
            authorization_path, "probe_specific"
        )

        authorization_status = get_database_status(authorization_path)
        self.assertFalse(authorization_status["initialized"])
        self.assertEqual(authorization_status["integrity"], "unavailable")

    def test_expected_check_text_weakened_by_always_true_is_rejected(self):
        for version in (1, 2):
            with self.subTest(table="devices", version=version):
                database_path = (
                    self.database_path.parent / f"always-true-v{version}-devices.sqlite3"
                )
                create_counterfeit_database(
                    database_path, version, None, check_style="always_true"
                )
                add_forbidden_lifecycle_state(database_path, version)

                connection = sqlite3.connect(database_path)
                try:
                    definition = connection.execute(
                        "SELECT sql FROM sqlite_schema WHERE type = 'table' "
                        "AND name = 'devices'"
                    ).fetchone()[0]
                finally:
                    connection.close()
                self.assertIn("revoked IN (0, 1)", definition)
                self.assertIn("OR 1 = 1", definition)

                status = get_database_status(database_path)
                self.assertFalse(status["initialized"])
                self.assertEqual(status["integrity"], "unavailable")
                if version == 1:
                    with self.assertRaises(DatabaseSchemaError):
                        migrate_database(database_path)

        authorization_path = (
            self.database_path.parent / "always-true-v2-authorization.sqlite3"
        )
        initialize_database(authorization_path)
        replace_authorization_table_with_counterfeit_checks(
            authorization_path, "always_true"
        )

        connection = sqlite3.connect(authorization_path)
        try:
            definition = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'enrollment_authorizations'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertIn("consumed_at IS NULL", definition)
        self.assertIn("OR 1 = 1", definition)

        status = get_database_status(authorization_path)
        self.assertFalse(status["initialized"])
        self.assertEqual(status["integrity"], "unavailable")

    def test_explicit_identity_creation_replaces_implicit_registration(self):
        public_key_b64, fingerprint = self._public_key_values()
        with self.assertRaises(DatabaseOperationError):
            register_device(
                self.database_path, "student1", "laptop1", public_key_b64, fingerprint
            )
        self.assertIsNone(get_user(self.database_path, "student1"))

        self._create_identity()
        register_device(
            self.database_path, "student1", "laptop1", public_key_b64, fingerprint
        )
        self.assertIsNotNone(get_device(self.database_path, "student1", "laptop1"))

    def test_authorization_is_scoped_digest_stored_and_replacement_cancels_open(self):
        self._create_identity()
        first = self._issue()
        second = self._issue()
        first_row = self._authorization_row(first["authorization_id"])
        second_row = self._authorization_row(second["authorization_id"])

        self.assertNotEqual(first_row["secret_digest"], first["authorization_secret"])
        self.assertIsNotNone(first_row["cancelled_at"])
        self.assertIsNone(second_row["cancelled_at"])
        self.assertIsNone(second_row["consumed_at"])
        with self.assertRaises(DatabaseOperationError):
            issue_enrollment_authorization(self.database_path, "missing", "new1")

        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "already1", public_key_b64, fingerprint)
        with self.assertRaises(DuplicateDeviceError):
            self._issue(device_id="already1")

    def test_concurrent_authorization_issuance_leaves_one_open_authorization(self):
        self._create_identity()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            authorizations = list(
                executor.map(lambda _: self._issue(), range(2))
            )

        rows = [self._authorization_row(item["authorization_id"]) for item in authorizations]
        open_rows = [
            row
            for row in rows
            if row["cancelled_at"] is None and row["consumed_at"] is None
        ]
        self.assertEqual(len(open_rows), 1)
        self.assertEqual(
            cancel_enrollment_authorization(
                self.database_path, open_rows[0]["authorization_id"]
            ),
            "cancelled",
        )

    def test_cancel_and_expiry_prevent_new_binding_without_consuming_grant(self):
        self._create_identity()
        authorization = self._issue()
        self.assertEqual(
            cancel_enrollment_authorization(
                self.database_path, authorization["authorization_id"]
            ),
            "cancelled",
        )
        public_key_b64, fingerprint = self._public_key_values()
        with self.assertRaises(EnrollmentDeniedError):
            bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

        fixed_time = "2026-01-01T00:00:00+00:00"
        with patch.object(db_utils, "utc_now", return_value=fixed_time):
            expired = self._issue(device_id="expired1")
        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:20:00+00:00"):
            with self.assertRaises(EnrollmentDeniedError):
                bind_authenticator(
                    self.database_path,
                    "student1",
                    "expired1",
                    public_key_b64,
                    fingerprint,
                    expired["authorization_id"],
                    expired["authorization_secret"],
                )

    def test_binding_is_atomic_and_exact_retry_reconciles_after_expiry(self):
        self._create_identity()
        fixed_time = "2026-01-01T00:00:00+00:00"
        with patch.object(db_utils, "utc_now", return_value=fixed_time):
            authorization = self._issue()
            public_key_b64, fingerprint = self._public_key_values()
            created = bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )
        self.assertEqual(created["outcome"], "created")

        with patch.object(db_utils, "utc_now", return_value="2026-01-01T00:20:00+00:00"):
            reconciled = bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )
        self.assertEqual(reconciled["outcome"], "reconciled")
        self.assertEqual(reconciled["binding_state"], "active")
        row = self._authorization_row(authorization["authorization_id"])
        self.assertEqual(row["consumed_public_key_fingerprint"], fingerprint)

    def test_binding_checks_expiry_after_waiting_for_sqlite_writer(self):
        self._create_identity()
        issued_at = "2026-01-01T00:00:00+00:00"
        with patch.object(db_utils, "utc_now", return_value=issued_at):
            authorization = issue_enrollment_authorization(
                self.database_path,
                "student1",
                "laptop1",
                lifetime_seconds=600,
            )
        public_key_b64, fingerprint = self._public_key_values()

        writer = sqlite3.connect(self.database_path)
        writer.execute("BEGIN IMMEDIATE")
        database_opened = threading.Event()
        writer_released = threading.Event()
        result = {}
        original_open = db_utils._open_existing_database

        def observed_open(database_path):
            connection = original_open(database_path)
            database_opened.set()
            return connection

        def transaction_time():
            if writer_released.is_set():
                return "2026-01-01T00:10:00+00:00"
            return "2026-01-01T00:09:59+00:00"

        def attempt_binding():
            try:
                bind_authenticator(
                    self.database_path,
                    "student1",
                    "laptop1",
                    public_key_b64,
                    fingerprint,
                    authorization["authorization_id"],
                    authorization["authorization_secret"],
                )
            except Exception as exc:
                result["error"] = exc

        try:
            with patch.object(db_utils, "_open_existing_database", side_effect=observed_open):
                with patch.object(db_utils, "utc_now", side_effect=transaction_time):
                    thread = threading.Thread(target=attempt_binding)
                    thread.start()
                    self.assertTrue(database_opened.wait(timeout=2))
                    writer_released.set()
                    writer.commit()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
        finally:
            writer.close()

        self.assertIsInstance(result.get("error"), EnrollmentDeniedError)
        self.assertIsNone(get_device(self.database_path, "student1", "laptop1"))
        self.assertIsNone(
            self._authorization_row(authorization["authorization_id"])["consumed_at"]
        )

    def test_failed_binding_rolls_back_without_consuming_authorization(self):
        self._create_identity()
        authorization = self._issue()
        public_key_b64, fingerprint = self._public_key_values()
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

        with self.assertRaises(DatabaseOperationError):
            bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )
        self.assertIsNone(get_device(self.database_path, "student1", "laptop1"))
        self.assertIsNone(self._authorization_row(authorization["authorization_id"])["consumed_at"])

    def test_concurrent_binding_creates_one_record_and_allows_exact_reconciliation(self):
        self._create_identity()
        authorization = self._issue()
        public_key_b64, fingerprint = self._public_key_values()

        def bind_once():
            return bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )["outcome"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: bind_once(), range(2)))

        self.assertIn("created", outcomes)
        self.assertTrue(set(outcomes).issubset({"created", "reconciled"}))
        self.assertEqual(get_database_status(self.database_path)["devices"], 1)

    def test_concurrent_different_keys_cannot_consume_one_authorization_twice(self):
        self._create_identity()
        authorization = self._issue()
        first_key_b64, first_fingerprint = self._public_key_values()
        second_key_b64, second_fingerprint = self._public_key_values()

        def bind_once(public_key_b64, fingerprint):
            try:
                return bind_authenticator(
                    self.database_path,
                    "student1",
                    "laptop1",
                    public_key_b64,
                    fingerprint,
                    authorization["authorization_id"],
                    authorization["authorization_secret"],
                )["outcome"]
            except EnrollmentDeniedError:
                return "denied"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda values: bind_once(*values),
                    ((first_key_b64, first_fingerprint), (second_key_b64, second_fingerprint)),
                )
            )

        self.assertEqual(outcomes.count("created"), 1)
        self.assertEqual(outcomes.count("denied"), 1)
        row = self._authorization_row(authorization["authorization_id"])
        bound = get_device(self.database_path, "student1", "laptop1")
        self.assertEqual(row["consumed_public_key_fingerprint"], bound["public_key_fingerprint"])

    def test_consumed_authorization_binding_inconsistency_fails_closed(self):
        self._create_identity()
        authorization = self._issue()
        public_key_b64, fingerprint = self._public_key_values()
        bind_authenticator(
            self.database_path,
            "student1",
            "laptop1",
            public_key_b64,
            fingerprint,
            authorization["authorization_id"],
            authorization["authorization_secret"],
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DELETE FROM devices WHERE user_id = ? AND device_id = ?", ("student1", "laptop1"))
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(EnrollmentStateError):
            bind_authenticator(
                self.database_path,
                "student1",
                "laptop1",
                public_key_b64,
                fingerprint,
                authorization["authorization_id"],
                authorization["authorization_secret"],
            )
        with self.assertRaises(EnrollmentStateError):
            issue_enrollment_authorization(self.database_path, "student1", "laptop1")

    def test_inventory_is_sanitized_and_revocation_is_terminal(self):
        self._create_identity()
        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "laptop1", public_key_b64, fingerprint)
        challenge = issue_authentication_challenge(
            self.database_path, "student1", "laptop1"
        )
        self.assertIsNotNone(challenge)

        self.assertEqual(
            revoke_authenticator(
                self.database_path, "student1", "laptop1", "suspected_compromise"
            ),
            "revoked",
        )
        self.assertEqual(
            revoke_authenticator(self.database_path, "student1", "laptop1", "other"),
            "already_revoked",
        )
        device = get_device(self.database_path, "student1", "laptop1")
        self.assertTrue(device["revoked"])
        self.assertIsNone(device["challenge"])
        self.assertEqual(device["revocation_reason"], "suspected_compromise")
        self.assertIsNone(
            issue_authentication_challenge(self.database_path, "student1", "laptop1")
        )
        self.assertIsNone(
            get_authentication_challenge(self.database_path, challenge["challenge_id"])
        )

        inventory = list_authenticator_inventory(self.database_path, user_id="student1")
        self.assertEqual(inventory[0]["authenticators"][0]["public_key_fingerprint"], fingerprint)
        inventory_text = repr(inventory)
        self.assertNotIn(public_key_b64, inventory_text)
        self.assertNotIn(challenge["nonce_b64"], inventory_text)
        self.assertNotIn(challenge["challenge_id"], inventory_text)
        self.assertNotIn("secret_digest", inventory_text)

        with self.assertRaises(DuplicateDeviceError):
            register_device(self.database_path, "student1", "new1", public_key_b64, fingerprint)

    def test_replacement_preparation_is_atomic_and_keeps_other_bindings_active(self):
        self._create_identity()
        old_public_key, old_fingerprint = self._public_key_values()
        other_public_key, other_fingerprint = self._public_key_values()
        register_device(
            self.database_path, "student1", "old1", old_public_key, old_fingerprint
        )
        register_device(
            self.database_path, "student1", "other1", other_public_key, other_fingerprint
        )
        old_challenge = issue_authentication_challenge(
            self.database_path, "student1", "old1"
        )

        replacement = prepare_authenticator_replacement(
            self.database_path,
            "student1",
            "old1",
            "replacement1",
            "suspected_compromise",
        )

        self.assertEqual(replacement["status"], "prepared")
        self.assertEqual(replacement["user_id"], "student1")
        self.assertEqual(replacement["device_id"], "replacement1")
        self.assertTrue(replacement["authorization_secret"])
        old = get_device(self.database_path, "student1", "old1")
        other = get_device(self.database_path, "student1", "other1")
        self.assertTrue(old["revoked"])
        self.assertEqual(old["public_key_fingerprint"], old_fingerprint)
        self.assertEqual(old["revocation_reason"], "suspected_compromise")
        self.assertFalse(other["revoked"])
        self.assertEqual(other["public_key_fingerprint"], other_fingerprint)
        self.assertIsNone(get_device(self.database_path, "student1", "replacement1"))
        self.assertIsNone(
            get_authentication_challenge(self.database_path, old_challenge["challenge_id"])
        )

        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                """
                SELECT user_id, device_id, consumed_at, cancelled_at
                FROM enrollment_authorizations
                WHERE authorization_id = ?
                """,
                (replacement["authorization_id"],),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(row, ("student1", "replacement1", None, None))

    def test_replacement_preparation_rolls_back_when_revocation_cannot_commit(self):
        self._create_identity()
        old_public_key, old_fingerprint = self._public_key_values()
        register_device(
            self.database_path, "student1", "old1", old_public_key, old_fingerprint
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_replacement_revocation
                BEFORE UPDATE OF revoked ON devices
                WHEN NEW.revoked = 1
                BEGIN
                    SELECT RAISE(ABORT, 'simulated replacement failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(DatabaseOperationError):
            prepare_authenticator_replacement(
                self.database_path,
                "student1",
                "old1",
                "replacement1",
                "lost",
            )

        self.assertFalse(get_device(self.database_path, "student1", "old1")["revoked"])
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM enrollment_authorizations
                WHERE user_id = ? AND device_id = ?
                """,
                ("student1", "replacement1"),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 0)

    def test_replacement_preparation_refuses_an_existing_destination_before_revocation(self):
        self._create_identity()
        old_public_key, old_fingerprint = self._public_key_values()
        existing_public_key, existing_fingerprint = self._public_key_values()
        register_device(
            self.database_path, "student1", "old1", old_public_key, old_fingerprint
        )
        register_device(
            self.database_path,
            "student1",
            "replacement1",
            existing_public_key,
            existing_fingerprint,
        )

        with self.assertRaises(DuplicateDeviceError):
            prepare_authenticator_replacement(
                self.database_path,
                "student1",
                "old1",
                "replacement1",
                "planned_replacement",
            )

        self.assertFalse(get_device(self.database_path, "student1", "old1")["revoked"])
        self.assertFalse(
            get_device(self.database_path, "student1", "replacement1")["revoked"]
        )

    def test_replacement_retry_without_the_secret_does_not_reactivate_old_binding(self):
        self._create_identity()
        old_public_key, old_fingerprint = self._public_key_values()
        register_device(
            self.database_path, "student1", "old1", old_public_key, old_fingerprint
        )
        first = prepare_authenticator_replacement(
            self.database_path,
            "student1",
            "old1",
            "replacement1",
            "lost",
        )
        retry = prepare_authenticator_replacement(
            self.database_path,
            "student1",
            "old1",
            "replacement1",
            "lost",
        )
        replacement_authorization = issue_enrollment_authorization(
            self.database_path, "student1", "replacement1"
        )

        self.assertEqual(retry["status"], "already_revoked")
        self.assertNotIn("authorization_secret", retry)
        self.assertNotEqual(
            replacement_authorization["authorization_id"], first["authorization_id"]
        )
        self.assertTrue(get_device(self.database_path, "student1", "old1")["revoked"])
        connection = sqlite3.connect(self.database_path)
        try:
            first_cancelled_at = connection.execute(
                """
                SELECT cancelled_at FROM enrollment_authorizations
                WHERE authorization_id = ?
                """,
                (first["authorization_id"],),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertIsNotNone(first_cancelled_at)

    def test_concurrent_replacement_preparation_has_one_winner(self):
        self._create_identity()
        old_public_key, old_fingerprint = self._public_key_values()
        register_device(
            self.database_path, "student1", "old1", old_public_key, old_fingerprint
        )

        start = threading.Barrier(2)

        def prepare_once():
            start.wait(timeout=5)
            return prepare_authenticator_replacement(
                self.database_path,
                "student1",
                "old1",
                "replacement1",
                "planned_replacement",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(
                    lambda _: prepare_once(),
                    range(2),
                )
            )

        self.assertEqual(sorted(result["status"] for result in results), [
            "already_revoked",
            "prepared",
        ])
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM enrollment_authorizations
                WHERE user_id = ? AND device_id = ?
                """,
                ("student1", "replacement1"),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)

    def test_challenge_is_consumed_once_across_concurrent_connections(self):
        self._create_identity()
        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "laptop1", public_key_b64, fingerprint)
        challenge = issue_authentication_challenge(
            self.database_path, "student1", "laptop1"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    consume_authentication_challenge,
                    self.database_path,
                    challenge["challenge_id"],
                )
                for _ in range(2)
            ]
            results = [future.result() for future in futures]

        self.assertEqual(sorted(results), [False, True])
        self.assertIsNotNone(
            get_authentication_challenge(self.database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_challenge_issuance_bounds_open_state_and_removes_stale_rows(self):
        self._create_identity()
        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "laptop1", public_key_b64, fingerprint)
        issued_at = "2026-01-01T00:00:00+00:00"
        with patch.object(db_utils, "utc_now", return_value=issued_at):
            challenges = [
                issue_authentication_challenge(
                    self.database_path, "student1", "laptop1", lifetime_seconds=60
                )
                for _ in range(db_utils.MAX_OUTSTANDING_CHALLENGES_PER_BINDING)
            ]
            self.assertIsNone(
                issue_authentication_challenge(
                    self.database_path, "student1", "laptop1", lifetime_seconds=60
                )
            )

        connection = sqlite3.connect(self.database_path)
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM authentication_challenges").fetchone()[0],
                db_utils.MAX_OUTSTANDING_CHALLENGES_PER_BINDING,
            )
        finally:
            connection.close()

        with patch.object(
            db_utils, "utc_now", return_value="2026-01-01T00:01:00+00:00"
        ):
            replacement = issue_authentication_challenge(
                self.database_path, "student1", "laptop1", lifetime_seconds=60
            )

        self.assertIsNotNone(replacement)
        self.assertEqual(len({challenge["challenge_id"] for challenge in challenges}), len(challenges))
        connection = sqlite3.connect(self.database_path)
        try:
            rows = connection.execute(
                "SELECT challenge_id FROM authentication_challenges"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(rows, [(replacement["challenge_id"],)])

    def test_challenge_expiry_is_checked_after_waiting_for_sqlite_writer(self):
        self._create_identity()
        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "laptop1", public_key_b64, fingerprint)
        issued_at = "2026-01-01T00:00:00+00:00"
        with patch.object(db_utils, "utc_now", return_value=issued_at):
            challenge = issue_authentication_challenge(
                self.database_path, "student1", "laptop1", lifetime_seconds=600
            )

        writer = sqlite3.connect(self.database_path)
        writer.execute("BEGIN IMMEDIATE")
        begin_attempted = threading.Event()
        writer_released = threading.Event()
        timestamp_before_writer_release = threading.Event()
        result = {}
        original_open = db_utils._open_existing_database

        def observed_open(database_path):
            connection = original_open(database_path)
            return ObservedConnection(connection)

        class ObservedConnection:
            def __init__(self, connection):
                self.connection = connection

            def execute(self, statement, *parameters):
                if statement == "BEGIN IMMEDIATE":
                    begin_attempted.set()
                return self.connection.execute(statement, *parameters)

            def rollback(self):
                self.connection.rollback()

            def close(self):
                self.connection.close()

        def transaction_time():
            if not writer_released.is_set():
                timestamp_before_writer_release.set()
                return "2026-01-01T00:09:59+00:00"
            return "2026-01-01T00:10:00+00:00"

        def consume():
            result["consumed"] = consume_authentication_challenge(
                self.database_path, challenge["challenge_id"]
            )

        try:
            with patch.object(db_utils, "_open_existing_database", side_effect=observed_open):
                with patch.object(db_utils, "utc_now", side_effect=transaction_time):
                    thread = threading.Thread(target=consume)
                    thread.start()
                    self.assertTrue(begin_attempted.wait(timeout=2))
                    self.assertFalse(timestamp_before_writer_release.is_set())
                    writer_released.set()
                    writer.commit()
                    thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
        finally:
            writer.close()

        self.assertFalse(result["consumed"])
        self.assertFalse(timestamp_before_writer_release.is_set())
        self.assertIsNone(
            get_authentication_challenge(self.database_path, challenge["challenge_id"])[
                "consumed_at"
            ]
        )

    def test_active_binding_claim_window_orders_claim_before_revocation(self):
        self._create_identity()
        public_key_b64, fingerprint = self._public_key_values()
        register_device(self.database_path, "student1", "laptop1", public_key_b64, fingerprint)
        claim_started = threading.Event()
        release_claim = threading.Event()
        outcome = {}

        def claim():
            claim_started.set()
            self.assertTrue(release_claim.wait(5))
            return "claimed"

        def run_claim():
            outcome["claim"] = run_if_binding_active(
                self.database_path, "student1", "laptop1", fingerprint, claim
            )

        def revoke():
            outcome["revoke"] = revoke_authenticator(
                self.database_path, "student1", "laptop1", "suspected_compromise"
            )

        claim_thread = threading.Thread(target=run_claim)
        claim_thread.start()
        self.assertTrue(claim_started.wait(5))
        revoke_thread = threading.Thread(target=revoke)
        revoke_thread.start()
        release_claim.set()
        claim_thread.join(10)
        revoke_thread.join(10)

        self.assertEqual(outcome["claim"], "claimed")
        self.assertEqual(outcome["revoke"], "revoked")
        self.assertFalse(
            run_if_binding_active(
                self.database_path, "student1", "laptop1", fingerprint, lambda: True
            )
        )


if __name__ == "__main__":
    unittest.main()
