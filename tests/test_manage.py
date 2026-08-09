import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import manage
from crypto_utils import generate_rsa_keypair, validate_rsa_public_key
from db_utils import DATABASE_ENV_VAR, get_device, register_device


class ManageCliTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"

    def tearDown(self):
        self._temp_dir.cleanup()

    def _run(self, *command):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = manage.main(["--database", str(self.database_path), *command])
        return exit_code, json.loads(output.getvalue())

    def test_init_and_status_commands(self):
        missing_exit, missing_status = self._run("status")
        init_exit, init_status = self._run("init")
        repeat_exit, repeat_status = self._run("init")
        migrate_exit, migrate_status = self._run("migrate")
        ready_exit, ready_status = self._run("status")

        self.assertEqual(missing_exit, 1)
        self.assertEqual(missing_status["status"], "not_ready")
        self.assertEqual(init_exit, 0)
        self.assertEqual(init_status["status"], "initialized")
        self.assertEqual(repeat_exit, 0)
        self.assertEqual(repeat_status["status"], "already_initialized")
        self.assertEqual(migrate_exit, 0)
        self.assertEqual(migrate_status["status"], "already_current")
        self.assertEqual(ready_exit, 0)
        self.assertEqual(ready_status["status"], "ready")
        self.assertEqual(ready_status["schema_version"], 3)
        self.assertEqual(ready_status["integrity"], "ok")

    def test_lifecycle_commands_use_sanitized_local_administration(self):
        self._run("init")
        create_exit, create_result = self._run("identity-add", "student1")
        repeated_exit, repeated_result = self._run("identity-add", "student1")
        issue_exit, authorization = self._run("enrollment-issue", "student1", "laptop1")
        cancel_exit, cancellation = self._run(
            "enrollment-cancel", authorization["authorization_id"]
        )
        inventory_exit, inventory = self._run("inventory", "--user-id", "student1")

        self.assertEqual(create_exit, 0)
        self.assertEqual(create_result["status"], "created")
        self.assertEqual(repeated_exit, 0)
        self.assertEqual(repeated_result["status"], "already_exists")
        self.assertEqual(issue_exit, 0)
        self.assertTrue(authorization["authorization_secret"])
        self.assertEqual(cancel_exit, 0)
        self.assertEqual(cancellation["status"], "cancelled")
        self.assertEqual(inventory_exit, 0)
        self.assertEqual(inventory["identities"][0]["authenticators"], [])
        self.assertNotIn("authorization_secret", json.dumps(inventory))

    def test_revoke_preserves_first_reason_and_warns_for_last_active_binding(self):
        self._run("init")
        self._run("identity-add", "student1")
        _, public_key = generate_rsa_keypair()
        public_key_b64, fingerprint = validate_rsa_public_key(
            base64.b64encode(public_key).decode("ascii")
        )
        register_device(
            self.database_path, "student1", "laptop1", public_key_b64, fingerprint
        )

        revoke_exit, revoked = self._run(
            "revoke", "student1", "laptop1", "lost"
        )
        first_revoked_at = get_device(
            self.database_path, "student1", "laptop1"
        )["revoked_at"]
        repeat_exit, repeated = self._run(
            "revoke", "student1", "laptop1", "other"
        )
        inventory_exit, inventory = self._run("inventory", "--user-id", "student1")

        self.assertEqual(revoke_exit, 0)
        self.assertEqual(revoked["status"], "revoked")
        self.assertIn("last active", revoked["warning"])
        self.assertEqual(repeat_exit, 0)
        self.assertEqual(repeated["status"], "already_revoked")
        self.assertEqual(inventory_exit, 0)
        self.assertEqual(
            inventory["identities"][0]["authenticators"][0]["revocation_reason"], "lost"
        )
        self.assertEqual(
            inventory["identities"][0]["authenticators"][0]["revoked_at"],
            first_revoked_at,
        )

    def test_init_refuses_to_replace_corrupt_state(self):
        corrupt_bytes = b"do not replace this state"
        self.database_path.write_bytes(corrupt_bytes)

        exit_code, result = self._run("init")

        self.assertEqual(exit_code, 1)
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.database_path.read_bytes(), corrupt_bytes)

    def test_default_init_stops_when_legacy_json_exists(self):
        legacy_path = self.database_path.parent / "database.json"
        legacy_contents = '{"student1": {"devices": {}}}'
        legacy_path.write_text(legacy_contents, encoding="utf-8")
        output = io.StringIO()

        with (
            patch.object(manage, "LEGACY_DATABASE_PATH", legacy_path),
            patch.object(
                manage,
                "get_default_database_path",
                return_value=self.database_path,
            ),
            patch.dict(os.environ, {DATABASE_ENV_VAR: ""}, clear=False),
            redirect_stdout(output),
        ):
            exit_code = manage.main(["init"])

        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(result["code"], "legacy_state_detected")
        self.assertEqual(legacy_path.read_text(encoding="utf-8"), legacy_contents)
        self.assertFalse(self.database_path.exists())

        with patch.object(manage, "LEGACY_DATABASE_PATH", legacy_path):
            explicit_exit, explicit_result = self._run("init")

        self.assertEqual(explicit_exit, 0)
        self.assertEqual(explicit_result["status"], "initialized")
        self.assertEqual(legacy_path.read_text(encoding="utf-8"), legacy_contents)


if __name__ == "__main__":
    unittest.main()
