import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import manage
from db_utils import DATABASE_ENV_VAR


class ManageCliTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"

    def tearDown(self):
        self._temp_dir.cleanup()

    def _run(self, command):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = manage.main(
                ["--database", str(self.database_path), command]
            )
        return exit_code, json.loads(output.getvalue())

    def test_init_and_status_commands(self):
        missing_exit, missing_status = self._run("status")
        init_exit, init_status = self._run("init")
        repeat_exit, repeat_status = self._run("init")
        ready_exit, ready_status = self._run("status")

        self.assertEqual(missing_exit, 1)
        self.assertEqual(missing_status["status"], "not_ready")
        self.assertEqual(init_exit, 0)
        self.assertEqual(init_status["status"], "initialized")
        self.assertEqual(repeat_exit, 0)
        self.assertEqual(repeat_status["status"], "already_initialized")
        self.assertEqual(ready_exit, 0)
        self.assertEqual(ready_status["status"], "ready")
        self.assertEqual(ready_status["schema_version"], 1)
        self.assertEqual(ready_status["integrity"], "ok")

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
