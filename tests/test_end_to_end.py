import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import requests

import client
import manage


class LiveApplicationEndToEndTests(unittest.TestCase):
    def setUp(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)

        self.temporary_path = Path(self._temporary_directory.name)
        self.database_path = self.temporary_path / "state.sqlite3"
        self.credential_directory = self.temporary_path / "credentials"

        self.server_process = None
        self.addCleanup(self._stop_server)

    def _run_manage(self, *arguments):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = manage.main(
                ["--database", str(self.database_path), *arguments]
            )

        self.assertEqual(
            exit_code,
            0,
            f"manage command {arguments[0]!r} exited with {exit_code}",
        )
        try:
            return json.loads(output.getvalue())
        except json.JSONDecodeError as error:
            self.fail(f"manage command {arguments[0]!r} returned invalid JSON: {error}")

    @staticmethod
    def _available_loopback_port():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    def _start_server(self):
        port = self._available_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        repository_root = Path(__file__).resolve().parents[1]

        environment = os.environ.copy()
        environment["PKAS_DATABASE_PATH"] = str(self.database_path)

        self.server_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "flask",
                "--app",
                "server",
                "run",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-reload",
            ],
            cwd=repository_root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.server_process.poll() is not None:
                diagnostics = self._stop_server()
                self.fail(f"server exited before becoming ready:\n{diagnostics}")

            try:
                response = requests.get(f"{base_url}/health", timeout=0.25)
                if response.status_code == 200:
                    return base_url
            except requests.RequestException:
                pass

            time.sleep(0.05)

        diagnostics = self._stop_server()
        self.fail(f"server did not become ready within 10 seconds:\n{diagnostics}")

    def _stop_server(self):
        process = self.server_process
        if process is None:
            return ""

        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        diagnostics = ""
        if process.stdout is not None:
            diagnostics = process.stdout.read()
            process.stdout.close()

        self.server_process = None
        return diagnostics[-4000:]

    @staticmethod
    def _event_index(events, *, event_type, device_id, reason_code):
        matches = [
            (index, event)
            for index, event in enumerate(events)
            if event["event_type"] == event_type
            and event.get("device_id") == device_id
            and event["reason_code"] == reason_code
        ]
        if len(matches) != 1:
            raise AssertionError(
                f"expected one {event_type}/{device_id}/{reason_code} event, "
                f"found {len(matches)}"
            )
        return matches[0]

    def test_live_lifecycle_composes_client_server_state_and_evidence(self):
        self._run_manage("init")
        self._run_manage("identity-add", "demo")
        initial_authorization = self._run_manage(
            "enrollment-issue", "demo", "laptop"
        )

        base_url = self._start_server()
        with patch.object(client, "BASE_URL", base_url):
            initial_enrollment = client.register_device(
                "demo",
                "laptop",
                initial_authorization["authorization_id"],
                initial_authorization["authorization_secret"],
                "initial-test-passphrase",
                self.credential_directory,
            )
            self.assertEqual(initial_enrollment["status"], "created")
            self.assertEqual(initial_enrollment["binding_state"], "active")

            initial_authentication = client.login(
                "demo",
                "laptop",
                "initial-test-passphrase",
                self.credential_directory,
            )
            self.assertEqual(initial_authentication["status"], "success")

            replacement_authorization = self._run_manage(
                "replacement-prepare",
                "demo",
                "laptop",
                "replacement",
                "suspected_compromise",
            )
            self.assertEqual(replacement_authorization["status"], "prepared")

            state_after_preparation = self._run_manage(
                "inventory", "--user-id", "demo"
            )
            prepared_bindings = {
                binding["device_id"]: binding
                for binding in state_after_preparation["identities"][0][
                    "authenticators"
                ]
            }
            self.assertEqual(prepared_bindings["laptop"]["state"], "revoked")

            denied_authentication = client.login(
                "demo",
                "laptop",
                "initial-test-passphrase",
                self.credential_directory,
            )
            self.assertEqual(
                denied_authentication["code"], "authentication_denied"
            )

            replacement_enrollment = client.register_device(
                "demo",
                "replacement",
                replacement_authorization["authorization_id"],
                replacement_authorization["authorization_secret"],
                "replacement-test-passphrase",
                self.credential_directory,
            )
            self.assertEqual(replacement_enrollment["status"], "created")
            self.assertEqual(replacement_enrollment["binding_state"], "active")
            self.assertNotEqual(
                replacement_enrollment["public_key_fingerprint"],
                initial_enrollment["public_key_fingerprint"],
            )

            replacement_authentication = client.login(
                "demo",
                "replacement",
                "replacement-test-passphrase",
                self.credential_directory,
            )
            self.assertEqual(replacement_authentication["status"], "success")

        inventory = self._run_manage("inventory", "--user-id", "demo")
        bindings = {
            binding["device_id"]: binding
            for binding in inventory["identities"][0]["authenticators"]
        }
        self.assertEqual(bindings["laptop"]["state"], "revoked")
        self.assertEqual(
            bindings["laptop"]["revocation_reason"], "suspected_compromise"
        )
        self.assertEqual(bindings["replacement"]["state"], "active")
        self.assertNotEqual(
            bindings["laptop"]["public_key_fingerprint"],
            bindings["replacement"]["public_key_fingerprint"],
        )

        evidence = self._run_manage("events", "--user-id", "demo")
        events = evidence["events"]
        old_bound_index, _ = self._event_index(
            events,
            event_type="authenticator.bound",
            device_id="laptop",
            reason_code="created",
        )
        old_success_index, _ = self._event_index(
            events,
            event_type="authentication.succeeded",
            device_id="laptop",
            reason_code="proof_verified",
        )
        replacement_prepared_index, replacement_prepared_event = self._event_index(
            events,
            event_type="authenticator.replacement_prepared",
            device_id="laptop",
            reason_code="suspected_compromise",
        )
        denied_index, denied_event = self._event_index(
            events,
            event_type="authentication.denied",
            device_id="laptop",
            reason_code="binding_revoked",
        )
        replacement_bound_index, _ = self._event_index(
            events,
            event_type="authenticator.bound",
            device_id="replacement",
            reason_code="created",
        )
        replacement_success_index, _ = self._event_index(
            events,
            event_type="authentication.succeeded",
            device_id="replacement",
            reason_code="proof_verified",
        )
        self.assertLess(
            old_bound_index,
            old_success_index,
        )
        self.assertLess(old_success_index, replacement_prepared_index)
        self.assertLess(replacement_prepared_index, denied_index)
        self.assertLess(denied_index, replacement_bound_index)
        self.assertLess(replacement_bound_index, replacement_success_index)

        investigation = self._run_manage(
            "investigate", "--user-id", "demo", "--device-id", "laptop"
        )
        findings = [
            finding
            for finding in investigation["findings"]
            if finding["finding_type"] == "post_revocation_targeting"
        ]
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(
            finding["public_key_fingerprint"],
            initial_enrollment["public_key_fingerprint"],
        )
        self.assertEqual(
            finding["evidence_event_ids"],
            [replacement_prepared_event["event_id"], denied_event["event_id"]],
        )
        self.assertIn(
            "does not prove the revoked authenticator or private key sent the request",
            finding["limitation"],
        )


if __name__ == "__main__":
    unittest.main()
