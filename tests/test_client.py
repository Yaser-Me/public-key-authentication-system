import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import client
from crypto_utils import validate_rsa_public_key


class ClientRegistrationTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(self._temp_dir.name)
        self.private_key_path = base_path / "private.enc"
        self.aes_key_path = base_path / "aes.bin"
        self.path_patch = patch.object(
            client,
            "_device_key_paths",
            return_value=(str(self.private_key_path), str(self.aes_key_path)),
        )
        self.path_patch.start()
        self.authorization_id = "authorization-123"
        self.authorization_secret = "secret-value"

    def tearDown(self):
        self.path_patch.stop()
        self._temp_dir.cleanup()

    def _register(self):
        return client.register_device(
            "student1",
            "laptop1",
            self.authorization_id,
            self.authorization_secret,
        )

    def _success_response(self, payload, status="created", binding_state="active"):
        response = Mock()
        response.ok = True
        response.status_code = 200
        _, fingerprint = validate_rsa_public_key(payload["public_key_b64"])
        response.json.return_value = {
            "status": status,
            "user_id": payload["user_id"],
            "device_id": payload["device_id"],
            "public_key_fingerprint": fingerprint,
            "binding_state": binding_state,
        }
        return response

    def test_denied_registration_preserves_key_files_after_request(self):
        response = Mock()
        response.ok = False
        response.status_code = 403
        response.json.return_value = {"error": "Enrollment denied."}
        with patch("client.requests.post", return_value=response) as post:
            result = self._register()

        self.assertIn("preserved", result["warning"])
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())
        self.assertEqual(post.call_args.kwargs["timeout"], client.REQUEST_TIMEOUT_SECONDS)

    def test_accepted_registration_saves_keys_without_overwriting(self):
        def post(url, json, timeout):
            return self._success_response(json)

        with patch("client.requests.post", side_effect=post) as request_post:
            with redirect_stdout(io.StringIO()):
                result = self._register()

        self.assertEqual(result["status"], "created")
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())
        private_key_before = self.private_key_path.read_text(encoding="utf-8")
        aes_key_before = self.aes_key_path.read_bytes()

        with self.assertRaises(FileExistsError):
            self._register()

        self.assertEqual(self.private_key_path.read_text(encoding="utf-8"), private_key_before)
        self.assertEqual(self.aes_key_path.read_bytes(), aes_key_before)
        self.assertEqual(request_post.call_count, 1)

    @patch("client.requests.post")
    def test_invalid_identifier_is_rejected_before_network_or_file_access(self, post):
        with self.assertRaises(ValueError):
            client.register_device(
                "student one",
                "laptop1",
                self.authorization_id,
                self.authorization_secret,
            )

        post.assert_not_called()
        self.assertFalse(self.private_key_path.exists())
        self.assertFalse(self.aes_key_path.exists())

    @patch("client.requests.post")
    def test_partial_local_write_is_cleaned_before_server_registration(self, post):
        missing_aes_path = self.aes_key_path.parent / "missing" / "aes.bin"
        with patch.object(
            client,
            "_device_key_paths",
            return_value=(str(self.private_key_path), str(missing_aes_path)),
        ):
            with self.assertRaises(FileNotFoundError):
                self._register()

        post.assert_not_called()
        self.assertFalse(self.private_key_path.exists())
        self.assertFalse(missing_aes_path.exists())

    @patch("client.requests.post", side_effect=client.requests.Timeout)
    def test_ambiguous_timeout_preserves_complete_local_keys(self, post):
        with self.assertRaises(client.requests.Timeout):
            self._register()

        self.assertEqual(post.call_count, 1)
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())

    @patch("client.requests.post", side_effect=client.requests.ConnectionError)
    def test_connection_failure_preserves_complete_local_keys(self, post):
        with self.assertRaises(client.requests.ConnectionError):
            self._register()

        self.assertEqual(post.call_count, 1)
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())

    def test_malformed_response_preserves_complete_local_keys(self):
        response = Mock()
        response.ok = True
        response.status_code = 200
        response.json.side_effect = ValueError("not JSON")

        with patch("client.requests.post", return_value=response):
            result = self._register()

        self.assertIn("could not be parsed", result["error"])
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())

    def test_mismatched_success_fields_are_ambiguous_and_preserve_keys(self):
        mismatches = {
            "user_id": "student2",
            "device_id": "tablet1",
            "public_key_fingerprint": "SHA256:wrong",
        }
        for field_name, wrong_value in mismatches.items():
            with self.subTest(field_name=field_name):
                def post(url, json, timeout):
                    response = self._success_response(json)
                    response.json.return_value[field_name] = wrong_value
                    return response

                with patch("client.requests.post", side_effect=post):
                    result = self._register()

                self.assertIn("could not be validated", result["error"])
                self.assertTrue(self.private_key_path.exists())
                self.assertTrue(self.aes_key_path.exists())
                self.private_key_path.unlink()
                self.aes_key_path.unlink()

    def test_explicit_retry_reuses_existing_key_without_overwriting(self):
        denied = Mock()
        denied.ok = False
        denied.status_code = 503
        denied.json.return_value = {"error": "state unavailable"}
        with patch("client.requests.post", return_value=denied):
            uncertain = self._register()
        self.assertIn("preserved", uncertain["warning"])
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())
        encrypted_before = self.private_key_path.read_text(encoding="utf-8")
        aes_before = self.aes_key_path.read_bytes()

        def post(url, json, timeout):
            return self._success_response(json, status="reconciled")

        with patch("client.requests.post", side_effect=post):
            result = client.retry_device_enrollment(
                "student1",
                "laptop1",
                self.authorization_id,
                self.authorization_secret,
            )

        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(self.private_key_path.read_text(encoding="utf-8"), encrypted_before)
        self.assertEqual(self.aes_key_path.read_bytes(), aes_before)


if __name__ == "__main__":
    unittest.main()
