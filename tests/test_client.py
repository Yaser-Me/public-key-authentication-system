import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import client


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

    def tearDown(self):
        self.path_patch.stop()
        self._temp_dir.cleanup()

    @patch("client.requests.post")
    def test_rejected_registration_does_not_create_local_key_files(self, post):
        response = Mock()
        response.ok = False
        response.status_code = 409
        response.json.return_value = {"error": "registration rejected"}
        post.return_value = response

        with redirect_stdout(io.StringIO()):
            result = client.register_device("student1", "laptop1")

        self.assertEqual(result, {"error": "registration rejected"})
        self.assertFalse(self.private_key_path.exists())
        self.assertFalse(self.aes_key_path.exists())
        self.assertEqual(post.call_args.kwargs["timeout"], client.REQUEST_TIMEOUT_SECONDS)

    @patch("client.requests.post")
    def test_accepted_registration_saves_keys_without_overwriting(self, post):
        response = Mock()
        response.ok = True
        response.json.return_value = {"status": "success"}
        post.return_value = response

        with redirect_stdout(io.StringIO()):
            result = client.register_device("student1", "laptop1")

        self.assertEqual(result, {"status": "success"})
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())
        private_key_before = self.private_key_path.read_text(encoding="utf-8")
        aes_key_before = self.aes_key_path.read_bytes()

        with self.assertRaises(FileExistsError):
            client.register_device("student1", "laptop1")

        self.assertEqual(self.private_key_path.read_text(encoding="utf-8"), private_key_before)
        self.assertEqual(self.aes_key_path.read_bytes(), aes_key_before)
        self.assertEqual(post.call_count, 1)

    @patch("client.requests.post")
    def test_invalid_identifier_is_rejected_before_network_or_file_access(self, post):
        with self.assertRaises(ValueError):
            client.register_device("student one", "laptop1")

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
                client.register_device("student1", "laptop1")

        post.assert_not_called()
        self.assertFalse(self.private_key_path.exists())
        self.assertFalse(missing_aes_path.exists())

    @patch("client.requests.post", side_effect=client.requests.Timeout)
    def test_ambiguous_timeout_preserves_complete_local_keys(self, post):
        with self.assertRaises(client.requests.Timeout):
            client.register_device("student1", "laptop1")

        self.assertEqual(post.call_count, 1)
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())

    @patch("client.requests.post")
    def test_unexpected_server_error_preserves_complete_local_keys(self, post):
        response = Mock()
        response.ok = False
        response.status_code = 500
        response.json.return_value = {"error": "unexpected server error"}
        post.return_value = response

        result = client.register_device("student1", "laptop1")

        self.assertIn("outcome is uncertain", result["warning"])
        self.assertTrue(self.private_key_path.exists())
        self.assertTrue(self.aes_key_path.exists())


if __name__ == "__main__":
    unittest.main()
