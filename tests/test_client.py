import io
import json
import tempfile
import threading
import unittest
import getpass
import base64
from urllib.parse import urlparse
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import client
import credential_store
import server
from credential_store import CredentialError, credential_paths, load_credential
from crypto_utils import (
    encrypt_private_key,
    generate_aes_key,
    generate_rsa_keypair,
    public_key_b64_from_private_key,
    validate_rsa_public_key,
)
from db_utils import (
    create_identity,
    get_device,
    initialize_database,
    prepare_authenticator_replacement,
    register_device,
    revoke_authenticator,
)


PASSPHRASE = "correct horse battery"


class ClientCredentialTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self._temp_dir.name) / "credentials"
        self.authorization_id = "authorization-123"
        self.authorization_secret = "secret-value"
        self.user_id = "student1"
        self.device_id = "laptop1"

    def tearDown(self):
        self._temp_dir.cleanup()

    def _register(self):
        return client.register_device(
            self.user_id,
            self.device_id,
            self.authorization_id,
            self.authorization_secret,
            PASSPHRASE,
            self.root,
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

    def _current_path(self):
        return credential_paths(self.user_id, self.device_id, self.root)[0]

    def test_accepted_registration_publishes_one_passphrase_credential(self):
        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"])) as post:
            result = self._register()

        self.assertEqual(result["status"], "created")
        current_path = self._current_path()
        self.assertTrue(current_path.exists())
        self.assertFalse(any(path.suffix == ".bin" for path in self.root.iterdir()))
        self.assertFalse(any(path.suffix == ".enc" for path in self.root.iterdir()))
        private_key, public_key, fingerprint = load_credential(
            current_path, self.user_id, self.device_id, PASSPHRASE
        )
        self.assertEqual(public_key, post.call_args.kwargs["json"]["public_key_b64"])
        self.assertEqual(fingerprint, result["public_key_fingerprint"])
        self.assertTrue(private_key.startswith(b"-----BEGIN PRIVATE KEY-----"))

    def test_existing_credential_is_never_overwritten_or_sent(self):
        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"])) as post:
            self._register()
        original = self._current_path().read_bytes()

        with self.assertRaises(CredentialError):
            self._register()

        self.assertEqual(self._current_path().read_bytes(), original)
        self.assertEqual(post.call_count, 1)

    def test_replacement_retry_preserves_one_new_credential_after_lost_response(self):
        database_path = Path(self._temp_dir.name) / "identity_lab.sqlite3"
        initialize_database(database_path)
        create_identity(database_path, self.user_id)
        _, old_public = generate_rsa_keypair()
        old_public_key_b64, old_fingerprint = validate_rsa_public_key(
            base64.b64encode(old_public).decode("ascii")
        )
        register_device(
            database_path,
            self.user_id,
            "old1",
            old_public_key_b64,
            old_fingerprint,
        )
        replacement = prepare_authenticator_replacement(
            database_path,
            self.user_id,
            "old1",
            self.device_id,
            "suspected_compromise",
        )
        original_server_config = {
            "TESTING": server.app.config["TESTING"],
            "DATABASE_PATH": server.app.config["DATABASE_PATH"],
        }
        self.addCleanup(server.app.config.update, original_server_config)
        server.app.config.update(TESTING=True, DATABASE_PATH=str(database_path))
        captured = {}

        def bind_then_lose_response(url, json, timeout):
            captured.update(json)
            response = server.app.test_client().post(urlparse(url).path, json=json)
            self.assertEqual(response.status_code, 200)
            raise client.requests.Timeout()

        with patch("client.requests.post", side_effect=bind_then_lose_response):
            uncertain = client.register_device(
                self.user_id,
                self.device_id,
                replacement["authorization_id"],
                replacement["authorization_secret"],
                PASSPHRASE,
                self.root,
            )

        current_path = self._current_path()
        credential_before_retry = current_path.read_bytes()
        self.assertEqual(uncertain["status"], "enrollment_outcome_uncertain")
        self.assertTrue(current_path.exists())
        self.assertTrue(get_device(database_path, self.user_id, "old1")["revoked"])

        def dispatch_to_server(url, json, timeout):
            response = server.app.test_client().post(urlparse(url).path, json=json)
            result = Mock()
            result.status_code = response.status_code
            result.ok = response.status_code < 400
            result.json.return_value = response.get_json()
            return result

        with patch("client.requests.post", side_effect=dispatch_to_server):
            reconciled = client.retry_device_enrollment(
                self.user_id,
                self.device_id,
                replacement["authorization_id"],
                replacement["authorization_secret"],
                PASSPHRASE,
                self.root,
            )

        _, _, credential_fingerprint = load_credential(
            current_path, self.user_id, self.device_id, PASSPHRASE
        )
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertEqual(current_path.read_bytes(), credential_before_retry)
        self.assertEqual(captured["public_key_b64"], get_device(
            database_path, self.user_id, self.device_id
        )["public_key_b64"])
        self.assertEqual(
            credential_fingerprint,
            get_device(database_path, self.user_id, self.device_id)[
                "public_key_fingerprint"
            ],
        )

    def test_denial_timeout_and_connection_failure_preserve_same_credential(self):
        denied = Mock()
        denied.ok = False
        denied.status_code = 403
        denied.json.return_value = {"error": "denied"}
        responses = [
            denied,
            client.requests.Timeout(),
            client.requests.ConnectionError(),
        ]
        for outcome in responses:
            with self.subTest(outcome=type(outcome).__name__):
                if isinstance(outcome, Exception):
                    request_patch = patch("client.requests.post", side_effect=outcome)
                else:
                    request_patch = patch("client.requests.post", return_value=outcome)
                with request_patch:
                    result = self._register()
                if isinstance(outcome, Exception):
                    self.assertEqual(result["status"], "enrollment_outcome_uncertain")
                else:
                    self.assertEqual(result["status"], "enrollment_not_confirmed")
                self.assertIn("preserved", result["warning"])
                self.assertTrue(self._current_path().exists())
                self._current_path().unlink()

    def test_malformed_and_mismatched_success_preserve_credential(self):
        malformed = Mock(ok=True, status_code=200)
        malformed.json.side_effect = ValueError("not json")
        with patch("client.requests.post", return_value=malformed):
            result = self._register()
        self.assertEqual(result["status"], "enrollment_outcome_uncertain")
        self.assertIn("could not be parsed", result["error"])
        self.assertTrue(self._current_path().exists())
        self._current_path().unlink()

        def mismatched(*args, **kwargs):
            response = self._success_response(kwargs["json"])
            response.json.return_value["device_id"] = "other-device"
            return response

        with patch("client.requests.post", side_effect=mismatched):
            result = self._register()
        self.assertEqual(result["status"], "enrollment_outcome_uncertain")
        self.assertIn("could not be validated", result["error"])
        self.assertTrue(self._current_path().exists())

    def test_cli_reports_post_dispatch_enrollment_transport_uncertainty(self):
        secrets = iter([self.authorization_secret, PASSPHRASE, PASSPHRASE])
        output = io.StringIO()
        with patch.object(client, "_read_hidden_secret", side_effect=lambda prompt: next(secrets)), patch(
            "client.requests.post", side_effect=client.requests.Timeout()
        ), redirect_stdout(output):
            exit_code = client.main(
                [
                    "--credential-directory",
                    str(self.root),
                    "enroll",
                    self.user_id,
                    self.device_id,
                    self.authorization_id,
                ]
            )
        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(result["status"], "enrollment_outcome_uncertain")
        self.assertTrue(self._current_path().exists())

    def test_concurrent_fresh_enrollment_publishes_and_sends_only_winner_key(self):
        barrier = threading.Barrier(2)
        original_link = credential_store.os.link
        original_argon2id = credential_store.Argon2id
        original_build = client._build_enrollment_payload
        generated_fingerprints = {}
        sent_fingerprints = []
        results = []
        errors = []
        lock = threading.Lock()
        kdf_lock = threading.Lock()

        class SerializedArgon2id:
            def __init__(self, *args, **kwargs):
                self._argon2id = original_argon2id(*args, **kwargs)

            def derive(self, passphrase):
                # The test exercises publication concurrency. Serializing this
                # resource-intensive real KDF keeps two test clients from
                # exhausting a constrained CI runner before they reach it.
                with kdf_lock:
                    return self._argon2id.derive(passphrase)

        def synchronized_link(source, destination):
            barrier.wait(timeout=10)
            return original_link(source, destination)

        def record_payload(*args, **kwargs):
            payload, fingerprint = original_build(*args, **kwargs)
            with lock:
                generated_fingerprints[threading.current_thread().name] = fingerprint
            return payload, fingerprint

        def accepted_response(*args, **kwargs):
            response = self._success_response(kwargs["json"])
            with lock:
                sent_fingerprints.append(response.json.return_value["public_key_fingerprint"])
            return response

        def enroll():
            try:
                result = self._register()
                with lock:
                    results.append(result)
            except CredentialError as exc:
                with lock:
                    errors.append(exc.code)

        with patch.object(credential_store, "Argon2id", SerializedArgon2id), patch.object(
            credential_store.os, "link", side_effect=synchronized_link
        ), patch.object(
            client, "_build_enrollment_payload", side_effect=record_payload
        ), patch("client.requests.post", side_effect=accepted_response):
            first = threading.Thread(target=enroll, name="first")
            second = threading.Thread(target=enroll, name="second")
            first.start()
            second.start()
            first.join(30)
            second.join(30)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, ["credential_exists"])
        self.assertEqual(len(results), 1)
        self.assertEqual(sent_fingerprints, [results[0]["public_key_fingerprint"]])
        self.assertEqual(len(generated_fingerprints), 2)
        losing_fingerprint = next(
            fingerprint
            for fingerprint in generated_fingerprints.values()
            if fingerprint != results[0]["public_key_fingerprint"]
        )
        self.assertNotIn(losing_fingerprint, sent_fingerprints)
        _, _, final_fingerprint = load_credential(
            self._current_path(), self.user_id, self.device_id, PASSPHRASE
        )
        self.assertEqual(final_fingerprint, results[0]["public_key_fingerprint"])

    def test_retry_reuses_the_same_key_and_credential_bytes(self):
        denied = Mock(ok=False, status_code=503)
        denied.json.return_value = {"error": "state unavailable"}
        with patch("client.requests.post", return_value=denied):
            self._register()
        current_before = self._current_path().read_bytes()
        _, public_before, fingerprint_before = load_credential(
            self._current_path(), self.user_id, self.device_id, PASSPHRASE
        )

        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"], "reconciled")) as post:
            result = client.retry_device_enrollment(
                self.user_id,
                self.device_id,
                self.authorization_id,
                self.authorization_secret,
                PASSPHRASE,
                self.root,
            )

        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(self._current_path().read_bytes(), current_before)
        self.assertEqual(post.call_args.kwargs["json"]["public_key_b64"], public_before)
        self.assertEqual(result["public_key_fingerprint"], fingerprint_before)

    def test_invalid_identifier_and_bad_local_unlock_make_no_request(self):
        with patch("client.requests.post") as post:
            with self.assertRaises(ValueError):
                client.register_device(
                    "student one",
                    self.device_id,
                    self.authorization_id,
                    self.authorization_secret,
                    PASSPHRASE,
                    self.root,
                )
        post.assert_not_called()

        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"])):
            self._register()
        with patch("client.requests.post") as post:
            with self.assertRaises(CredentialError):
                client.login(self.user_id, self.device_id, "wrong passphrase value", self.root)
        post.assert_not_called()

        self._current_path().write_bytes(b"not a credential")
        with patch("client.requests.post") as post:
            with self.assertRaises(CredentialError):
                client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        post.assert_not_called()

        legacy_root = self.root.parent / "legacy"
        legacy_root.mkdir()
        legacy_key, _ = generate_rsa_keypair()
        legacy_aes = generate_aes_key()
        (legacy_root / f"privkey_{self.user_id}_{self.device_id}.enc").write_text(
            encrypt_private_key(legacy_aes, legacy_key), encoding="ascii"
        )
        (legacy_root / f"aeskey_{self.user_id}_{self.device_id}.bin").write_bytes(
            legacy_aes
        )
        with patch("client.requests.post") as post:
            with self.assertRaises(CredentialError):
                client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        post.assert_not_called()

    def test_login_transport_outcomes_are_classified_by_dispatch_boundary(self):
        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"])):
            self._register()
        current_before = self._current_path().read_bytes()
        _, _, fingerprint = load_credential(
            self._current_path(), self.user_id, self.device_id, PASSPHRASE
        )
        challenge = Mock()
        challenge.json.return_value = {
            "protocol": client.AUTHENTICATION_PROTOCOL,
            "challenge_id": "A" * 43,
            "nonce": base64.b64encode(b"x" * 32).decode("ascii"),
            "user_id": self.user_id,
            "device_id": self.device_id,
            "public_key_fingerprint": fingerprint,
            "expires_at": "2026-01-01T00:05:00+00:00",
        }

        with patch("client.requests.post", side_effect=[challenge, client.requests.Timeout()]) as post:
            result = client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        self.assertEqual(result["status"], "authentication_outcome_uncertain")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(self._current_path().read_bytes(), current_before)

        with patch("client.requests.post", side_effect=client.requests.Timeout()) as post:
            result = client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        self.assertEqual(result["status"], "challenge_unavailable")
        self.assertEqual(post.call_count, 1)
        self.assertEqual(self._current_path().read_bytes(), current_before)

    def test_login_uses_v2_challenge_context_without_replacing_credential(self):
        with patch(
            "client.requests.post",
            side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"]),
        ):
            self._register()
        current_before = self._current_path().read_bytes()
        _, _, fingerprint = load_credential(
            self._current_path(), self.user_id, self.device_id, PASSPHRASE
        )
        challenge = Mock()
        challenge.json.return_value = {
            "protocol": client.AUTHENTICATION_PROTOCOL,
            "challenge_id": "A" * 43,
            "nonce": base64.b64encode(b"x" * 32).decode("ascii"),
            "user_id": self.user_id,
            "device_id": self.device_id,
            "public_key_fingerprint": fingerprint,
            "expires_at": "2026-01-01T00:05:00+00:00",
        }
        verified = Mock()
        verified.json.return_value = {"status": "success", "message": "Login OK"}

        with patch("client.requests.post", side_effect=[challenge, verified]) as post:
            result = client.login(self.user_id, self.device_id, PASSPHRASE, self.root)

        self.assertEqual(result["status"], "success")
        self.assertEqual(post.call_args_list[0].kwargs["json"], {
            "protocol": client.AUTHENTICATION_PROTOCOL,
            "user_id": self.user_id,
            "device_id": self.device_id,
        })
        verification_payload = post.call_args_list[1].kwargs["json"]
        self.assertEqual(
            set(verification_payload), {"protocol", "challenge_id", "signature"}
        )
        self.assertEqual(verification_payload["protocol"], client.AUTHENTICATION_PROTOCOL)
        self.assertEqual(verification_payload["challenge_id"], "A" * 43)
        self.assertEqual(self._current_path().read_bytes(), current_before)

    def test_invalid_challenge_or_verification_response_preserves_credential(self):
        with patch(
            "client.requests.post",
            side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"]),
        ):
            self._register()
        current_before = self._current_path().read_bytes()
        invalid_challenge = Mock()
        invalid_challenge.json.return_value = {"protocol": client.AUTHENTICATION_PROTOCOL}
        with patch("client.requests.post", return_value=invalid_challenge) as post:
            result = client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        self.assertEqual(result["status"], "challenge_unavailable")
        self.assertEqual(post.call_count, 1)

        _, _, fingerprint = load_credential(
            self._current_path(), self.user_id, self.device_id, PASSPHRASE
        )
        valid_challenge = Mock()
        valid_challenge.json.return_value = {
            "protocol": client.AUTHENTICATION_PROTOCOL,
            "challenge_id": "A" * 43,
            "nonce": base64.b64encode(b"x" * 32).decode("ascii"),
            "user_id": self.user_id,
            "device_id": self.device_id,
            "public_key_fingerprint": fingerprint,
            "expires_at": "2026-01-01T00:05:00+00:00",
        }
        malformed_verification = Mock()
        malformed_verification.json.side_effect = ValueError("not json")
        with patch(
            "client.requests.post", side_effect=[valid_challenge, malformed_verification]
        ):
            result = client.login(self.user_id, self.device_id, PASSPHRASE, self.root)
        self.assertEqual(result["status"], "authentication_outcome_uncertain")
        self.assertEqual(self._current_path().read_bytes(), current_before)

    def test_status_command_does_not_need_a_secret(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = client.main(
                ["--credential-directory", str(self.root), "credential-status", self.user_id, self.device_id]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "absent")
        self.assertEqual(json.loads(output.getvalue())["credential_validation"], "not_present")

    def test_status_rejects_unsafe_occupants_and_marks_recognized_state_unverified(self):
        current_path = self._current_path()
        current_path.parent.mkdir(parents=True)
        current_path.mkdir()
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = client.main(
                ["--credential-directory", str(self.root), "credential-status", self.user_id, self.device_id]
            )
        status = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(status["status"], "invalid_or_conflicting")
        self.assertEqual(status["credential_validation"], "invalid_or_conflicting")

        current_path.rmdir()
        current_path.write_bytes(b"not a credential")
        self.assertEqual(
            client.describe_local_state(self.user_id, self.device_id, self.root)[0],
            "invalid_or_conflicting",
        )

        current_path.unlink()
        with patch("client.requests.post", side_effect=lambda *args, **kwargs: self._success_response(kwargs["json"])):
            self._register()
        with patch.object(credential_store, "Argon2id", side_effect=AssertionError("unlock attempted")):
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = client.main(
                    ["--credential-directory", str(self.root), "credential-status", self.user_id, self.device_id]
                )
        status = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(status["status"], "current")
        self.assertEqual(status["credential_validation"], "structurally_recognized_not_unlocked")

    def test_login_command_returns_success_exit_code_for_v2_login_success(self):
        output = io.StringIO()
        with patch.object(client, "_read_hidden_secret", return_value=PASSPHRASE), patch.object(
            client, "login", return_value={"status": "success", "message": "Login OK"}
        ), redirect_stdout(output):
            exit_code = client.main(
                ["--credential-directory", str(self.root), "login", self.user_id, self.device_id]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "success")

    def test_hidden_input_warning_fails_without_accepting_echoed_secret(self):
        with patch.object(client.getpass, "getpass", side_effect=getpass.GetPassWarning("unsafe")):
            with self.assertRaises(CredentialError) as error:
                client._read_hidden_secret("Secret: ")
        self.assertEqual(error.exception.code, "secret_input_unavailable")


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        base = Path(self._temp_dir.name)
        self.credential_root = base / "credentials"
        self.legacy_root = base / "legacy"
        self.legacy_root.mkdir()
        self.database_path = base / "identity.sqlite3"
        initialize_database(self.database_path)
        self.user_id = "student1"
        self.device_id = "laptop1"
        create_identity(self.database_path, self.user_id)
        self.private_key_pem, _ = generate_rsa_keypair()
        public_key = public_key_b64_from_private_key(self.private_key_pem)
        public_key, self.fingerprint = validate_rsa_public_key(public_key)
        register_device(
            self.database_path,
            self.user_id,
            self.device_id,
            public_key,
            self.fingerprint,
        )
        self.private_path = self.legacy_root / f"privkey_{self.user_id}_{self.device_id}.enc"
        self.aes_path = self.legacy_root / f"aeskey_{self.user_id}_{self.device_id}.bin"
        aes_key = generate_aes_key()
        self.private_path.write_text(encrypt_private_key(aes_key, self.private_key_pem), encoding="ascii")
        self.aes_path.write_bytes(aes_key)

    def tearDown(self):
        self._temp_dir.cleanup()

    def _migrate(self):
        return client.migrate_legacy_credential(
            self.user_id,
            self.device_id,
            PASSPHRASE,
            self.database_path,
            self.legacy_root,
            self.credential_root,
        )

    def _create_unclaimed_staging(self):
        with patch.object(client, "run_if_binding_active", return_value=False):
            with self.assertRaises(CredentialError):
                self._migrate()
        return credential_paths(self.user_id, self.device_id, self.credential_root)

    def test_migration_rewraps_exact_active_key_and_removes_legacy_pair(self):
        result = self._migrate()
        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertEqual(result["status"], "legacy_migrated")
        self.assertEqual(result["public_key_fingerprint"], self.fingerprint)
        self.assertTrue(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertFalse(self.private_path.exists())
        self.assertFalse(self.aes_path.exists())
        _, _, fingerprint = load_credential(
            current_path, self.user_id, self.device_id, PASSPHRASE
        )
        self.assertEqual(fingerprint, self.fingerprint)

    def test_unmatched_or_revoked_binding_cannot_start_migration(self):
        revoke_authenticator(
            self.database_path, self.user_id, self.device_id, "suspected_compromise"
        )
        with self.assertRaises(CredentialError):
            self._migrate()
        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertFalse(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

    def test_malformed_or_oversized_legacy_material_is_bounded_and_preserved(self):
        original_aes_key = self.aes_path.read_bytes()
        self.aes_path.write_bytes(b"x" * 33)
        with self.assertRaises(CredentialError) as error:
            self._migrate()
        self.assertEqual(error.exception.code, "legacy_unavailable")
        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertFalse(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

        self.aes_path.write_bytes(b"y" * 32)
        with self.assertRaises(CredentialError) as error:
            self._migrate()
        self.assertEqual(error.exception.code, "legacy_unavailable")
        self.assertFalse(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())
        self.aes_path.write_bytes(original_aes_key)

    def test_legacy_aes_reader_uses_only_key_length_plus_one(self):
        calls = []
        original_open = Path.open

        class TrackedFile:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                calls.append(size)
                return b"x" * size

        def tracked_open(path, *args, **kwargs):
            if path == self.aes_path:
                return TrackedFile()
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=tracked_open):
            with self.assertRaises(CredentialError) as error:
                self._migrate()
        self.assertEqual(error.exception.code, "legacy_unavailable")
        self.assertEqual(calls, [33])

    def test_discard_first_removes_only_unclaimed_staging_before_resume_can_claim(self):
        current_path, pending_path = self._create_unclaimed_staging()
        discard_inside_claim = threading.Event()
        allow_discard = threading.Event()
        resume_attempted_claim = threading.Event()
        discard_result = []
        resume_error = []
        original_unlink = Path.unlink
        original_run = client.run_if_binding_active

        def watched_run(*args, **kwargs):
            if threading.current_thread().name == "resume":
                resume_attempted_claim.set()
            return original_run(*args, **kwargs)

        def pause_discard_unlink(path, *args, **kwargs):
            if path == pending_path and threading.current_thread().name == "discard":
                discard_inside_claim.set()
                allow_discard.wait(10)
            return original_unlink(path, *args, **kwargs)

        def discard():
            try:
                discard_result.append(
                    client.discard_unclaimed_staging(
                        self.user_id,
                        self.device_id,
                        PASSPHRASE,
                        self.database_path,
                        self.legacy_root,
                        self.credential_root,
                    )
                )
            except CredentialError as exc:
                discard_result.append(exc.code)

        def resume():
            try:
                client.resume_legacy_cleanup(
                    self.user_id,
                    self.device_id,
                    PASSPHRASE,
                    self.database_path,
                    self.legacy_root,
                    self.credential_root,
                )
            except CredentialError as exc:
                resume_error.append(exc.code)

        with patch.object(client, "run_if_binding_active", side_effect=watched_run), patch.object(
            Path, "unlink", autospec=True, side_effect=pause_discard_unlink
        ):
            discard_thread = threading.Thread(target=discard, name="discard")
            discard_thread.start()
            self.assertTrue(discard_inside_claim.wait(10))
            resume_thread = threading.Thread(target=resume, name="resume")
            resume_thread.start()
            self.assertTrue(resume_attempted_claim.wait(10))
            allow_discard.set()
            discard_thread.join(20)
            resume_thread.join(20)

        self.assertFalse(discard_thread.is_alive())
        self.assertFalse(resume_thread.is_alive())
        self.assertEqual(discard_result, [{"status": "staging_discarded"}])
        self.assertIn(resume_error[0], {"credential_missing", "storage_unavailable", "migration_refused"})
        self.assertFalse(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

    def test_claim_first_preserves_pending_marker_against_discard(self):
        current_path, pending_path = self._create_unclaimed_staging()
        discard_ready = threading.Event()
        allow_discard = threading.Event()
        claim_complete = threading.Event()
        allow_cleanup = threading.Event()
        discard_error = []
        resume_error = []
        original_run = client.run_if_binding_active
        original_finish = client._finish_cleanup

        def ordered_run(*args, **kwargs):
            if threading.current_thread().name == "discard":
                discard_ready.set()
                allow_discard.wait(10)
            return original_run(*args, **kwargs)

        def hold_cleanup(*args, **kwargs):
            if threading.current_thread().name == "resume":
                claim_complete.set()
                allow_cleanup.wait(10)
                raise CredentialError("mixed_cleanup_required", "forced pause")
            return original_finish(*args, **kwargs)

        def discard():
            try:
                client.discard_unclaimed_staging(
                    self.user_id,
                    self.device_id,
                    PASSPHRASE,
                    self.database_path,
                    self.legacy_root,
                    self.credential_root,
                )
            except CredentialError as exc:
                discard_error.append(exc.code)

        def resume():
            try:
                client.resume_legacy_cleanup(
                    self.user_id,
                    self.device_id,
                    PASSPHRASE,
                    self.database_path,
                    self.legacy_root,
                    self.credential_root,
                )
            except CredentialError as exc:
                resume_error.append(exc.code)

        with patch.object(client, "run_if_binding_active", side_effect=ordered_run), patch.object(
            client, "_finish_cleanup", side_effect=hold_cleanup
        ):
            discard_thread = threading.Thread(target=discard, name="discard")
            discard_thread.start()
            self.assertTrue(discard_ready.wait(10))
            resume_thread = threading.Thread(target=resume, name="resume")
            resume_thread.start()
            self.assertTrue(claim_complete.wait(10))
            self.assertTrue(current_path.exists())
            self.assertTrue(pending_path.exists())
            self.assertTrue(current_path.samefile(pending_path))
            allow_discard.set()
            discard_thread.join(20)
            allow_cleanup.set()
            resume_thread.join(20)

        self.assertFalse(discard_thread.is_alive())
        self.assertFalse(resume_thread.is_alive())
        self.assertEqual(discard_error, ["migration_refused"])
        self.assertEqual(resume_error, ["mixed_cleanup_required"])
        self.assertTrue(current_path.exists())
        self.assertTrue(pending_path.exists())
        self.assertTrue(current_path.samefile(pending_path))
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

    def test_unclaimed_staging_can_resume_only_with_active_exact_binding(self):
        with patch.object(client, "run_if_binding_active", return_value=False):
            with self.assertRaises(CredentialError):
                self._migrate()
        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertFalse(current_path.exists())
        self.assertTrue(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

        result = client.resume_legacy_cleanup(
            self.user_id,
            self.device_id,
            PASSPHRASE,
            self.database_path,
            self.legacy_root,
            self.credential_root,
        )
        self.assertEqual(result["status"], "legacy_migrated")
        self.assertTrue(current_path.exists())
        self.assertFalse(pending_path.exists())

    def test_cleanup_can_finish_after_post_claim_revocation(self):
        original_remove = client._remove_legacy_file
        with patch.object(client, "_remove_legacy_file", side_effect=CredentialError("mixed_cleanup_required", "forced cleanup failure")):
            with self.assertRaises(CredentialError):
                self._migrate()
        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertTrue(current_path.exists())
        self.assertTrue(pending_path.exists())
        revoke_authenticator(
            self.database_path, self.user_id, self.device_id, "suspected_compromise"
        )
        with patch.object(client, "_remove_legacy_file", original_remove):
            result = client.resume_legacy_cleanup(
                self.user_id,
                self.device_id,
                PASSPHRASE,
                self.database_path,
                self.legacy_root,
                self.credential_root,
            )
        self.assertEqual(result["binding_state"], "revoked")
        self.assertTrue(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertFalse(self.private_path.exists())
        self.assertFalse(self.aes_path.exists())

    def test_migration_claim_blocks_fresh_enrollment_before_network(self):
        migration_claimed = threading.Event()
        release_migration = threading.Event()

        def hold_cleanup(*args, **kwargs):
            migration_claimed.set()
            self.assertTrue(release_migration.wait(10))
            raise CredentialError("mixed_cleanup_required", "forced pause")

        migration_error = []

        def migrate():
            try:
                self._migrate()
            except CredentialError as exc:
                migration_error.append(exc.code)

        with patch.object(client, "_finish_cleanup", side_effect=hold_cleanup):
            migration = threading.Thread(target=migrate)
            migration.start()
            self.assertTrue(migration_claimed.wait(20))
            with patch("client.requests.post") as post:
                with self.assertRaises(CredentialError):
                    client.register_device(
                        self.user_id,
                        self.device_id,
                        "authorization-123",
                        "secret-value",
                        PASSPHRASE,
                        self.credential_root,
                    )
            post.assert_not_called()
            release_migration.set()
            migration.join(20)

        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertEqual(migration_error, ["mixed_cleanup_required"])
        self.assertTrue(current_path.exists())
        self.assertTrue(pending_path.exists())
        self.assertTrue(current_path.samefile(pending_path))
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())

    def test_fresh_current_winner_prevents_legacy_cleanup(self):
        fresh_checked = threading.Event()
        release_fresh = threading.Event()
        pending_created = threading.Event()
        release_migration = threading.Event()
        original_state = client._current_state
        original_claim = client.run_if_binding_active
        fresh_error = []
        migration_error = []

        def pause_fresh_state(*args, **kwargs):
            if threading.current_thread().name == "fresh" and not fresh_checked.is_set():
                result = original_state(*args, **kwargs)
                fresh_checked.set()
                self.assertTrue(release_fresh.wait(15))
                return result
            return original_state(*args, **kwargs)

        def pause_migration_claim(*args, **kwargs):
            pending_created.set()
            self.assertTrue(release_migration.wait(15))
            return original_claim(*args, **kwargs)

        def fresh():
            try:
                client.register_device(
                    self.user_id,
                    self.device_id,
                    "authorization-123",
                    "secret-value",
                    PASSPHRASE,
                    self.credential_root,
                )
            except CredentialError as exc:
                fresh_error.append(exc.code)

        def migrate():
            try:
                self._migrate()
            except CredentialError as exc:
                migration_error.append(exc.code)

        with patch.object(client, "_current_state", side_effect=pause_fresh_state), patch.object(
            client, "run_if_binding_active", side_effect=pause_migration_claim
        ), patch("client.requests.post") as post:
            fresh_thread = threading.Thread(target=fresh, name="fresh")
            fresh_thread.start()
            self.assertTrue(fresh_checked.wait(10))
            migration_thread = threading.Thread(target=migrate, name="migration")
            migration_thread.start()
            self.assertTrue(pending_created.wait(20))
            release_fresh.set()
            fresh_thread.join(20)
            release_migration.set()
            migration_thread.join(20)

        current_path, pending_path = credential_paths(
            self.user_id, self.device_id, self.credential_root
        )
        self.assertFalse(fresh_thread.is_alive())
        self.assertFalse(migration_thread.is_alive())
        self.assertEqual(fresh_error, ["mixed_cleanup_required"])
        self.assertEqual(migration_error, ["migration_refused"])
        self.assertTrue(current_path.exists())
        self.assertFalse(pending_path.exists())
        self.assertTrue(self.private_path.exists())
        self.assertTrue(self.aes_path.exists())
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
