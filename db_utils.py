import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = 1
DATABASE_ENV_VAR = "PKAS_DATABASE_PATH"
DATABASE_NAME = "identity_lab.sqlite3"
APP_DIRECTORY_NAME = "PublicKeyAuthenticationSystem"


class DatabaseError(Exception):
    """Base exception for local state failures."""


class DatabaseNotInitializedError(DatabaseError):
    """Raised when the local database has not been initialized."""


class DatabaseSchemaError(DatabaseError):
    """Raised when the database is corrupt or has an unsupported schema."""


class DatabaseOperationError(DatabaseError):
    """Raised when a database operation cannot be completed safely."""


class DuplicateDeviceError(DatabaseOperationError):
    """Raised when a device identifier or public key is already registered."""


def utc_now():
    """Return an ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def get_default_database_path():
    """Return the configured database path or the Windows-first default."""
    configured_path = os.environ.get(DATABASE_ENV_VAR)
    if configured_path:
        return Path(configured_path).expanduser()

    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        base_directory = Path(local_app_data)
    else:
        base_directory = Path.home() / ".local" / "share"

    return base_directory / APP_DIRECTORY_NAME / DATABASE_NAME


def _configure_connection(connection):
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _verify_database_integrity(connection):
    integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    if len(integrity_rows) != 1 or integrity_rows[0][0] != "ok":
        raise DatabaseSchemaError("Local state failed SQLite's integrity check.")

    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise DatabaseSchemaError("Local state contains invalid device ownership data.")


def _open_existing_database(database_path):
    path = Path(database_path)
    try:
        is_database_file = path.is_file()
    except OSError as exc:
        raise DatabaseSchemaError("Local state could not be inspected safely.") from exc

    if not is_database_file:
        raise DatabaseNotInitializedError(
            f"Local state is not initialized at '{path}'. Run 'python manage.py init'."
        )

    connection = None
    try:
        uri = f"{path.resolve().as_uri()}?mode=rw"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        _configure_connection(connection)
        _verify_database_integrity(connection)
        schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
    except DatabaseError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        if connection is not None:
            connection.close()
        raise DatabaseSchemaError("Local state could not be opened safely.") from exc

    if schema_version != SCHEMA_VERSION:
        connection.close()
        raise DatabaseSchemaError(
            f"Unsupported database schema version {schema_version}; "
            f"expected {SCHEMA_VERSION}."
        )

    return connection


def _check_existing_database_for_init(path):
    status = get_database_status(path)
    if status["initialized"]:
        return False

    detail = status.get("error")
    if detail:
        raise DatabaseSchemaError(detail)
    raise DatabaseSchemaError(
        f"Refusing to replace unreadable or unsupported local state at '{path}'."
    )


def initialize_database(database_path=None):
    """Create the database schema without replacing existing local state."""
    path = Path(database_path or get_default_database_path())

    try:
        if path.exists():
            return _check_existing_database_for_init(path)
        path.parent.mkdir(parents=True, exist_ok=True)
    except DatabaseError:
        raise
    except OSError as exc:
        raise DatabaseOperationError(
            f"The local state directory could not be prepared at '{path.parent}'."
        ) from exc

    try:
        # Exclusive creation prevents initialization from replacing a file that
        # appears between the readiness check and SQLite opening the path.
        with path.open("xb"):
            pass
    except FileExistsError:
        return _check_existing_database_for_init(path)
    except OSError as exc:
        raise DatabaseOperationError("Local state could not be initialized.") from exc

    connection = None
    try:
        connection = sqlite3.connect(path, timeout=5.0)
        _configure_connection(connection)
        # DDL does not implicitly open a transaction in Python's legacy sqlite3
        # mode, so begin explicitly to make the whole schema all-or-nothing.
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE users (
                user_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            )
            """
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
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    except (OSError, sqlite3.DatabaseError) as exc:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.DatabaseError:
                pass
            connection.close()
            connection = None

        try:
            path.unlink(missing_ok=True)
        except OSError:
            raise DatabaseOperationError(
                "Local state initialization failed and its partial file "
                "could not be removed safely."
            ) from exc
        raise DatabaseOperationError("Local state could not be initialized.") from exc
    finally:
        if connection is not None:
            connection.close()

    return True


def get_database_status(database_path=None):
    """Return a read-only summary of database readiness and record counts."""
    path = Path(database_path or get_default_database_path())
    status = {
        "path": str(path.resolve()),
        "initialized": False,
        "schema_version": None,
        "integrity": "missing",
        "users": 0,
        "devices": 0,
    }

    try:
        is_database_file = path.is_file()
    except OSError:
        status["integrity"] = "unavailable"
        status["error"] = "Local state could not be inspected safely."
        return status

    if not is_database_file:
        return status

    connection = None
    try:
        connection = _open_existing_database(path)
        status.update(
            {
                "initialized": True,
                "schema_version": SCHEMA_VERSION,
                "integrity": "ok",
                "users": connection.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "devices": connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            }
        )
        return status
    except DatabaseError as exc:
        status["integrity"] = "unavailable"
        status["error"] = str(exc)
        return status
    except sqlite3.DatabaseError as exc:
        status["integrity"] = "unavailable"
        status["error"] = "Local state could not be inspected safely."
        return status
    finally:
        if connection is not None:
            connection.close()


def register_device(
    database_path,
    user_id,
    device_id,
    public_key_b64,
    public_key_fingerprint,
):
    """Register a new device and never replace an existing device or key."""
    connection = _open_existing_database(database_path)
    timestamp = utc_now()

    try:
        with connection:
            connection.execute(
                "INSERT OR IGNORE INTO users (user_id, created_at) VALUES (?, ?)",
                (user_id, timestamp),
            )
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
                (
                    user_id,
                    device_id,
                    public_key_b64,
                    public_key_fingerprint,
                    timestamp,
                ),
            )
    except sqlite3.IntegrityError as exc:
        message = str(exc).lower()
        if "unique constraint" in message:
            raise DuplicateDeviceError(
                "The device identifier or public key is already registered."
            ) from exc
        raise DatabaseOperationError("Device registration was rolled back.") from exc
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("Device registration was rolled back.") from exc
    finally:
        connection.close()


def get_user(database_path, user_id):
    """Return a user summary if it exists."""
    connection = _open_existing_database(database_path)
    try:
        row = connection.execute(
            "SELECT user_id, created_at FROM users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("The user record could not be read.") from exc
    finally:
        connection.close()


def get_device(database_path, user_id, device_id):
    """Return a device record if it exists."""
    connection = _open_existing_database(database_path)
    try:
        row = connection.execute(
            """
            SELECT
                user_id,
                device_id,
                public_key_b64,
                public_key_fingerprint,
                challenge_b64,
                revoked,
                created_at,
                revoked_at
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        ).fetchone()
        if not row:
            return None

        device = dict(row)
        device["challenge"] = device.pop("challenge_b64")
        device["revoked"] = bool(device["revoked"])
        return device
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("The device record could not be read.") from exc
    finally:
        connection.close()


def list_devices(database_path, user_id):
    """Return registered devices for a user, keyed by device identifier."""
    connection = _open_existing_database(database_path)
    try:
        rows = connection.execute(
            """
            SELECT
                user_id,
                device_id,
                public_key_b64,
                public_key_fingerprint,
                challenge_b64,
                revoked,
                created_at,
                revoked_at
            FROM devices
            WHERE user_id = ?
            ORDER BY created_at, device_id
            """,
            (user_id,),
        ).fetchall()

        devices = {}
        for row in rows:
            device = dict(row)
            device["challenge"] = device.pop("challenge_b64")
            device["revoked"] = bool(device["revoked"])
            devices[device["device_id"]] = device
        return devices
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("Device records could not be read.") from exc
    finally:
        connection.close()


def issue_device_challenge(database_path, user_id, device_id, challenge_b64):
    """Set a fresh challenge only when the device exists and is active."""
    connection = _open_existing_database(database_path)
    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE devices
                SET challenge_b64 = ?
                WHERE user_id = ? AND device_id = ? AND revoked = 0
                """,
                (challenge_b64, user_id, device_id),
            )
            return cursor.rowcount == 1
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("The challenge could not be issued.") from exc
    finally:
        connection.close()


def consume_device_challenge(database_path, user_id, device_id, challenge_b64):
    """Atomically consume the current challenge for an active device."""
    connection = _open_existing_database(database_path)
    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE devices
                SET challenge_b64 = NULL
                WHERE user_id = ?
                  AND device_id = ?
                  AND challenge_b64 = ?
                  AND revoked = 0
                """,
                (user_id, device_id, challenge_b64),
            )
            return cursor.rowcount == 1
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("The challenge could not be consumed.") from exc
    finally:
        connection.close()


def revoke_device(database_path, user_id, device_id):
    """Revoke a device and clear its outstanding challenge transactionally."""
    connection = _open_existing_database(database_path)
    timestamp = utc_now()
    try:
        with connection:
            cursor = connection.execute(
                """
                UPDATE devices
                SET revoked = 1,
                    challenge_b64 = NULL,
                    revoked_at = COALESCE(revoked_at, ?)
                WHERE user_id = ? AND device_id = ?
                """,
                (timestamp, user_id, device_id),
            )
            return cursor.rowcount == 1
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("Device revocation was rolled back.") from exc
    finally:
        connection.close()
