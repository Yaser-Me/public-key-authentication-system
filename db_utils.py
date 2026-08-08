import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_VERSION = 2
DATABASE_ENV_VAR = "PKAS_DATABASE_PATH"
DATABASE_NAME = "identity_lab.sqlite3"
APP_DIRECTORY_NAME = "PublicKeyAuthenticationSystem"
DEFAULT_ENROLLMENT_LIFETIME_SECONDS = 10 * 60
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
AUTHORIZATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
REVOCATION_REASONS = {
    "lost",
    "suspected_compromise",
    "planned_replacement",
    "other",
}


# Schema validation is deliberately conservative. This application owns its
# versioned SQLite schema, so only definitions created by supported versions are
# accepted. Comparing the whole normalized definition prevents unrelated or
# weakened CHECK expressions from impersonating the required lifecycle rules.
V1_DEVICES_TABLE_SQL = """
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

V2_DEVICES_TABLE_SQL = """
CREATE TABLE devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL UNIQUE,
    challenge_b64 TEXT,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CHECK (
        (revoked = 0 AND revoked_at IS NULL AND revocation_reason IS NULL)
        OR (revoked = 1 AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
)
"""

# ALTER TABLE preserves the historical v1 checks and adds the new nullable
# reason column. That honest historical shape remains a supported v2 variant.
MIGRATED_V2_DEVICES_TABLE_SQL = V1_DEVICES_TABLE_SQL.replace(
    "revoked_at TEXT,",
    "revoked_at TEXT,\n    revocation_reason TEXT,",
    1,
)

ENROLLMENT_AUTHORIZATIONS_TABLE_SQL = """
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
    CHECK (
        (consumed_at IS NULL AND consumed_public_key_fingerprint IS NULL)
        OR (
            consumed_at IS NOT NULL
            AND consumed_public_key_fingerprint IS NOT NULL
        )
    ),
    CHECK (cancelled_at IS NULL OR consumed_at IS NULL)
)
"""


class DatabaseError(Exception):
    """Base exception for local state failures."""


class DatabaseNotInitializedError(DatabaseError):
    """Raised when the local database has not been initialized."""


class DatabaseSchemaError(DatabaseError):
    """Raised when the database is corrupt or has an unsupported schema."""


class DatabaseMigrationRequiredError(DatabaseSchemaError):
    """Raised when a v1 database needs the explicit v1-to-v2 migration."""


class DatabaseOperationError(DatabaseError):
    """Raised when a database operation cannot be completed safely."""


class DuplicateDeviceError(DatabaseOperationError):
    """Raised when a device identifier or public key is already registered."""


class EnrollmentDeniedError(Exception):
    """Raised for enrollment authorization failures safe to report generically."""


class EnrollmentStateError(DatabaseError):
    """Raised when consumed authorization and authenticator state disagree."""


def utc_now():
    """Return an ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def validate_identifier(value, field_name):
    """Validate identifiers at every trusted state entry point."""
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must be 1-64 characters using letters, numbers, '.', '_' or '-'."
        )
    return value


def validate_revocation_reason(reason):
    """Keep revocation reasons bounded and suitable for safe inventory output."""
    if reason not in REVOCATION_REASONS:
        allowed = ", ".join(sorted(REVOCATION_REASONS))
        raise ValueError(f"reason must be one of: {allowed}.")
    return reason


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


def _open_raw_database(database_path):
    """Open and integrity-check state without accepting a schema version."""
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
        return connection, schema_version
    except DatabaseError:
        if connection is not None:
            connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        if connection is not None:
            connection.close()
        raise DatabaseSchemaError("Local state could not be opened safely.") from exc


def _open_existing_database(database_path):
    """Open only the current schema version for normal runtime operations."""
    connection, schema_version = _open_raw_database(database_path)
    if schema_version == 1:
        connection.close()
        raise DatabaseMigrationRequiredError(
            "Local state requires the explicit v1-to-v2 migration. "
            "Run 'python manage.py migrate'."
        )
    if schema_version != SCHEMA_VERSION:
        connection.close()
        raise DatabaseSchemaError(
            f"Unsupported database schema version {schema_version}; "
            f"expected {SCHEMA_VERSION}."
        )
    try:
        _validate_v2_schema(connection)
    except DatabaseError:
        connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        connection.close()
        raise DatabaseSchemaError(
            "Local v2 state could not be validated safely."
        ) from exc
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


def _create_v2_schema(connection):
    connection.execute(
        """
        CREATE TABLE users (
            user_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(V2_DEVICES_TABLE_SQL)
    _create_enrollment_authorization_schema(connection)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _create_enrollment_authorization_schema(connection):
    """Create the one Milestone 1 table shared by initialization and migration."""
    connection.execute(ENROLLMENT_AUTHORIZATIONS_TABLE_SQL)
    connection.execute(
        """
        CREATE INDEX enrollment_authorizations_scope_index
        ON enrollment_authorizations (user_id, device_id)
        """
    )


def initialize_database(database_path=None):
    """Create v2 local state without replacing existing data."""
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
        # Exclusive creation prevents replacing a file created after the check.
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
        # SQLite DDL needs an explicit transaction for all-or-nothing setup.
        connection.execute("BEGIN IMMEDIATE")
        _create_v2_schema(connection)
        _validate_v2_schema(connection)
        connection.commit()
    except (OSError, sqlite3.DatabaseError, DatabaseError) as exc:
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


def _table_columns(connection, table_name):
    return {
        row["name"]: row
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def _has_primary_key(columns, expected_columns):
    primary_key = tuple(
        row["name"]
        for row in sorted(columns.values(), key=lambda row: row["pk"])
        if row["pk"]
    )
    return primary_key == tuple(expected_columns)


def _has_unique_columns(connection, table_name, expected_columns):
    for index in connection.execute(f"PRAGMA index_list({table_name})").fetchall():
        if not index["unique"] or index["partial"]:
            continue
        columns = tuple(
            row["name"]
            for row in connection.execute(
                "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
                (index["name"],),
            ).fetchall()
        )
        if columns == tuple(expected_columns):
            return True
    return False


def _has_foreign_key(connection, table_name, source_column, target_table, target_column):
    return any(
        row["from"] == source_column
        and row["table"] == target_table
        and row["to"] == target_column
        and row["on_delete"].upper() == "CASCADE"
        for row in connection.execute(f"PRAGMA foreign_key_list({table_name})")
    )


def _normalize_schema_sql(schema_sql):
    """Ignore only keyword case and harmless whitespace in owned schema SQL."""
    return " ".join(schema_sql.casefold().split())


def _require_supported_table_definition(
    connection, table_name, supported_definitions
):
    """Accept only canonical table definitions produced by supported versions."""
    row = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    if row is None or row["sql"] is None:
        raise DatabaseSchemaError(
            "Local state does not have the expected lifecycle table definition."
        )

    actual_definition = _normalize_schema_sql(row["sql"])
    expected_definitions = {
        _normalize_schema_sql(definition) for definition in supported_definitions
    }
    if actual_definition not in expected_definitions:
        raise DatabaseSchemaError(
            "Local state has an unsupported lifecycle table definition."
        )


def _require_schema_properties(
    connection,
    table_name,
    required_columns,
    required_not_null,
    primary_key,
    foreign_key=None,
    unique_columns=None,
):
    columns = _table_columns(connection, table_name)
    if not required_columns.issubset(columns):
        raise DatabaseSchemaError(
            "Local state does not have the expected lifecycle schema."
        )
    if any(
        not columns[name]["notnull"] and not columns[name]["pk"]
        for name in required_not_null
    ):
        raise DatabaseSchemaError("Local state is missing required column constraints.")
    if not _has_primary_key(columns, primary_key):
        raise DatabaseSchemaError("Local state is missing a required primary key.")
    if unique_columns and not _has_unique_columns(
        connection, table_name, unique_columns
    ):
        raise DatabaseSchemaError(
            "Local state is missing a required uniqueness constraint."
        )
    if foreign_key and not _has_foreign_key(connection, table_name, *foreign_key):
        raise DatabaseSchemaError("Local state is missing required ownership constraints.")


def _validate_user_and_device_schema(connection, include_revocation_reason):
    _require_schema_properties(
        connection,
        "users",
        {"user_id", "created_at"},
        {"user_id", "created_at"},
        ("user_id",),
    )
    device_columns = {
        "user_id",
        "device_id",
        "public_key_b64",
        "public_key_fingerprint",
        "challenge_b64",
        "revoked",
        "created_at",
        "revoked_at",
    }
    if include_revocation_reason:
        device_columns.add("revocation_reason")
    _require_schema_properties(
        connection,
        "devices",
        device_columns,
        {
            "user_id",
            "device_id",
            "public_key_b64",
            "public_key_fingerprint",
            "revoked",
            "created_at",
        },
        ("user_id", "device_id"),
        foreign_key=("user_id", "users", "user_id"),
        unique_columns=("public_key_fingerprint",),
    )
    if include_revocation_reason:
        supported_definitions = (
            V2_DEVICES_TABLE_SQL,
            MIGRATED_V2_DEVICES_TABLE_SQL,
        )
    else:
        supported_definitions = (V1_DEVICES_TABLE_SQL,)
    _require_supported_table_definition(
        connection, "devices", supported_definitions
    )


def _validate_v1_schema(connection):
    _validate_user_and_device_schema(connection, include_revocation_reason=False)


def _validate_v2_schema(connection):
    """Reject files whose claimed v2 version lacks required lifecycle state."""
    _validate_user_and_device_schema(connection, include_revocation_reason=True)
    _require_schema_properties(
        connection,
        "enrollment_authorizations",
        {
            "authorization_id",
            "secret_digest",
            "user_id",
            "device_id",
            "created_at",
            "expires_at",
            "cancelled_at",
            "consumed_at",
            "consumed_public_key_fingerprint",
        },
        {
            "authorization_id",
            "secret_digest",
            "user_id",
            "device_id",
            "created_at",
            "expires_at",
        },
        ("authorization_id",),
        foreign_key=("user_id", "users", "user_id"),
    )
    _require_supported_table_definition(
        connection,
        "enrollment_authorizations",
        (ENROLLMENT_AUTHORIZATIONS_TABLE_SQL,),
    )


def _apply_v2_schema_changes(connection):
    """Apply the small, explicit v1-to-v2 schema delta inside a transaction."""
    connection.execute("ALTER TABLE devices ADD COLUMN revocation_reason TEXT")
    _create_enrollment_authorization_schema(connection)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def migrate_database(database_path=None):
    """Explicitly migrate supported v1 local state to v2, or roll back fully."""
    path = database_path or get_default_database_path()
    connection, schema_version = _open_raw_database(path)
    if schema_version != 1:
        connection.close()
        if schema_version == SCHEMA_VERSION:
            # Do not report a damaged v2 file as current merely because its
            # user_version was changed. Normal runtime validation must succeed.
            current_connection = _open_existing_database(path)
            current_connection.close()
            return False
        raise DatabaseSchemaError(
            f"Unsupported database schema version {schema_version}; expected 1."
        )

    try:
        connection.execute("BEGIN IMMEDIATE")
        _validate_v1_schema(connection)
        _apply_v2_schema_changes(connection)
        _verify_database_integrity(connection)
        _validate_v2_schema(connection)
        connection.commit()
        return True
    except DatabaseError:
        try:
            connection.rollback()
        except sqlite3.DatabaseError:
            pass
        raise
    except sqlite3.DatabaseError as exc:
        try:
            connection.rollback()
        except sqlite3.DatabaseError:
            pass
        raise DatabaseOperationError("Local state migration was rolled back.") from exc
    finally:
        connection.close()


def get_database_status(database_path=None):
    """Return a read-only summary of readiness, including migration-required state."""
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
        connection, schema_version = _open_raw_database(path)
        status["schema_version"] = schema_version
        if schema_version == 1:
            _validate_v1_schema(connection)
            status["integrity"] = "migration_required"
            status["error"] = (
                "Local state requires the explicit v1-to-v2 migration. "
                "Run 'python manage.py migrate'."
            )
            return status
        if schema_version != SCHEMA_VERSION:
            status["integrity"] = "unavailable"
            status["error"] = (
                f"Unsupported database schema version {schema_version}; "
                f"expected {SCHEMA_VERSION}."
            )
            return status

        _validate_v2_schema(connection)

        status.update(
            {
                "initialized": True,
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
    except sqlite3.DatabaseError:
        status["integrity"] = "unavailable"
        status["error"] = "Local state could not be inspected safely."
        return status
    finally:
        if connection is not None:
            connection.close()


def _rollback_quietly(connection):
    try:
        connection.rollback()
    except sqlite3.DatabaseError:
        pass


def create_identity(database_path, user_id):
    """Create a logical identity through the trusted local administration path."""
    validate_identifier(user_id, "user_id")
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "INSERT OR IGNORE INTO users (user_id, created_at) VALUES (?, ?)",
            (user_id, utc_now()),
        )
        connection.commit()
        return cursor.rowcount == 1
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Logical identity creation was rolled back.") from exc
    finally:
        connection.close()


def _insert_device(connection, user_id, device_id, public_key_b64, fingerprint, timestamp):
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
            revoked_at,
            revocation_reason
        ) VALUES (?, ?, ?, ?, NULL, 0, ?, NULL, NULL)
        """,
        (user_id, device_id, public_key_b64, fingerprint, timestamp),
    )


def register_device(database_path, user_id, device_id, public_key_b64, public_key_fingerprint):
    """Register a binding for an existing identity without implicit user creation."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if connection.execute(
            "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
        ).fetchone() is None:
            raise DatabaseOperationError("The logical identity does not exist.")
        _insert_device(
            connection,
            user_id,
            device_id,
            public_key_b64,
            public_key_fingerprint,
            utc_now(),
        )
        connection.commit()
    except DuplicateDeviceError:
        _rollback_quietly(connection)
        raise
    except DatabaseError:
        _rollback_quietly(connection)
        raise
    except sqlite3.IntegrityError as exc:
        _rollback_quietly(connection)
        message = str(exc).lower()
        if "unique constraint" in message:
            raise DuplicateDeviceError(
                "The device identifier or public key is already registered."
            ) from exc
        raise DatabaseOperationError("Device registration was rolled back.") from exc
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Device registration was rolled back.") from exc
    finally:
        connection.close()


def get_user(database_path, user_id):
    """Return a user summary if it exists."""
    connection = _open_existing_database(database_path)
    try:
        row = connection.execute(
            "SELECT user_id, created_at FROM users WHERE user_id = ?", (user_id,)
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
                revoked_at,
                revocation_reason
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
    """Return full device records for internal test and runtime use only."""
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
                revoked_at,
                revocation_reason
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


def list_authenticator_inventory(database_path, user_id=None, fingerprint=None):
    """Return lifecycle inventory without public keys, challenges, or secrets."""
    if user_id is not None:
        validate_identifier(user_id, "user_id")
    connection = _open_existing_database(database_path)
    try:
        conditions = []
        parameters = []
        if user_id is not None:
            conditions.append("users.user_id = ?")
            parameters.append(user_id)
        if fingerprint is not None:
            conditions.append("devices.public_key_fingerprint = ?")
            parameters.append(fingerprint)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = connection.execute(
            f"""
            SELECT
                users.user_id,
                users.created_at AS identity_created_at,
                devices.device_id,
                devices.public_key_fingerprint,
                devices.revoked,
                devices.created_at AS binding_created_at,
                devices.revoked_at,
                devices.revocation_reason
            FROM users
            LEFT JOIN devices ON devices.user_id = users.user_id
            {where}
            ORDER BY users.created_at, users.user_id, devices.created_at, devices.device_id
            """,
            parameters,
        ).fetchall()
        inventory = []
        identities = {}
        for row in rows:
            record = dict(row)
            identity = identities.get(record["user_id"])
            if identity is None:
                identity = {
                    "user_id": record["user_id"],
                    "created_at": record["identity_created_at"],
                    "authenticators": [],
                }
                identities[record["user_id"]] = identity
                inventory.append(identity)
            if record["device_id"] is not None:
                identity["authenticators"].append(
                    {
                        "device_id": record["device_id"],
                        "state": "revoked" if record["revoked"] else "active",
                        "public_key_fingerprint": record["public_key_fingerprint"],
                        "created_at": record["binding_created_at"],
                        "revoked_at": record["revoked_at"],
                        "revocation_reason": record["revocation_reason"],
                    }
                )
        return inventory
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("Authenticator inventory could not be read.") from exc
    finally:
        connection.close()


def _authorization_secret_digest(secret):
    if not isinstance(secret, str) or not secret or len(secret) > 512:
        raise EnrollmentDeniedError()
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _parse_timestamp(timestamp, field_name):
    try:
        parsed = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError) as exc:
        raise EnrollmentStateError(
            f"Local authorization {field_name} timestamp is invalid."
        ) from exc
    if parsed.tzinfo is None:
        raise EnrollmentStateError(
            f"Local authorization {field_name} timestamp is invalid."
        )
    return parsed


def _authorization_is_open(authorization, timestamp):
    if authorization["consumed_at"] is not None or authorization["cancelled_at"] is not None:
        return False
    return _parse_timestamp(authorization["expires_at"], "expiry") > _parse_timestamp(
        timestamp, "current"
    )


def issue_enrollment_authorization(
    database_path, user_id, device_id, lifetime_seconds=DEFAULT_ENROLLMENT_LIFETIME_SECONDS
):
    """Create one scoped, short-lived authorization and cancel earlier open scope."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    if not isinstance(lifetime_seconds, int) or lifetime_seconds <= 0:
        raise ValueError("lifetime_seconds must be a positive integer.")

    authorization_id = secrets.token_urlsafe(16)
    authorization_secret = secrets.token_urlsafe(32)
    secret_digest = _authorization_secret_digest(authorization_secret)
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        expires_at = (
            _parse_timestamp(timestamp, "current") + timedelta(seconds=lifetime_seconds)
        ).isoformat()
        if connection.execute(
            "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
        ).fetchone() is None:
            raise DatabaseOperationError("The logical identity does not exist.")
        existing_binding = connection.execute(
            "SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        ).fetchone()
        if existing_binding is not None:
            raise DuplicateDeviceError("The authenticator binding already exists.")

        earlier = connection.execute(
            """
            SELECT
                authorization_id,
                expires_at,
                cancelled_at,
                consumed_at,
                consumed_public_key_fingerprint
            FROM enrollment_authorizations
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        ).fetchall()
        for authorization in earlier:
            if (authorization["consumed_at"] is None) != (
                authorization["consumed_public_key_fingerprint"] is None
            ):
                raise EnrollmentStateError(
                    "Consumed enrollment authorization state is inconsistent."
                )
            if authorization["consumed_at"] is not None:
                raise EnrollmentStateError(
                    "Consumed enrollment authorization has no corresponding binding."
                )
            if _authorization_is_open(authorization, timestamp):
                connection.execute(
                    """
                    UPDATE enrollment_authorizations
                    SET cancelled_at = ?
                    WHERE authorization_id = ?
                    """,
                    (timestamp, authorization["authorization_id"]),
                )

        connection.execute(
            """
            INSERT INTO enrollment_authorizations (
                authorization_id,
                secret_digest,
                user_id,
                device_id,
                created_at,
                expires_at,
                cancelled_at,
                consumed_at,
                consumed_public_key_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                authorization_id,
                secret_digest,
                user_id,
                device_id,
                timestamp,
                expires_at,
            ),
        )
        connection.commit()
        return {
            "authorization_id": authorization_id,
            "authorization_secret": authorization_secret,
            "user_id": user_id,
            "device_id": device_id,
            "expires_at": expires_at,
        }
    except (DatabaseError, EnrollmentDeniedError):
        _rollback_quietly(connection)
        raise
    except sqlite3.IntegrityError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Enrollment authorization issuance was rolled back.") from exc
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Enrollment authorization issuance was rolled back.") from exc
    finally:
        connection.close()


def cancel_enrollment_authorization(database_path, authorization_id):
    """Cancel an open authorization without rewriting historical state."""
    if not isinstance(authorization_id, str) or not AUTHORIZATION_ID_PATTERN.fullmatch(
        authorization_id
    ):
        raise ValueError("authorization_id is invalid.")
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        authorization = connection.execute(
            """
            SELECT authorization_id, expires_at, cancelled_at, consumed_at
            FROM enrollment_authorizations
            WHERE authorization_id = ?
            """,
            (authorization_id,),
        ).fetchone()
        if authorization is None:
            connection.commit()
            return "not_found"
        if authorization["consumed_at"] is not None:
            connection.commit()
            return "consumed"
        if authorization["cancelled_at"] is not None:
            connection.commit()
            return "already_cancelled"
        if not _authorization_is_open(authorization, timestamp):
            connection.commit()
            return "expired"
        connection.execute(
            "UPDATE enrollment_authorizations SET cancelled_at = ? WHERE authorization_id = ?",
            (timestamp, authorization_id),
        )
        connection.commit()
        return "cancelled"
    except DatabaseError:
        _rollback_quietly(connection)
        raise
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Enrollment authorization cancellation was rolled back.") from exc
    finally:
        connection.close()


def bind_authenticator(
    database_path,
    user_id,
    device_id,
    public_key_b64,
    public_key_fingerprint,
    authorization_id,
    authorization_secret,
):
    """Atomically bind an authenticator or reconcile an exact previous binding."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    if not isinstance(authorization_id, str) or not AUTHORIZATION_ID_PATTERN.fullmatch(
        authorization_id
    ):
        raise EnrollmentDeniedError()
    secret_digest = _authorization_secret_digest(authorization_secret)
    connection = _open_existing_database(database_path)
    try:
        # BEGIN IMMEDIATE makes scope replacement, cancellation, and binding
        # outcomes serializable without a process-global lock.
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        authorization = connection.execute(
            """
            SELECT
                authorization_id,
                secret_digest,
                user_id,
                device_id,
                expires_at,
                cancelled_at,
                consumed_at,
                consumed_public_key_fingerprint
            FROM enrollment_authorizations
            WHERE authorization_id = ?
            """,
            (authorization_id,),
        ).fetchone()
        if authorization is None or not hmac.compare_digest(
            authorization["secret_digest"], secret_digest
        ):
            raise EnrollmentDeniedError()
        if authorization["user_id"] != user_id or authorization["device_id"] != device_id:
            raise EnrollmentDeniedError()

        consumed_at = authorization["consumed_at"]
        consumed_fingerprint = authorization["consumed_public_key_fingerprint"]
        if (consumed_at is None) != (consumed_fingerprint is None):
            raise EnrollmentStateError(
                "Consumed enrollment authorization state is inconsistent."
            )
        if consumed_at is not None:
            if authorization["cancelled_at"] is not None:
                raise EnrollmentStateError(
                    "Consumed enrollment authorization state is inconsistent."
                )
            if consumed_fingerprint != public_key_fingerprint:
                raise EnrollmentDeniedError()
            device = connection.execute(
                """
                SELECT public_key_fingerprint, revoked
                FROM devices
                WHERE user_id = ? AND device_id = ?
                """,
                (user_id, device_id),
            ).fetchone()
            if device is None or device["public_key_fingerprint"] != public_key_fingerprint:
                raise EnrollmentStateError(
                    "Consumed enrollment authorization does not match its binding."
                )
            connection.commit()
            return {
                "outcome": "reconciled",
                "binding_state": "revoked" if device["revoked"] else "active",
                "public_key_fingerprint": public_key_fingerprint,
            }

        if not _authorization_is_open(authorization, timestamp):
            raise EnrollmentDeniedError()
        if connection.execute(
            "SELECT 1 FROM users WHERE user_id = ?", (user_id,)
        ).fetchone() is None:
            raise EnrollmentStateError("Enrollment authorization owner is missing.")
        if connection.execute(
            "SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?",
            (user_id, device_id),
        ).fetchone() is not None:
            raise EnrollmentDeniedError()
        if connection.execute(
            "SELECT 1 FROM devices WHERE public_key_fingerprint = ?",
            (public_key_fingerprint,),
        ).fetchone() is not None:
            raise EnrollmentDeniedError()

        _insert_device(
            connection,
            user_id,
            device_id,
            public_key_b64,
            public_key_fingerprint,
            timestamp,
        )
        consumed = connection.execute(
            """
            UPDATE enrollment_authorizations
            SET consumed_at = ?, consumed_public_key_fingerprint = ?
            WHERE authorization_id = ?
              AND consumed_at IS NULL
              AND cancelled_at IS NULL
            """,
            (timestamp, public_key_fingerprint, authorization_id),
        )
        if consumed.rowcount != 1:
            raise EnrollmentStateError(
                "Enrollment authorization changed during trusted binding."
            )
        connection.commit()
        return {
            "outcome": "created",
            "binding_state": "active",
            "public_key_fingerprint": public_key_fingerprint,
        }
    except (EnrollmentDeniedError, EnrollmentStateError):
        _rollback_quietly(connection)
        raise
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Authenticator binding was rolled back.") from exc
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


def revoke_authenticator(database_path, user_id, device_id, reason):
    """Terminally revoke a binding and clear its outstanding challenge."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    validate_revocation_reason(reason)
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        device = connection.execute(
            """
            SELECT revoked, revoked_at, revocation_reason
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        ).fetchone()
        if device is None:
            connection.commit()
            return "not_found"
        if device["revoked"]:
            connection.commit()
            return "already_revoked"
        connection.execute(
            """
            UPDATE devices
            SET revoked = 1,
                challenge_b64 = NULL,
                revoked_at = ?,
                revocation_reason = ?
            WHERE user_id = ? AND device_id = ? AND revoked = 0
            """,
            (utc_now(), reason, user_id, device_id),
        )
        connection.commit()
        return "revoked"
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Authenticator revocation was rolled back.") from exc
    finally:
        connection.close()
