import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_VERSION = 4
DATABASE_ENV_VAR = "PKAS_DATABASE_PATH"
DATABASE_NAME = "identity_lab.sqlite3"
APP_DIRECTORY_NAME = "PublicKeyAuthenticationSystem"
DEFAULT_ENROLLMENT_LIFETIME_SECONDS = 10 * 60
DEFAULT_CHALLENGE_LIFETIME_SECONDS = 5 * 60
MAX_OUTSTANDING_CHALLENGES_PER_BINDING = 8
MAX_SECURITY_EVENT_QUERY_LIMIT = 1000
MAX_ENROLLMENT_AUTHORIZATION_QUERY_LIMIT = 1000
DEFAULT_SECURITY_ANALYSIS_LIMIT = 100
INVALID_SIGNATURE_FINDING_THRESHOLD = 3
INVALID_SIGNATURE_FINDING_WINDOW_SECONDS = 10 * 60
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
AUTHORIZATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
CHALLENGE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
EVENT_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
REASON_CODE_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
FINGERPRINT_PATTERN = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
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

AUTHENTICATION_CHALLENGES_TABLE_SQL = """
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
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
)
"""

SECURITY_EVENTS_TABLE_SQL = """
CREATE TABLE security_events (
    event_id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_assurance TEXT NOT NULL,
    user_id TEXT,
    device_id TEXT,
    related_device_id TEXT,
    public_key_fingerprint TEXT,
    interaction_id TEXT
)
"""

ENROLLMENT_AUTHORIZATIONS_SCOPE_INDEX_SQL = """
CREATE INDEX enrollment_authorizations_scope_index
ON enrollment_authorizations (user_id, device_id)
"""

AUTHENTICATION_CHALLENGES_BINDING_INDEX_SQL = """
CREATE INDEX authentication_challenges_binding_index
ON authentication_challenges (user_id, device_id)
"""

SECURITY_EVENTS_SCOPE_INDEX_SQL = """
CREATE INDEX security_events_scope_index
ON security_events (user_id, device_id, event_id)
"""


class DatabaseError(Exception):
    """Base exception for local state failures."""


class DatabaseNotInitializedError(DatabaseError):
    """Raised when the local database has not been initialized."""


class DatabaseSchemaError(DatabaseError):
    """Raised when the database is corrupt or has an unsupported schema."""


class DatabaseMigrationRequiredError(DatabaseSchemaError):
    """Raised when local state needs the explicit migration command."""


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


def validate_challenge_id(value):
    """Accept only the fixed 256-bit base64url challenge identifier form."""
    if not isinstance(value, str) or not CHALLENGE_ID_PATTERN.fullmatch(value):
        raise ValueError("challenge_id is invalid.")
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
    if schema_version in (1, 2, 3):
        connection.close()
        raise DatabaseMigrationRequiredError(
            "Local state requires the explicit migration to schema v4. "
            "Run 'python manage.py migrate'."
        )
    if schema_version != SCHEMA_VERSION:
        connection.close()
        raise DatabaseSchemaError(
            f"Unsupported database schema version {schema_version}; "
            f"expected {SCHEMA_VERSION}."
        )
    try:
        _validate_v4_schema(connection)
    except DatabaseError:
        connection.close()
        raise
    except sqlite3.DatabaseError as exc:
        connection.close()
        raise DatabaseSchemaError(
            "Local v4 state could not be validated safely."
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


def _create_v4_schema(connection):
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
    _create_authentication_challenge_schema(connection)
    _create_security_event_schema(connection)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _create_enrollment_authorization_schema(connection):
    """Create the enrollment-authorization table shared by initialization and migration."""
    connection.execute(ENROLLMENT_AUTHORIZATIONS_TABLE_SQL)
    connection.execute(ENROLLMENT_AUTHORIZATIONS_SCOPE_INDEX_SQL)


def _create_authentication_challenge_schema(connection):
    """Create the explicit v3 authentication challenge state."""
    connection.execute(AUTHENTICATION_CHALLENGES_TABLE_SQL)
    connection.execute(AUTHENTICATION_CHALLENGES_BINDING_INDEX_SQL)


def _create_security_event_schema(connection):
    """Create the small application-native security evidence table."""
    connection.execute(SECURITY_EVENTS_TABLE_SQL)
    connection.execute(SECURITY_EVENTS_SCOPE_INDEX_SQL)


def initialize_database(database_path=None):
    """Create v4 local state without replacing existing data."""
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
        _create_v4_schema(connection)
        _validate_v4_schema(connection)
        _insert_security_event(
            connection,
            utc_now(),
            "state.initialized",
            "success",
            "schema_v4",
            "local_administrator",
            "trusted_local_account",
        )
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


def _require_supported_index_definition(connection, index_name, expected_definition):
    """Require the application-owned index used by a supported schema version."""
    row = connection.execute(
        "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?",
        (index_name,),
    ).fetchone()
    if row is None or row["sql"] is None:
        raise DatabaseSchemaError("Local state is missing a required application index.")
    if _normalize_schema_sql(row["sql"]) != _normalize_schema_sql(expected_definition):
        raise DatabaseSchemaError("Local state has an unsupported index definition.")


def _reject_unsupported_schema_extensions(connection):
    """Reject persisted triggers or views that can change application semantics."""
    row = connection.execute(
        """
        SELECT type, name
        FROM sqlite_schema
        WHERE type IN ('trigger', 'view')
        LIMIT 1
        """
    ).fetchone()
    if row is not None:
        raise DatabaseSchemaError(
            "Local state contains unsupported triggers or views."
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
    _reject_unsupported_schema_extensions(connection)


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
    _require_supported_index_definition(
        connection,
        "enrollment_authorizations_scope_index",
        ENROLLMENT_AUTHORIZATIONS_SCOPE_INDEX_SQL,
    )
    _reject_unsupported_schema_extensions(connection)


def _validate_v3_schema(connection):
    """Reject current state missing the v3 authentication challenge controls."""
    _validate_v2_schema(connection)
    _require_schema_properties(
        connection,
        "authentication_challenges",
        {
            "challenge_id",
            "user_id",
            "device_id",
            "public_key_fingerprint",
            "nonce_b64",
            "created_at",
            "expires_at",
            "consumed_at",
        },
        {
            "challenge_id",
            "user_id",
            "device_id",
            "public_key_fingerprint",
            "nonce_b64",
            "created_at",
            "expires_at",
        },
        ("challenge_id",),
        foreign_key=("user_id", "devices", "user_id"),
    )
    _require_supported_table_definition(
        connection,
        "authentication_challenges",
        (AUTHENTICATION_CHALLENGES_TABLE_SQL,),
    )
    _require_supported_index_definition(
        connection,
        "authentication_challenges_binding_index",
        AUTHENTICATION_CHALLENGES_BINDING_INDEX_SQL,
    )
    _reject_unsupported_schema_extensions(connection)


def _validate_v4_schema(connection):
    """Reject current state missing the application-owned evidence table."""
    _validate_v3_schema(connection)
    _require_schema_properties(
        connection,
        "security_events",
        {
            "event_id",
            "occurred_at",
            "event_type",
            "outcome",
            "reason_code",
            "actor_kind",
            "actor_assurance",
            "user_id",
            "device_id",
            "related_device_id",
            "public_key_fingerprint",
            "interaction_id",
        },
        {
            "event_id",
            "occurred_at",
            "event_type",
            "outcome",
            "reason_code",
            "actor_kind",
            "actor_assurance",
        },
        ("event_id",),
    )
    _require_supported_table_definition(
        connection,
        "security_events",
        (SECURITY_EVENTS_TABLE_SQL,),
    )
    _require_supported_index_definition(
        connection,
        "security_events_scope_index",
        SECURITY_EVENTS_SCOPE_INDEX_SQL,
    )
    _reject_unsupported_schema_extensions(connection)


def _apply_v2_schema_changes(connection):
    """Apply the small, explicit v1-to-v2 schema delta inside a transaction."""
    connection.execute("ALTER TABLE devices ADD COLUMN revocation_reason TEXT")
    _create_enrollment_authorization_schema(connection)
    connection.execute("PRAGMA user_version = 2")


def _apply_v3_schema_changes(connection):
    """Retire legacy single-challenge state and add explicit v3 challenges."""
    # Stored v2 challenges were signed by the retired raw PKCS#1 v1.5 protocol.
    # They cannot become valid v3 authentication state after migration.
    connection.execute("UPDATE devices SET challenge_b64 = NULL")
    _create_authentication_challenge_schema(connection)
    connection.execute("PRAGMA user_version = 3")


def _apply_v4_schema_changes(connection):
    """Add application-native security evidence without rewriting history."""
    _create_security_event_schema(connection)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def migrate_database(database_path=None):
    """Explicitly migrate supported v1, v2, or v3 state to v4 atomically."""
    path = database_path or get_default_database_path()
    connection, schema_version = _open_raw_database(path)
    source_version = schema_version
    try:
        connection.execute("BEGIN IMMEDIATE")
        if schema_version == 1:
            _validate_v1_schema(connection)
            _apply_v2_schema_changes(connection)
            _verify_database_integrity(connection)
            _validate_v2_schema(connection)
        elif schema_version == 2:
            _validate_v2_schema(connection)
        elif schema_version == 3:
            _validate_v3_schema(connection)
        elif schema_version == SCHEMA_VERSION:
            _validate_v4_schema(connection)
            connection.commit()
            return False
        else:
            raise DatabaseSchemaError(
                f"Unsupported database schema version {schema_version}; expected 1, 2, 3, or {SCHEMA_VERSION}."
            )
        if schema_version in (1, 2):
            _apply_v3_schema_changes(connection)
            _verify_database_integrity(connection)
            _validate_v3_schema(connection)
        _apply_v4_schema_changes(connection)
        _verify_database_integrity(connection)
        _validate_v4_schema(connection)
        _insert_security_event(
            connection,
            utc_now(),
            "state.migrated",
            "success",
            f"schema_v{source_version}_to_v4",
            "local_administrator",
            "trusted_local_account",
        )
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
        "security_events": 0,
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
        if schema_version in (1, 2, 3):
            if schema_version == 1:
                _validate_v1_schema(connection)
            elif schema_version == 2:
                _validate_v2_schema(connection)
            else:
                _validate_v3_schema(connection)
            status["integrity"] = "migration_required"
            status["error"] = (
                "Local state requires the explicit migration to schema v4. "
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

        _validate_v4_schema(connection)

        status.update(
            {
                "initialized": True,
                "integrity": "ok",
                "users": connection.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "devices": connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                "security_events": connection.execute(
                    "SELECT COUNT(*) FROM security_events"
                ).fetchone()[0],
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


def _insert_security_event(
    connection,
    occurred_at,
    event_type,
    outcome,
    reason_code,
    actor_kind,
    actor_assurance,
    user_id=None,
    device_id=None,
    related_device_id=None,
    public_key_fingerprint=None,
    interaction_id=None,
):
    """Insert sanitized evidence using the caller's existing transaction."""
    values = (
        occurred_at,
        event_type,
        outcome,
        reason_code,
        actor_kind,
        actor_assurance,
        user_id,
        device_id,
        related_device_id,
        public_key_fingerprint,
        interaction_id,
    )
    cursor = connection.execute(
        """
        INSERT INTO security_events (
            occurred_at,
            event_type,
            outcome,
            reason_code,
            actor_kind,
            actor_assurance,
            user_id,
            device_id,
            related_device_id,
            public_key_fingerprint,
            interaction_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        values,
    )
    if cursor.rowcount != 1 or cursor.lastrowid is None:
        raise sqlite3.IntegrityError("Security evidence was not inserted.")
    stored_event = connection.execute(
        """
        SELECT
            occurred_at,
            event_type,
            outcome,
            reason_code,
            actor_kind,
            actor_assurance,
            user_id,
            device_id,
            related_device_id,
            public_key_fingerprint,
            interaction_id
        FROM security_events
        WHERE event_id = ?
        """,
        (cursor.lastrowid,),
    ).fetchone()
    if stored_event is None or tuple(stored_event) != values:
        raise sqlite3.IntegrityError("Security evidence did not persist as expected.")


def record_security_observation(
    database_path,
    event_type,
    reason_code,
    challenge_id=None,
):
    """Persist a denial, deriving optional context only from trusted challenge state."""
    if event_type not in {
        "authentication.denied",
        "authentication.protocol_rejected",
        "enrollment.denied",
    }:
        raise ValueError("event_type is not an observational security event.")
    if not isinstance(reason_code, str) or not REASON_CODE_PATTERN.fullmatch(reason_code):
        raise ValueError("reason_code is invalid.")
    if challenge_id is not None:
        validate_challenge_id(challenge_id)

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        challenge = None
        if challenge_id is not None:
            challenge = connection.execute(
                """
                SELECT challenge_id, user_id, device_id, public_key_fingerprint
                FROM authentication_challenges
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            ).fetchone()
        _insert_security_event(
            connection,
            utc_now(),
            event_type,
            "denied",
            reason_code,
            "client",
            "unverified_claim",
            user_id=challenge["user_id"] if challenge else None,
            device_id=challenge["device_id"] if challenge else None,
            public_key_fingerprint=(
                challenge["public_key_fingerprint"] if challenge else None
            ),
            interaction_id=challenge["challenge_id"] if challenge else None,
        )
        connection.commit()
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Security evidence could not be recorded.") from exc
    finally:
        connection.close()


def list_security_events(
    database_path,
    user_id=None,
    device_id=None,
    event_type=None,
    limit=100,
):
    """Return a bounded chronological security-event view for local inspection."""
    if user_id is not None:
        validate_identifier(user_id, "user_id")
    if device_id is not None:
        validate_identifier(device_id, "device_id")
    if event_type is not None and (
        not isinstance(event_type, str) or not EVENT_TYPE_PATTERN.fullmatch(event_type)
    ):
        raise ValueError("event_type is invalid.")
    if not isinstance(limit, int) or not 1 <= limit <= MAX_SECURITY_EVENT_QUERY_LIMIT:
        raise ValueError(
            f"limit must be between 1 and {MAX_SECURITY_EVENT_QUERY_LIMIT}."
        )

    connection = _open_existing_database(database_path)
    try:
        conditions = []
        parameters = []
        if user_id is not None:
            conditions.append("user_id = ?")
            parameters.append(user_id)
        if device_id is not None:
            conditions.append("(device_id = ? OR related_device_id = ?)")
            parameters.extend((device_id, device_id))
        if event_type is not None:
            conditions.append("event_type = ?")
            parameters.append(event_type)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        parameters.append(limit)
        rows = connection.execute(
            f"""
            SELECT
                event_id,
                occurred_at,
                event_type,
                outcome,
                reason_code,
                actor_kind,
                actor_assurance,
                user_id,
                device_id,
                related_device_id,
                public_key_fingerprint,
                interaction_id
            FROM security_events
            {where}
            ORDER BY event_id DESC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [dict(row) for row in reversed(rows)]
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("Security events could not be read.") from exc
    finally:
        connection.close()


def _validate_analysis_event(event):
    """Validate selected evidence before using it for security interpretation."""
    if not isinstance(event["event_id"], int) or event["event_id"] <= 0:
        raise DatabaseOperationError("Security evidence could not be analyzed safely.")
    if not isinstance(event["occurred_at"], str) or len(event["occurred_at"]) > 64:
        raise DatabaseOperationError("Security evidence could not be analyzed safely.")
    try:
        occurred_at = _parse_timestamp(event["occurred_at"], "event")
    except EnrollmentStateError as exc:
        raise DatabaseOperationError(
            "Security evidence could not be analyzed safely."
        ) from exc

    token_fields = {
        "event_type": EVENT_TYPE_PATTERN,
        "outcome": REASON_CODE_PATTERN,
        "reason_code": REASON_CODE_PATTERN,
        "actor_kind": REASON_CODE_PATTERN,
        "actor_assurance": REASON_CODE_PATTERN,
    }
    for field_name, pattern in token_fields.items():
        value = event[field_name]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise DatabaseOperationError(
                "Security evidence could not be analyzed safely."
            )

    for field_name in ("user_id", "device_id", "related_device_id"):
        value = event[field_name]
        if value is not None:
            try:
                validate_identifier(value, field_name)
            except ValueError as exc:
                raise DatabaseOperationError(
                    "Security evidence could not be analyzed safely."
                ) from exc

    fingerprint = event["public_key_fingerprint"]
    if fingerprint is not None and (
        not isinstance(fingerprint, str)
        or not FINGERPRINT_PATTERN.fullmatch(fingerprint)
    ):
        raise DatabaseOperationError("Security evidence could not be analyzed safely.")

    interaction_id = event["interaction_id"]
    if interaction_id is not None:
        try:
            validate_challenge_id(interaction_id)
        except ValueError as exc:
            raise DatabaseOperationError(
                "Security evidence could not be analyzed safely."
            ) from exc

    if event["event_type"] == "authenticator.replacement_prepared":
        if (
            event["related_device_id"] is None
            or event["related_device_id"] == event["device_id"]
        ):
            raise DatabaseOperationError(
                "Security evidence could not be analyzed safely."
            )
    elif event["related_device_id"] is not None:
        raise DatabaseOperationError("Security evidence could not be analyzed safely.")

    required_context = (
        event["user_id"],
        event["device_id"],
        event["public_key_fingerprint"],
    )
    event_key = (event["event_type"], event["reason_code"])
    exact_semantics = {
        ("authentication.denied", "invalid_signature"): (
            "denied",
            "client",
            "unverified_claim",
            True,
        ),
        ("authentication.denied", "challenge_replayed"): (
            "denied",
            "client",
            "unverified_claim",
            True,
        ),
        ("authentication.succeeded", "proof_verified"): (
            "success",
            "authenticator",
            "cryptographically_verified",
            True,
        ),
        ("authentication.denied", "binding_revoked"): (
            "denied",
            "client",
            "unverified_claim",
            False,
        ),
    }
    expected = exact_semantics.get(event_key)
    if event["event_type"] in {
        "authenticator.revoked",
        "authenticator.replacement_prepared",
    }:
        expected = (
            "success",
            "local_administrator",
            "trusted_local_account",
            False,
        )
    if expected is not None:
        outcome, actor_kind, actor_assurance, needs_interaction = expected
        inconsistent = (
            event["outcome"] != outcome
            or event["actor_kind"] != actor_kind
            or event["actor_assurance"] != actor_assurance
            or any(value is None for value in required_context)
            or (needs_interaction and interaction_id is None)
            or (not needs_interaction and interaction_id is not None)
        )
        if event["event_type"].startswith("authenticator."):
            inconsistent = inconsistent or event["reason_code"] not in REVOCATION_REASONS
        if inconsistent:
            raise DatabaseOperationError(
                "Security evidence could not be analyzed safely."
            )
    return occurred_at


def _binding_context(event):
    return (
        event["user_id"],
        event["device_id"],
        event["public_key_fingerprint"],
    )


def _invalid_signature_findings(analyzed_events):
    grouped = {}
    for event, occurred_at in analyzed_events:
        if (
            event["event_type"] == "authentication.denied"
            and event["reason_code"] == "invalid_signature"
        ):
            grouped.setdefault(_binding_context(event), []).append(
                (event, occurred_at)
            )

    findings = []
    window = timedelta(seconds=INVALID_SIGNATURE_FINDING_WINDOW_SECONDS)
    for context, attempts in grouped.items():
        attempts.sort(key=lambda item: (item[1], item[0]["event_id"]))
        latest_evidence = None
        for right_index, (_, right_time) in enumerate(attempts):
            candidates = {}
            for event, occurred_at in attempts[: right_index + 1]:
                if right_time - occurred_at <= window:
                    candidates[event["interaction_id"]] = (event, occurred_at)
            if len(candidates) >= INVALID_SIGNATURE_FINDING_THRESHOLD:
                selected = sorted(
                    candidates.values(),
                    key=lambda item: (item[1], item[0]["event_id"]),
                )[-INVALID_SIGNATURE_FINDING_THRESHOLD:]
                latest_evidence = sorted(event["event_id"] for event, _ in selected)
        if latest_evidence is None:
            continue
        user_id, device_id, fingerprint = context
        findings.append(
            {
                "finding_type": "repeated_invalid_authentication_proofs",
                "user_id": user_id,
                "device_id": device_id,
                "public_key_fingerprint": fingerprint,
                "evidence_event_ids": latest_evidence,
                "fact": (
                    "Three distinct authentication challenge interactions for this "
                    "binding produced invalid-signature denials within "
                    f"{INVALID_SIGNATURE_FINDING_WINDOW_SECONDS} seconds."
                ),
                "interpretation": (
                    "This can indicate a stale or mismatched credential, or repeated "
                    "attempts without the matching private key."
                ),
                "limitation": (
                    "The requests were not cryptographically attributed to a person, "
                    "physical device, or attacker."
                ),
            }
        )
    return findings


def _replay_findings(analyzed_events):
    successful_interactions = {}
    replay_events = {}
    for event, _ in analyzed_events:
        interaction_id = event["interaction_id"]
        context = _binding_context(event)
        key = (interaction_id, context)
        if (
            event["event_type"] == "authentication.succeeded"
            and event["reason_code"] == "proof_verified"
        ):
            successful_interactions.setdefault(key, event)
        elif (
            event["event_type"] == "authentication.denied"
            and event["reason_code"] == "challenge_replayed"
            and key in successful_interactions
            and successful_interactions[key]["event_id"] < event["event_id"]
        ):
            replay_events.setdefault(key, []).append(event)

    findings = []
    for key, replays in replay_events.items():
        success = successful_interactions[key]
        user_id, device_id, fingerprint = key[1]
        findings.append(
            {
                "finding_type": "challenge_replay_after_success",
                "user_id": user_id,
                "device_id": device_id,
                "public_key_fingerprint": fingerprint,
                "evidence_event_ids": [success["event_id"]]
                + [event["event_id"] for event in replays],
                "fact": (
                    "A successfully consumed one-time challenge was submitted again "
                    "and rejected."
                ),
                "interpretation": (
                    "The evidence shows challenge reuse after authentication success."
                ),
                "limitation": (
                    "This does not prove malicious replay; a retry after response "
                    "uncertainty is also plausible."
                ),
            }
        )
    return findings


def _post_revocation_findings(analyzed_events):
    revocations = {}
    denied_requests = {}
    for event, _ in analyzed_events:
        context = _binding_context(event)
        if event["event_type"] in {
            "authenticator.revoked",
            "authenticator.replacement_prepared",
        }:
            revocations.setdefault(context, event)
        elif (
            event["event_type"] == "authentication.denied"
            and event["reason_code"] == "binding_revoked"
            and context in revocations
            and revocations[context]["event_id"] < event["event_id"]
        ):
            denied_requests.setdefault(context, []).append(event)

    findings = []
    for context, requests in denied_requests.items():
        revocation = revocations[context]
        user_id, device_id, fingerprint = context
        findings.append(
            {
                "finding_type": "post_revocation_targeting",
                "user_id": user_id,
                "device_id": device_id,
                "public_key_fingerprint": fingerprint,
                "evidence_event_ids": [revocation["event_id"]]
                + [event["event_id"] for event in requests],
                "fact": (
                    "Authentication activity targeted this binding after its terminal "
                    "revocation and was rejected."
                ),
                "interpretation": (
                    "This can indicate stale client configuration or continued attempts "
                    "that name the revoked binding."
                ),
                "limitation": (
                    "The requester was not cryptographically verified, so this does not "
                    "prove the revoked authenticator or private key sent the request."
                ),
            }
        )
    return findings


def analyze_security_events(
    database_path,
    user_id,
    device_id=None,
    limit=DEFAULT_SECURITY_ANALYSIS_LIMIT,
):
    """Derive bounded identity findings from one consistent committed event snapshot."""
    validate_identifier(user_id, "user_id")
    if device_id is not None:
        validate_identifier(device_id, "device_id")
    if not isinstance(limit, int) or not 1 <= limit <= MAX_SECURITY_EVENT_QUERY_LIMIT:
        raise ValueError(
            f"limit must be between 1 and {MAX_SECURITY_EVENT_QUERY_LIMIT}."
        )

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN")
        conditions = ["user_id = ?"]
        parameters = [user_id]
        if device_id is not None:
            conditions.append("(device_id = ? OR related_device_id = ?)")
            parameters.extend((device_id, device_id))
        parameters.append(limit + 1)
        rows = connection.execute(
            f"""
            SELECT
                event_id,
                occurred_at,
                event_type,
                outcome,
                reason_code,
                actor_kind,
                actor_assurance,
                user_id,
                device_id,
                related_device_id,
                public_key_fingerprint,
                interaction_id
            FROM security_events
            WHERE {' AND '.join(conditions)}
            ORDER BY event_id DESC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        truncated = len(rows) > limit
        timeline = [dict(row) for row in reversed(rows[:limit])]
        analyzed_events = [
            (event, _validate_analysis_event(event)) for event in timeline
        ]
        findings = (
            _invalid_signature_findings(analyzed_events)
            + _replay_findings(analyzed_events)
            + _post_revocation_findings(analyzed_events)
        )
        findings.sort(key=lambda finding: max(finding["evidence_event_ids"]))
        connection.commit()
        return {
            "scope": {"user_id": user_id, "device_id": device_id},
            "policy": {
                "invalid_signature_distinct_interactions": (
                    INVALID_SIGNATURE_FINDING_THRESHOLD
                ),
                "invalid_signature_window_seconds": (
                    INVALID_SIGNATURE_FINDING_WINDOW_SECONDS
                ),
            },
            "complete": not truncated,
            "completeness_note": (
                "All stored events matching this scope were analyzed."
                if not truncated
                else (
                    "Only the newest bounded selection was analyzed; earlier activity "
                    "may affect the result."
                )
            ),
            "events_examined": len(timeline),
            "timeline": timeline,
            "findings": findings,
        }
    except DatabaseError:
        _rollback_quietly(connection)
        raise
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError(
            "Security evidence could not be analyzed safely."
        ) from exc
    finally:
        connection.close()


def create_identity(database_path, user_id):
    """Create a logical identity through the trusted local administration path."""
    validate_identifier(user_id, "user_id")
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        cursor = connection.execute(
            "INSERT OR IGNORE INTO users (user_id, created_at) VALUES (?, ?)",
            (user_id, timestamp),
        )
        if cursor.rowcount == 1:
            _insert_security_event(
                connection,
                timestamp,
                "identity.created",
                "success",
                "created",
                "local_administrator",
                "trusted_local_account",
                user_id=user_id,
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


def list_enrollment_authorizations(
    database_path, user_id, device_id=None, limit=100
):
    """Return a bounded, sanitized authorization view for trusted local administration."""
    validate_identifier(user_id, "user_id")
    if device_id is not None:
        validate_identifier(device_id, "device_id")
    if (
        not isinstance(limit, int)
        or not 1 <= limit <= MAX_ENROLLMENT_AUTHORIZATION_QUERY_LIMIT
    ):
        raise ValueError(
            "limit must be between 1 and "
            f"{MAX_ENROLLMENT_AUTHORIZATION_QUERY_LIMIT}."
        )

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN")
        timestamp = utc_now()
        conditions = ["user_id = ?"]
        parameters = [user_id]
        if device_id is not None:
            conditions.append("device_id = ?")
            parameters.append(device_id)
        parameters.append(limit)
        rows = connection.execute(
            f"""
            SELECT
                authorization_id,
                user_id,
                device_id,
                created_at,
                expires_at,
                cancelled_at,
                consumed_at
            FROM enrollment_authorizations
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at DESC, authorization_id DESC
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        current_time = _parse_timestamp(timestamp, "current")
        authorizations = []
        for row in reversed(rows):
            record = dict(row)
            # A recorded terminal outcome remains authoritative after wall-clock expiry.
            if record["consumed_at"] is not None:
                state = "consumed"
            elif record["cancelled_at"] is not None:
                state = "cancelled"
            elif _parse_timestamp(record["expires_at"], "expiry") <= current_time:
                state = "expired"
            else:
                state = "open"
            authorizations.append(
                {
                    "authorization_id": record["authorization_id"],
                    "user_id": record["user_id"],
                    "device_id": record["device_id"],
                    "created_at": record["created_at"],
                    "expires_at": record["expires_at"],
                    "state": state,
                }
            )
        connection.commit()
        return authorizations
    except DatabaseError:
        _rollback_quietly(connection)
        raise
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError(
            "Enrollment authorizations could not be read."
        ) from exc
    finally:
        connection.close()


def run_if_binding_active(database_path, user_id, device_id, fingerprint, operation):
    """Run one short local claim while the exact binding remains active.

    The callback must be limited to the minimum non-database claim operation.
    This deliberately holds SQLite's normal writer position only long enough to
    order a local credential claim against a concurrent trusted revocation.
    """
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    if not isinstance(fingerprint, str):
        raise ValueError("fingerprint is required.")
    if not callable(operation):
        raise ValueError("operation must be callable.")

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        binding = connection.execute(
            """
            SELECT revoked, public_key_fingerprint
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        ).fetchone()
        if (
            binding is None
            or binding["revoked"]
            or binding["public_key_fingerprint"] != fingerprint
        ):
            connection.rollback()
            return False
        result = operation()
        connection.rollback()
        return result
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Authenticator claim check could not be completed.") from exc
    except Exception:
        _rollback_quietly(connection)
        raise
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
            f"Local state {field_name} timestamp is invalid."
        ) from exc
    if parsed.tzinfo is None:
        raise EnrollmentStateError(f"Local state {field_name} timestamp is invalid.")
    return parsed


def _authorization_is_open(authorization, timestamp):
    if authorization["consumed_at"] is not None or authorization["cancelled_at"] is not None:
        return False
    return _parse_timestamp(authorization["expires_at"], "expiry") > _parse_timestamp(
        timestamp, "current"
    )


def _issue_enrollment_authorization_in_transaction(
    connection, user_id, device_id, timestamp, lifetime_seconds
):
    """Create one scoped authorization while an existing writer transaction is held."""
    authorization_id = secrets.token_urlsafe(16)
    authorization_secret = secrets.token_urlsafe(32)
    secret_digest = _authorization_secret_digest(authorization_secret)
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
    return {
        "authorization_id": authorization_id,
        "authorization_secret": authorization_secret,
        "user_id": user_id,
        "device_id": device_id,
        "expires_at": expires_at,
    }


def issue_enrollment_authorization(
    database_path, user_id, device_id, lifetime_seconds=DEFAULT_ENROLLMENT_LIFETIME_SECONDS
):
    """Create one scoped, short-lived authorization and cancel earlier open scope."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    if not isinstance(lifetime_seconds, int) or lifetime_seconds <= 0:
        raise ValueError("lifetime_seconds must be a positive integer.")

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        authorization = _issue_enrollment_authorization_in_transaction(
            connection, user_id, device_id, timestamp, lifetime_seconds
        )
        _insert_security_event(
            connection,
            timestamp,
            "enrollment.authorization_issued",
            "success",
            "issued",
            "local_administrator",
            "trusted_local_account",
            user_id=user_id,
            device_id=device_id,
        )
        connection.commit()
        return authorization
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


def prepare_authenticator_replacement(
    database_path,
    user_id,
    old_device_id,
    new_device_id,
    reason,
    lifetime_seconds=DEFAULT_ENROLLMENT_LIFETIME_SECONDS,
):
    """Revoke one active binding and authorize one distinct replacement binding."""
    validate_identifier(user_id, "user_id")
    validate_identifier(old_device_id, "old_device_id")
    validate_identifier(new_device_id, "new_device_id")
    validate_revocation_reason(reason)
    if old_device_id == new_device_id:
        raise ValueError("replacement binding must use a different device_id.")
    if not isinstance(lifetime_seconds, int) or lifetime_seconds <= 0:
        raise ValueError("lifetime_seconds must be a positive integer.")

    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        old_binding = connection.execute(
            """
            SELECT revoked, public_key_fingerprint
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, old_device_id),
        ).fetchone()
        if old_binding is None:
            connection.commit()
            return {
                "status": "not_found",
                "old_device_id": old_device_id,
                "device_id": new_device_id,
            }
        if old_binding["revoked"]:
            connection.commit()
            return {
                "status": "already_revoked",
                "old_device_id": old_device_id,
                "device_id": new_device_id,
            }

        authorization = _issue_enrollment_authorization_in_transaction(
            connection, user_id, new_device_id, timestamp, lifetime_seconds
        )
        connection.execute(
            """
            UPDATE devices
            SET revoked = 1,
                challenge_b64 = NULL,
                revoked_at = ?,
                revocation_reason = ?
            WHERE user_id = ? AND device_id = ? AND revoked = 0
            """,
            (timestamp, reason, user_id, old_device_id),
        )
        connection.execute(
            """
            DELETE FROM authentication_challenges
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, old_device_id),
        )
        _insert_security_event(
            connection,
            timestamp,
            "authenticator.replacement_prepared",
            "success",
            reason,
            "local_administrator",
            "trusted_local_account",
            user_id=user_id,
            device_id=old_device_id,
            related_device_id=new_device_id,
            public_key_fingerprint=old_binding["public_key_fingerprint"],
        )
        connection.commit()
        authorization.update(
            {
                "status": "prepared",
                "old_device_id": old_device_id,
                "revocation_reason": reason,
            }
        )
        return authorization
    except (DatabaseError, EnrollmentDeniedError):
        _rollback_quietly(connection)
        raise
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Authenticator replacement was rolled back.") from exc
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
            SELECT
                authorization_id,
                user_id,
                device_id,
                expires_at,
                cancelled_at,
                consumed_at
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
        _insert_security_event(
            connection,
            timestamp,
            "enrollment.authorization_cancelled",
            "success",
            "cancelled",
            "local_administrator",
            "trusted_local_account",
            user_id=authorization["user_id"],
            device_id=authorization["device_id"],
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
    """Bind or reconcile after the caller has verified enrollment proof v1."""
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
            _insert_security_event(
                connection,
                timestamp,
                "authenticator.binding_reconciled",
                "success",
                "revoked" if device["revoked"] else "active",
                "client",
                "proof_of_possession_verified",
                user_id=user_id,
                device_id=device_id,
                public_key_fingerprint=public_key_fingerprint,
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
        _insert_security_event(
            connection,
            timestamp,
            "authenticator.bound",
            "success",
            "created",
            "client",
            "proof_of_possession_verified",
            user_id=user_id,
            device_id=device_id,
            public_key_fingerprint=public_key_fingerprint,
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


def _challenge_expiry(timestamp, lifetime_seconds):
    return (_parse_timestamp(timestamp, "created") + timedelta(
        seconds=lifetime_seconds
    )).isoformat()


def _remove_stale_authentication_challenges(connection, timestamp):
    """Remove consumed or expired v3 challenges during a normal writer transition."""
    current_time = _parse_timestamp(timestamp, "current")
    rows = connection.execute(
        """
        SELECT challenge_id, expires_at, consumed_at
        FROM authentication_challenges
        """
    ).fetchall()
    stale_challenge_ids = []
    for row in rows:
        if row["consumed_at"] is not None or (
            _parse_timestamp(row["expires_at"], "challenge expiry") <= current_time
        ):
            stale_challenge_ids.append((row["challenge_id"],))
    if stale_challenge_ids:
        connection.executemany(
            "DELETE FROM authentication_challenges WHERE challenge_id = ?",
            stale_challenge_ids,
        )


def issue_authentication_challenge(
    database_path, user_id, device_id, lifetime_seconds=DEFAULT_CHALLENGE_LIFETIME_SECONDS
):
    """Create one independent v2 challenge for an exact active binding."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    if not isinstance(lifetime_seconds, int) or lifetime_seconds <= 0:
        raise ValueError("lifetime_seconds must be a positive integer.")

    challenge_id = secrets.token_urlsafe(32)
    nonce_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        binding = connection.execute(
            """
            SELECT user_id, device_id, public_key_fingerprint, revoked
            FROM devices
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        ).fetchone()
        if binding is None:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "binding_not_found",
                "client",
                "unverified_claim",
            )
            connection.commit()
            return None
        if binding["revoked"]:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "binding_revoked",
                "client",
                "unverified_claim",
                user_id=binding["user_id"],
                device_id=binding["device_id"],
                public_key_fingerprint=binding["public_key_fingerprint"],
            )
            connection.commit()
            return None
        _remove_stale_authentication_challenges(connection, timestamp)
        open_challenge_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM authentication_challenges
            WHERE user_id = ?
              AND device_id = ?
              AND consumed_at IS NULL
            """,
            (user_id, device_id),
        ).fetchone()[0]
        if open_challenge_count >= MAX_OUTSTANDING_CHALLENGES_PER_BINDING:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "challenge_limit_reached",
                "client",
                "unverified_claim",
                user_id=binding["user_id"],
                device_id=binding["device_id"],
                public_key_fingerprint=binding["public_key_fingerprint"],
            )
            connection.commit()
            return None
        expires_at = _challenge_expiry(timestamp, lifetime_seconds)
        connection.execute(
            """
            INSERT INTO authentication_challenges (
                challenge_id,
                user_id,
                device_id,
                public_key_fingerprint,
                nonce_b64,
                created_at,
                expires_at,
                consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                challenge_id,
                user_id,
                device_id,
                binding["public_key_fingerprint"],
                nonce_b64,
                timestamp,
                expires_at,
            ),
        )
        _insert_security_event(
            connection,
            timestamp,
            "authentication.challenge_issued",
            "success",
            "issued",
            "client",
            "unverified_claim",
            user_id=binding["user_id"],
            device_id=binding["device_id"],
            public_key_fingerprint=binding["public_key_fingerprint"],
            interaction_id=challenge_id,
        )
        connection.commit()
        return {
            "challenge_id": challenge_id,
            "nonce_b64": nonce_b64,
            "user_id": user_id,
            "device_id": device_id,
            "public_key_fingerprint": binding["public_key_fingerprint"],
            "expires_at": expires_at,
        }
    except (EnrollmentStateError, sqlite3.DatabaseError) as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("The authentication challenge could not be issued.") from exc
    finally:
        connection.close()


def get_authentication_challenge(database_path, challenge_id):
    """Return stored challenge context for signature verification only."""
    validate_challenge_id(challenge_id)
    connection = _open_existing_database(database_path)
    try:
        row = connection.execute(
            """
            SELECT
                challenges.challenge_id,
                challenges.user_id,
                challenges.device_id,
                challenges.public_key_fingerprint,
                challenges.nonce_b64,
                challenges.created_at,
                challenges.expires_at,
                challenges.consumed_at,
                devices.public_key_b64,
                devices.public_key_fingerprint AS binding_fingerprint,
                devices.revoked
            FROM authentication_challenges AS challenges
            JOIN devices
              ON devices.user_id = challenges.user_id
             AND devices.device_id = challenges.device_id
            WHERE challenges.challenge_id = ?
            """,
            (challenge_id,),
        ).fetchone()
        if row is not None and row["public_key_fingerprint"] != row["binding_fingerprint"]:
            raise DatabaseOperationError(
                "Stored authentication challenge does not match its authenticator binding."
            )
        return dict(row) if row else None
    except sqlite3.DatabaseError as exc:
        raise DatabaseOperationError("The authentication challenge could not be read.") from exc
    finally:
        connection.close()


def consume_authentication_challenge(database_path, challenge_id):
    """Consume one challenge after the caller has verified its PKAS-AUTH-V2 proof."""
    validate_challenge_id(challenge_id)
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        timestamp = utc_now()
        challenge = connection.execute(
            """
            SELECT
                user_id,
                device_id,
                public_key_fingerprint,
                expires_at,
                consumed_at
            FROM authentication_challenges
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        ).fetchone()
        if challenge is None:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "challenge_unavailable",
                "client",
                "unverified_claim",
            )
            connection.commit()
            return False
        if challenge["consumed_at"] is not None:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "challenge_replayed",
                "client",
                "unverified_claim",
                user_id=challenge["user_id"],
                device_id=challenge["device_id"],
                public_key_fingerprint=challenge["public_key_fingerprint"],
                interaction_id=challenge_id,
            )
            connection.commit()
            return False
        expires_at = _parse_timestamp(challenge["expires_at"], "challenge expiry")
        current_time = _parse_timestamp(timestamp, "current")
        if expires_at <= current_time:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "challenge_expired",
                "client",
                "unverified_claim",
                user_id=challenge["user_id"],
                device_id=challenge["device_id"],
                public_key_fingerprint=challenge["public_key_fingerprint"],
                interaction_id=challenge_id,
            )
            connection.commit()
            return False
        cursor = connection.execute(
            """
            UPDATE authentication_challenges
            SET consumed_at = ?
            WHERE challenge_id = ?
              AND consumed_at IS NULL
              AND EXISTS (
                  SELECT 1
                  FROM devices
                  WHERE devices.user_id = authentication_challenges.user_id
                    AND devices.device_id = authentication_challenges.device_id
                    AND devices.public_key_fingerprint = authentication_challenges.public_key_fingerprint
                    AND devices.revoked = 0
              )
            """,
            (timestamp, challenge_id),
        )
        if cursor.rowcount == 1:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.succeeded",
                "success",
                "proof_verified",
                "authenticator",
                "cryptographically_verified",
                user_id=challenge["user_id"],
                device_id=challenge["device_id"],
                public_key_fingerprint=challenge["public_key_fingerprint"],
                interaction_id=challenge_id,
            )
        else:
            _insert_security_event(
                connection,
                timestamp,
                "authentication.denied",
                "denied",
                "binding_inactive",
                "client",
                "unverified_claim",
                user_id=challenge["user_id"],
                device_id=challenge["device_id"],
                public_key_fingerprint=challenge["public_key_fingerprint"],
                interaction_id=challenge_id,
            )
        connection.commit()
        return cursor.rowcount == 1
    except (EnrollmentStateError, sqlite3.DatabaseError) as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("The authentication challenge could not be consumed.") from exc
    finally:
        connection.close()


def revoke_authenticator(database_path, user_id, device_id, reason):
    """Terminally revoke a binding and delete its outstanding v3 challenges."""
    validate_identifier(user_id, "user_id")
    validate_identifier(device_id, "device_id")
    validate_revocation_reason(reason)
    connection = _open_existing_database(database_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        device = connection.execute(
            """
            SELECT revoked, revoked_at, revocation_reason, public_key_fingerprint
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
        timestamp = utc_now()
        connection.execute(
            """
            UPDATE devices
            SET revoked = 1,
                challenge_b64 = NULL,
                revoked_at = ?,
                revocation_reason = ?
            WHERE user_id = ? AND device_id = ? AND revoked = 0
            """,
            (timestamp, reason, user_id, device_id),
        )
        connection.execute(
            """
            DELETE FROM authentication_challenges
            WHERE user_id = ? AND device_id = ?
            """,
            (user_id, device_id),
        )
        _insert_security_event(
            connection,
            timestamp,
            "authenticator.revoked",
            "success",
            reason,
            "local_administrator",
            "trusted_local_account",
            user_id=user_id,
            device_id=device_id,
            public_key_fingerprint=device["public_key_fingerprint"],
        )
        connection.commit()
        return "revoked"
    except sqlite3.DatabaseError as exc:
        _rollback_quietly(connection)
        raise DatabaseOperationError("Authenticator revocation was rolled back.") from exc
    finally:
        connection.close()
