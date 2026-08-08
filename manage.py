import argparse
import json
import os
from pathlib import Path

from db_utils import (
    DATABASE_ENV_VAR,
    DatabaseError,
    cancel_enrollment_authorization,
    create_identity,
    get_database_status,
    get_default_database_path,
    initialize_database,
    issue_enrollment_authorization,
    list_authenticator_inventory,
    migrate_database,
    revoke_authenticator,
)


LEGACY_DATABASE_PATH = Path(__file__).resolve().parent / "database.json"


def build_parser():
    parser = argparse.ArgumentParser(
        description="Initialize and inspect local authentication state."
    )
    parser.add_argument(
        "--database",
        type=Path,
        help="Override the local SQLite database path.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Initialize local state without replacing it.")
    subparsers.add_parser("status", help="Show local state readiness and counts.")
    subparsers.add_parser("migrate", help="Explicitly migrate supported v1 state to v2.")

    identity_add = subparsers.add_parser(
        "identity-add", help="Create a logical identity through trusted local administration."
    )
    identity_add.add_argument("user_id")

    authorization_issue = subparsers.add_parser(
        "enrollment-issue",
        help="Issue one scoped enrollment authorization and cancel an earlier open one.",
    )
    authorization_issue.add_argument("user_id")
    authorization_issue.add_argument("device_id")

    authorization_cancel = subparsers.add_parser(
        "enrollment-cancel", help="Cancel an open enrollment authorization."
    )
    authorization_cancel.add_argument("authorization_id")

    inventory = subparsers.add_parser(
        "inventory", help="Show sanitized identity and authenticator lifecycle state."
    )
    inventory.add_argument("--user-id")
    inventory.add_argument("--fingerprint")

    revoke = subparsers.add_parser(
        "revoke", help="Terminally revoke an authenticator and clear its challenge."
    )
    revoke.add_argument("user_id")
    revoke.add_argument("device_id")
    revoke.add_argument("reason")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    database_path = args.database or get_default_database_path()

    if args.command == "init":
        using_default_path = args.database is None and not os.environ.get(
            DATABASE_ENV_VAR
        )
        if (
            using_default_path
            and not Path(database_path).exists()
            and LEGACY_DATABASE_PATH.is_file()
        ):
            print(
                json.dumps(
                    {
                        "status": "error",
                        "code": "legacy_state_detected",
                        "error": (
                            "Legacy database.json state was found and was not modified. "
                            "Review or archive it before initializing empty SQLite state, "
                            "or pass --database to make the new path explicit."
                        ),
                        "legacy_path": str(LEGACY_DATABASE_PATH),
                        "path": str(Path(database_path).resolve()),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 1

        try:
            created = initialize_database(database_path)
        except DatabaseError as exc:
            print(json.dumps({"status": "error", "error": str(exc)}))
            return 1

        result = get_database_status(database_path)
        result["status"] = "initialized" if created else "already_initialized"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if args.command == "migrate":
        try:
            migrated = migrate_database(database_path)
        except DatabaseError as exc:
            print(json.dumps({"status": "error", "error": str(exc)}))
            return 1

        result = get_database_status(database_path)
        result["status"] = "migrated" if migrated else "already_current"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    try:
        if args.command == "identity-add":
            created = create_identity(database_path, args.user_id)
            print(
                json.dumps(
                    {
                        "status": "created" if created else "already_exists",
                        "user_id": args.user_id,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "enrollment-issue":
            authorization = issue_enrollment_authorization(
                database_path, args.user_id, args.device_id
            )
            print(json.dumps(authorization, indent=2, sort_keys=True))
            return 0

        if args.command == "enrollment-cancel":
            result = cancel_enrollment_authorization(
                database_path, args.authorization_id
            )
            print(
                json.dumps(
                    {"status": result, "authorization_id": args.authorization_id},
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "inventory":
            result = list_authenticator_inventory(
                database_path,
                user_id=args.user_id,
                fingerprint=args.fingerprint,
            )
            print(json.dumps({"identities": result}, indent=2, sort_keys=True))
            return 0

        if args.command == "revoke":
            before = list_authenticator_inventory(database_path, user_id=args.user_id)
            active_count = sum(
                authenticator["state"] == "active"
                for identity in before
                for authenticator in identity["authenticators"]
            )
            result = revoke_authenticator(
                database_path, args.user_id, args.device_id, args.reason
            )
            output = {
                "status": result,
                "user_id": args.user_id,
                "device_id": args.device_id,
            }
            if result == "revoked" and active_count == 1:
                output["warning"] = (
                    "This was the last active authenticator for the logical identity."
                )
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0 if result != "not_found" else 1
    except (DatabaseError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1

    status = get_database_status(database_path)
    status["status"] = "ready" if status["initialized"] else "not_ready"
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status["initialized"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
