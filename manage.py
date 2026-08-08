import argparse
import json
import os
from pathlib import Path

from db_utils import (
    DATABASE_ENV_VAR,
    DatabaseError,
    get_database_status,
    get_default_database_path,
    initialize_database,
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

    status = get_database_status(database_path)
    status["status"] = "ready" if status["initialized"] else "not_ready"
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status["initialized"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
