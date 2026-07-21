# Repository Guidance

## Project scope

This repository is evolving from an academic passwordless-authentication demo
into an identity security and detection lab. Work must follow the approved
project phase and the decisions recorded in `docs/decision-log.md`.

## Strategic context

- Read `MARKET_CONTEXT.md` before proposing or implementing any project phase.
- Use it to understand the project's market purpose, portfolio role, and
  evidence priorities.
- Treat it as strategic context, not permission to expand the active phase.
  Explicit approved phase instructions remain authoritative for implementation
  scope.
- Preserve the distinction between this focused supporting identity-security
  project and the separate **Azure Privileged Access Abuse Detection & Recovery
  Lab** flagship project. Do not duplicate or replace the flagship's Azure,
  Microsoft Sentinel, cloud-control-plane, or privileged-access scenario.

## Phase 0 constraints

- Preserve current runtime behavior. Do not change application code merely to
  make a characterization test pass.
- Treat insecure behavior captured by characterization tests as documented
  technical debt for a later phase.
- Keep tests isolated from the repository's `database.json` and client key
  files. Use temporary directories and Flask's in-process test client.
- Do not add security scanners, telemetry, rate limiting, storage migrations,
  dependency-policy changes, or application restructuring during Phase 0.
- Do not commit or push unless the user explicitly requests it.

## Required checks

Use the repository-local virtual environment and run the complete suite before
and after any approved change:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git diff --check
git status --short --branch
```

Never commit `database.json`, `.env`, generated AES keys, encrypted private
keys, virtual environments, or Python test artifacts.
