# Decision Log

## 2026-07-22 — Market context guides strategy, not phase scope

**Decision:** `MARKET_CONTEXT.md` is the repository's strategic source for
market purpose, portfolio positioning, and evidence priorities. Approved phase
instructions remain authoritative for implementation scope.

**Consequences:** Market relevance informs decisions but must not cause
uncontrolled feature, architecture, or tool expansion. Work remains bounded by
the active approved phase, and this supporting identity-security project stays
distinct from the separate Azure/Sentinel flagship project.

## 2026-07-22 — Prefer the simplest secure and testable implementation

**Decision:** The repository will favor solutions that are secure, testable,
and understandable at the project's current Python and Flask coding level over
enterprise-style abstraction or architectural complexity.

**Consequences:** Changes should adapt to the existing code and introduce only
the smallest necessary structure. Any new abstraction must solve a specific
problem that a simpler approach cannot handle safely. Phase plans must explain
their complexity and learning fit, and completed work must include a simple
explanation of anything that may be difficult for a beginner to defend.

## 2026-07-22 — Phase 0 is characterization-only

**Decision:** Phase 0 preserves and documents the existing system before later
restructuring or security fixes.

**Consequences:** Runtime source files remain unchanged. Tests may encode
insecure behavior when that behavior is the current implementation, and the
assessment records it as technical debt rather than treating it as a desired
security property.

## 2026-07-22 — Test Flask routes in process

**Decision:** Authentication routes are exercised through Flask's
`app.test_client()` instead of a live development server.

**Consequences:** Characterization tests require no bound TCP port or external
HTTP service and remain deterministic in local and CI environments.

## 2026-07-22 — Isolate generated state

**Decision:** Route tests redirect `db_utils.DB_FILE` to a temporary directory,
reset the server's in-memory database for every test, and generate RSA keys only
in memory.

**Consequences:** Tests exercise the real JSON persistence functions without
reading or writing the repository's `database.json`. They do not create client
AES-key or encrypted-private-key files.

## 2026-07-22 — Defer security and architecture work

**Decision:** Static security scanning, dependency-policy changes, structured
telemetry, authentication hardening, rate limiting, SQLite migration, and
application restructuring are deferred to later approved phases.

**Consequences:** The existing CI is changed only if its current unittest
discovery command cannot run the characterization suite reliably.
