# Contributing

Start with README.md, THREAT_MODEL.md and docs/architecture/README.md. Keep changes within product vulnerability response. Do not add mandatory cloud calls, analytics, AI integrations or shared multi-tenancy to this release.

Use Go formatting and run scripts/test.sh against an isolated local PostgreSQL instance. Add meaningful tests for authorization boundaries, encryption, audit ordering, deadlines and persistence when changing them. UI-only reversible edits do not require mirrored unit tests.

Use synthetic reports and generated local credentials. Never commit .env, database dumps, reporter tokens or exploit samples from real cases. Contributions are under Apache-2.0. Establish maintainer review and a private reporting channel before a public community launch.

French pages are generated from static template literals. Update `internal/beacon/web/fr.json` and run `python3 scripts/localize.py`; CI rejects stale generated templates. Never translate user-supplied report text.
