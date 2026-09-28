#!/usr/bin/env python3
"""Validate and materialize the isolated PostgreSQL restore target.

The restore wrapper deliberately accepts URI DSNs only.  Keeping the database
name in the URI path makes it possible to prove that createdb, pg_restore,
grant application, session revocation and Beacon verification all point at
the same newly generated database and server.
"""
import os
import pathlib
import re
import sys
from urllib.parse import parse_qsl, unquote, urlsplit


def fail(message):
    raise SystemExit(f"restore target rejected: {message}")


def parse_uri(raw, label, template=False):
    if not raw:
        fail(f"{label} is empty")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"postgres", "postgresql"}:
        fail(f"{label} must use a postgres:// or postgresql:// URI")
    if not parsed.hostname:
        fail(f"{label} must contain a hostname")
    if parsed.fragment:
        fail(f"{label} must not contain a URI fragment")
    try:
        port = parsed.port or 5432
    except ValueError:
        fail(f"{label} has an invalid port")
    query_keys = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    allowed_query_keys = {"sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "connect_timeout", "channel_binding", "gssencmode"}
    if query_keys - allowed_query_keys:
        fail(f"{label} contains an unsupported connection-routing option")
    path = unquote(parsed.path)
    if not path.startswith("/") or not path[1:] or "/" in path[1:]:
        fail(f"{label} must contain one database path component")
    if template:
        if path.count("%s") != 1 or parsed.query.count("%s") or parsed.fragment.count("%s"):
            fail(f"{label} must contain exactly one %s in its database path")
    elif "%s" in raw:
        fail(f"{label} must not contain %s")
    database = path[1:]
    return parsed, port, database


def endpoint(parsed, port):
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def main():
    output_dir = pathlib.Path(sys.argv[1])
    maintenance = os.environ.get("BEACON_PG_RESTORE_MAINTENANCE_URL")
    runtime_template = os.environ.get("BEACON_PG_RESTORE_URL_TEMPLATE")
    admin_template = os.environ.get("BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE")
    source = os.environ.get("BEACON_PG_SOURCE_DATABASE_URL")
    maintenance_parsed, maintenance_port, maintenance_db = parse_uri(maintenance, "BEACON_PG_RESTORE_MAINTENANCE_URL")
    runtime_parsed, runtime_port, runtime_db_template = parse_uri(runtime_template, "BEACON_PG_RESTORE_URL_TEMPLATE", True)
    admin_parsed, admin_port, admin_db_template = parse_uri(admin_template, "BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE", True)

    expected_endpoint = endpoint(maintenance_parsed, maintenance_port)
    if endpoint(runtime_parsed, runtime_port) != expected_endpoint or endpoint(admin_parsed, admin_port) != expected_endpoint:
        fail("maintenance, runtime and admin DSNs must reach the same restore server")

    token = os.environ.get("BEACON_RESTORE_DATABASE_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
        fail("BEACON_RESTORE_DATABASE_TOKEN must be a safe PostgreSQL identifier")
    runtime_db = runtime_db_template.replace("%s", token)
    admin_db = admin_db_template.replace("%s", token)
    if runtime_db != admin_db:
        fail("runtime and admin templates resolve to different database names")
    if len(runtime_db) > 63:
        fail("resolved restore database name exceeds PostgreSQL's 63-byte limit")
    if runtime_db == maintenance_db:
        fail("restore database must differ from the maintenance database")

    if source:
        source_parsed, source_port, source_db = parse_uri(source, "BEACON_PG_SOURCE_DATABASE_URL")
        if endpoint(source_parsed, source_port) == expected_endpoint and source_db == runtime_db:
            fail("restore database matches the configured source database")

    runtime_url = runtime_template.replace("%s", token)
    admin_url = admin_template.replace("%s", token)
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in (("restore-db", runtime_db), ("runtime-url", runtime_url), ("admin-url", admin_url)):
        path = output_dir / name
        path.write_text(value + "\n", encoding="utf-8")
        path.chmod(0o600)


if __name__ == "__main__":
    main()
