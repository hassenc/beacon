#!/usr/bin/env bash
# Deterministic contract test for the production backup/restore wrappers.
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/bin" "$tmp/out" "$tmp/offhost" "$tmp/db"
printf '%064d\n' 0 > "$tmp/backup.key"
printf '%064d\n' 1 > "$tmp/app.key"

cat > "$tmp/bin/beacon" <<'SH'
#!/usr/bin/env bash
set -eu
case "${1:-}" in
  backup-encrypt|backup-decrypt) cat ;;
  audit) echo 'Verified synthetic events' ;;
  verify-data) echo 'Verified synthetic data' ;;
  *) echo "unexpected beacon command" >&2; exit 1 ;;
esac
SH
cat > "$tmp/bin/pg_dump" <<'SH'
#!/usr/bin/env bash
printf 'synthetic custom-format dump\n'
SH
cat > "$tmp/bin/createdb" <<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "${!#}" > "$TEST_DB_MARKER"
SH
cat > "$tmp/bin/pg_restore" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
SH
cat > "$tmp/bin/psql" <<'SH'
#!/usr/bin/env bash
cat >/dev/null || true
exit 0
SH
cat > "$tmp/bin/dropdb" <<'SH'
#!/usr/bin/env bash
rm -f "$TEST_DB_MARKER"
SH
chmod +x "$tmp/bin"/*

cat > "$tmp/backup.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_PG_SOURCE_DATABASE_URL=postgres://synthetic/source
BEACON_BACKUP_OUTPUT_DIR=$tmp/out
BEACON_BACKUP_DEST_DIR=$tmp/offhost
BEACON_BACKUP_RETENTION_DAYS=35
BEACON_BACKUP_PRUNE=0
BEACON_SOURCE_IDENTITY=fixture
BEACON_SCHEMA_IDENTITY=schema-4
BEACON_IMAGE_ID=sha256:fixture
EOF
PATH="$tmp/bin:$PATH" BEACON_CONFIG_FILE="$tmp/backup.env" "$root/scripts/production-backup.sh" "$tmp/backup.env"
backup_path="$(find "$tmp/out" -type f -name 'beacon-*.backup' -print -quit)"
test -n "$backup_path"
test -f "$tmp/offhost/$(basename "$backup_path")"
test -f "${backup_path%.backup}.json"
python3 - "$tmp/offhost/$(basename "${backup_path%.backup}.json")" <<'PY'
import json, sys
metadata = json.load(open(sys.argv[1], encoding="utf-8"))
assert metadata["copy_complete"] is True
assert metadata["sha256"] == metadata["destination_sha256"]
assert metadata["bytes"] == metadata["destination_bytes"]
PY

cat > "$tmp/mount-failure.env" <<EOF
$(cat "$tmp/backup.env")
BEACON_BACKUP_REQUIRE_MOUNT=1
BEACON_BACKUP_MOUNTPOINT=$tmp/not-mounted
EOF
if PATH="$tmp/bin:$PATH" "$root/scripts/production-backup.sh" "$tmp/mount-failure.env" >/dev/null 2>&1; then
  echo 'unmounted backup destination unexpectedly accepted' >&2
  exit 1
fi

touch "$tmp/not-a-directory"
sed "s#BEACON_BACKUP_DEST_DIR=.*#BEACON_BACKUP_DEST_DIR=$tmp/not-a-directory#" "$tmp/backup.env" > "$tmp/copy-failure.env"
if PATH="$tmp/bin:$PATH" "$root/scripts/production-backup.sh" "$tmp/copy-failure.env" >/dev/null 2>&1; then
  echo 'backup copy failure unexpectedly succeeded' >&2
  exit 1
fi

cat > "$tmp/restore.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=postgres://synthetic/postgres
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://synthetic/restore-%s
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://synthetic/restore-%s
BEACON_PG_SOURCE_DATABASE_URL=postgres://synthetic/source
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
BEACON_RESTORE_KEEP=0
EOF
TEST_DB_MARKER="$tmp/db/created" PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/restore.env" "$backup_path"
test ! -e "$tmp/db/created"

cat > "$tmp/bin/pg_restore" <<'SH'
#!/usr/bin/env bash
cat >/dev/null
exit 17
SH
chmod +x "$tmp/bin/pg_restore"
if TEST_DB_MARKER="$tmp/db/created" PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/restore.env" "$backup_path" >/dev/null 2>&1; then
  echo 'import failure unexpectedly succeeded' >&2
  exit 1
fi
test ! -e "$tmp/db/created"

cat > "$tmp/mismatch.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=postgres://synthetic/postgres
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://synthetic/restore-%s
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://other/restore-%s
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
EOF
if PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/mismatch.env" "$backup_path" >/dev/null 2>&1; then
  echo 'restore target mismatch unexpectedly accepted' >&2
  exit 1
fi

cat > "$tmp/mismatch-db.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=postgres://synthetic/postgres
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://synthetic/runtime-%s
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://synthetic/admin-%s
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
EOF
if PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/mismatch-db.env" "$backup_path" >/dev/null 2>&1; then
  echo 'restore database mismatch unexpectedly accepted' >&2
  exit 1
fi

cat > "$tmp/query-placeholder.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=postgres://synthetic/postgres
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://synthetic/live?application_name=%s
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://synthetic/live?application_name=%s
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
EOF
if PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/query-placeholder.env" "$backup_path" >/dev/null 2>&1; then
  echo 'query placeholder unexpectedly accepted' >&2
  exit 1
fi

cat > "$tmp/query-host.env" <<EOF
BEACON_BIN=$tmp/bin/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=postgres://synthetic/postgres
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://synthetic/restore-%s?host=another
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://synthetic/restore-%s?host=another
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
EOF
if PATH="$tmp/bin:$PATH" "$root/scripts/production-restore.sh" "$tmp/query-host.env" "$backup_path" >/dev/null 2>&1; then
  echo 'query host override unexpectedly accepted' >&2
  exit 1
fi
echo 'production backup/restore wrappers: PASS'
