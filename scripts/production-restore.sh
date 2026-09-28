#!/usr/bin/env bash
# Restore an existing authenticated backup into a new, isolated PostgreSQL DB.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
config_file="${1:?Usage: production-restore.sh /path/to/restore.env /path/to/backup}"
backup_path="${2:?Usage: production-restore.sh /path/to/restore.env /path/to/backup}"
test -r "$config_file" || { echo "Cannot read configuration file: $config_file" >&2; exit 1; }
test -r "$backup_path" || { echo "Cannot read backup: $backup_path" >&2; exit 1; }
umask 077
set -a
. "$config_file"
set +a
: "${BEACON_BIN:?Set BEACON_BIN to the reviewed Beacon binary}"
: "${BEACON_BACKUP_KEY_FILE:?Set BEACON_BACKUP_KEY_FILE to the separate archive key}"
: "${BEACON_KEY_FILE:?Set BEACON_KEY_FILE to the application encryption key}"
: "${BEACON_PG_RESTORE_MAINTENANCE_URL:?Set the isolated restore maintenance DSN}"
: "${BEACON_PG_RESTORE_URL_TEMPLATE:?Set the isolated restore runtime DSN template with one %s database placeholder}"
: "${BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE:?Set the isolated restore admin DSN template with one %s database placeholder}"
: "${BEACON_RUNTIME_GRANTS_FILE:=deploy/runtime-grants.sql}"
test -r "$BEACON_RUNTIME_GRANTS_FILE"
test -r "$BEACON_BACKUP_KEY_FILE"
test -r "$BEACON_KEY_FILE"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

metadata_path="${backup_path%.backup}.json"
if [[ -r "$metadata_path" ]]; then
  expected_sha256="$(python3 - "$metadata_path" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["sha256"])
PY
)"
  actual_sha256="$(sha256 "$backup_path")"
  test "$expected_sha256" = "$actual_sha256" || { echo "Backup checksum does not match metadata" >&2; exit 1; }
fi

staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/beacon-restore.XXXXXX")"
raw_dump_path="$staging_dir/restore.dump"
restore_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
keep_restore="${BEACON_RESTORE_KEEP:-0}"
created=0
restore_token="beacon_restore_$(date -u +%Y%m%d%H%M%S)_$$"
cleanup() {
  if [[ "$created" == 1 && "$keep_restore" != 1 ]]; then
    dropdb --if-exists --maintenance-db="$BEACON_PG_RESTORE_MAINTENANCE_URL" "$restore_db" >/dev/null 2>&1 || true
  fi
  rm -rf "$staging_dir"
}
trap cleanup EXIT HUP INT TERM

BEACON_RESTORE_DATABASE_TOKEN="$restore_token" \
  python3 scripts/validate-restore-target.py "$staging_dir/target"
restore_db="$(<"$staging_dir/target/restore-db")"
restore_url="$(<"$staging_dir/target/runtime-url")"
restore_admin_url="$(<"$staging_dir/target/admin-url")"

# Authenticate the complete archive before creating or modifying any target DB.
BEACON_BACKUP_KEY_FILE="$BEACON_BACKUP_KEY_FILE" "$BEACON_BIN" backup-decrypt < "$backup_path" > "$raw_dump_path"
createdb --maintenance-db="$BEACON_PG_RESTORE_MAINTENANCE_URL" "$restore_db"
created=1
pg_restore --dbname="$restore_admin_url" --no-owner < "$raw_dump_path"
psql "$restore_admin_url" -v ON_ERROR_STOP=1 -f "$BEACON_RUNTIME_GRANTS_FILE" >/dev/null
psql "$restore_admin_url" -v ON_ERROR_STOP=1 -c 'DELETE FROM sessions' >/dev/null

DATABASE_URL="$restore_url" BEACON_KEY_FILE="$BEACON_KEY_FILE" "$BEACON_BIN" audit verify
DATABASE_URL="$restore_url" BEACON_KEY_FILE="$BEACON_KEY_FILE" "$BEACON_BIN" verify-data
restore_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "RESTORE_OK database=$restore_db started=$restore_started finished=$restore_finished kept=$keep_restore"
