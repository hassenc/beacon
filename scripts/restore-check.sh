#!/usr/bin/env bash
# Restores a snapshot to a NEW database. Never overwrites the primary database.
set -eu
set -o pipefail
cd "$(dirname "$0")/.."
umask 077
set -a
. ./.env
set +a
: "${BEACON_BACKUP_KEY_FILE:?Set BEACON_BACKUP_KEY_FILE to the separately protected recovery key}"
test -r "$BEACON_BACKUP_KEY_FILE"
mkdir -p artifacts
restore_db="beacon_restore_$(date +%s)"
dump_path="artifacts/${restore_db}.backup"
raw_dump_path="$(mktemp "artifacts/${restore_db}.XXXXXX.dump")"
cleanup() {
  if [[ -n "${BEACON_PG_DATABASE_URL_TEMPLATE:-}" ]]; then
    dropdb --if-exists --maintenance-db="${BEACON_PG_ADMIN_DATABASE_URL:-}" "$restore_db" >/dev/null 2>&1 || true
  else
    docker compose exec -T "${BEACON_DB_SERVICE:-db}" dropdb -U "${BEACON_DB_USER:-beacon}" --if-exists "$restore_db" >/dev/null 2>&1 || true
  fi
  rm -f "$dump_path" "$raw_dump_path"
}
trap cleanup EXIT HUP INT TERM
encrypt_backup() {
  if [[ -n "${BEACON_BIN:-}" ]]; then
    "$BEACON_BIN" backup-encrypt
  else
    go run ./cmd/beacon backup-encrypt
  fi
}
decrypt_backup() {
  if [[ -n "${BEACON_BIN:-}" ]]; then
    "$BEACON_BIN" backup-decrypt
  else
    go run ./cmd/beacon backup-decrypt
  fi
}
run_beacon() {
  if [[ -n "${BEACON_BIN:-}" ]]; then
    "$BEACON_BIN" "$@"
  else
    go run ./cmd/beacon "$@"
  fi
}
dump_database() {
  if [[ -n "${BEACON_PG_SOURCE_DATABASE_URL:-}" ]]; then
    pg_dump "$BEACON_PG_SOURCE_DATABASE_URL" -Fc
  else
    docker compose exec -T "${BEACON_DB_SERVICE:-db}" pg_dump -U "${BEACON_DB_USER:-beacon}" -d "${BEACON_DB_NAME:-beacon}" -Fc
  fi
}
create_restore_database() {
  if [[ -n "${BEACON_PG_DATABASE_URL_TEMPLATE:-}" ]]; then
    createdb --maintenance-db="${BEACON_PG_ADMIN_DATABASE_URL:?Set BEACON_PG_ADMIN_DATABASE_URL}" "$restore_db"
  else
    docker compose exec -T "${BEACON_DB_SERVICE:-db}" createdb -U "${BEACON_DB_USER:-beacon}" "$restore_db"
  fi
}
restore_database() {
  if [[ -n "${BEACON_PG_DATABASE_URL_TEMPLATE:-}" ]]; then
    local restore_dsn="${BEACON_PG_DATABASE_URL_TEMPLATE/\%s/$restore_db}"
    pg_restore --dbname="$restore_dsn" --no-owner < "$raw_dump_path"
  else
    docker compose exec -T "${BEACON_DB_SERVICE:-db}" pg_restore -U "${BEACON_DB_USER:-beacon}" -d "$restore_db" --no-owner < "$raw_dump_path"
  fi
}
dump_database |
  BEACON_BACKUP_KEY_FILE="$BEACON_BACKUP_KEY_FILE" encrypt_backup > "$dump_path"
create_restore_database
# Stage the complete authenticated dump before touching the destination. A
# late decrypt/authentication failure must not leave a partially restored DB.
BEACON_BACKUP_KEY_FILE="$BEACON_BACKUP_KEY_FILE" decrypt_backup < "$dump_path" > "$raw_dump_path"
restore_database
if [[ -n "${BEACON_PG_DATABASE_URL_TEMPLATE:-}" ]]; then
  export DATABASE_URL="${BEACON_PG_DATABASE_URL_TEMPLATE/\%s/$restore_db}"
else
  export DATABASE_URL="postgres://beacon:${POSTGRES_PASSWORD}@127.0.0.1:55438/${restore_db}?sslmode=disable"
fi
run_beacon audit verify
run_beacon verify-data
echo 'Restore, decryption, attachment hashes, and audit chain verified in an isolated database.'
