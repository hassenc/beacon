#!/usr/bin/env bash
set -eu
set -o pipefail
cd "$(dirname "$0")/.."
umask 077
config_file="${BEACON_CONFIG_FILE:-.env}"
test -r "$config_file" || { echo "Cannot read configuration file: $config_file" >&2; exit 1; }
set -a
. "$config_file"
set +a
: "${BEACON_BACKUP_KEY_FILE:?Set BEACON_BACKUP_KEY_FILE to a separately protected 32-byte hex recovery key}"
test -r "$BEACON_BACKUP_KEY_FILE"
if [[ "${BEACON_BACKUP_MODE:-evaluation}" == production ]]; then
  : "${BEACON_BIN:?Production backup requires BEACON_BIN}"
  : "${BEACON_PG_SOURCE_DATABASE_URL:?Production backup requires BEACON_PG_SOURCE_DATABASE_URL}"
fi
backup_dir="${BEACON_BACKUP_OUTPUT_DIR:-artifacts/backups}"
mkdir -p "$backup_dir"
backup_path="$backup_dir/beacon-$(date -u +%Y%m%dT%H%M%S)-$(od -An -N4 -tu4 /dev/urandom | tr -d ' ').backup"
tmp_path="$(mktemp "$backup_dir/.beacon-backup.XXXXXX")"
metadata_path="${backup_path%.backup}.json"
tmp_metadata="$(mktemp "$backup_dir/.beacon-backup-metadata.XXXXXX")"
trap 'rm -f "$tmp_path" "$tmp_metadata"' EXIT HUP INT TERM
encrypt_backup() {
  if [[ -n "${BEACON_BIN:-}" ]]; then
    "$BEACON_BIN" backup-encrypt
  else
    go run ./cmd/beacon backup-encrypt
  fi
}
dump_database() {
  if [[ -n "${BEACON_PG_SOURCE_DATABASE_URL:-}" ]]; then
    pg_dump "$BEACON_PG_SOURCE_DATABASE_URL" -Fc
  else
    docker compose exec -T "${BEACON_DB_SERVICE:-db}" pg_dump -U "${BEACON_DB_USER:-beacon}" -d "${BEACON_DB_NAME:-beacon}" -Fc
  fi
}
dump_database |
  BEACON_BACKUP_KEY_FILE="$BEACON_BACKUP_KEY_FILE" encrypt_backup > "$tmp_path"
mv "$tmp_path" "$backup_path"
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
backup_sha256="$(sha256 "$backup_path")"
backup_bytes="$(wc -c < "$backup_path" | tr -d ' ')"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BACKUP_PATH="$backup_path" BACKUP_SHA256="$backup_sha256" BACKUP_BYTES="$backup_bytes" CREATED_AT="$created_at" METADATA_PATH="$tmp_metadata" python3 - <<'PY'
import json, os
from pathlib import Path

metadata = {
    "format": "beacon-production-backup-v1",
    "created_at": os.environ["CREATED_AT"],
    "artifact": Path(os.environ["BACKUP_PATH"]).name,
    "sha256": os.environ["BACKUP_SHA256"],
    "bytes": int(os.environ["BACKUP_BYTES"]),
    "source_identity": os.environ.get("BEACON_SOURCE_IDENTITY", "unspecified"),
    "schema_identity": os.environ.get("BEACON_SCHEMA_IDENTITY", "unspecified"),
    "image_identity": os.environ.get("BEACON_IMAGE_ID", "unspecified"),
    "copy_complete": False,
}
Path(os.environ["METADATA_PATH"]).write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
PY
mv "$tmp_metadata" "$metadata_path"
destination="none"
if [[ -n "${BEACON_BACKUP_DEST_DIR:-}" ]]; then
  mkdir -p "$BEACON_BACKUP_DEST_DIR"
  destination="$BEACON_BACKUP_DEST_DIR"
  destination_backup="$BEACON_BACKUP_DEST_DIR/$(basename "$backup_path")"
  destination_metadata="$BEACON_BACKUP_DEST_DIR/$(basename "$metadata_path")"
  destination_tmp="$(mktemp "$BEACON_BACKUP_DEST_DIR/.beacon-backup-copy.XXXXXX")"
  destination_metadata_tmp="$(mktemp "$BEACON_BACKUP_DEST_DIR/.beacon-backup-metadata.XXXXXX")"
  rm_destination_temps() { rm -f "$destination_tmp" "$destination_metadata_tmp"; }
  trap 'rm -f "$tmp_path" "$tmp_metadata" "$destination_tmp" "$destination_metadata_tmp"' EXIT HUP INT TERM
  install -m 0600 "$backup_path" "$destination_tmp"
  destination_sha256="$(sha256 "$destination_tmp")"
  destination_bytes="$(wc -c < "$destination_tmp" | tr -d ' ')"
  test "$destination_sha256" = "$backup_sha256" || { echo "Destination backup checksum mismatch" >&2; exit 1; }
  test "$destination_bytes" = "$backup_bytes" || { echo "Destination backup size mismatch" >&2; exit 1; }
  mv "$destination_tmp" "$destination_backup"
  DESTINATION_METADATA="$destination_metadata_tmp" \
  DESTINATION_COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  DESTINATION_SHA256="$destination_sha256" \
  DESTINATION_BYTES="$destination_bytes" \
  SOURCE_METADATA="$metadata_path" python3 - <<'PY'
import json, os
from pathlib import Path

metadata = json.loads(Path(os.environ["SOURCE_METADATA"]).read_text(encoding="utf-8"))
metadata.update(
    copy_complete=True,
    destination_completed_at=os.environ["DESTINATION_COMPLETED_AT"],
    destination_sha256=os.environ["DESTINATION_SHA256"],
    destination_bytes=int(os.environ["DESTINATION_BYTES"]),
)
Path(os.environ["DESTINATION_METADATA"]).write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
PY
  mv "$destination_metadata_tmp" "$destination_metadata"
fi
trap - EXIT HUP INT TERM
echo "BACKUP_OK path=$backup_path sha256=$backup_sha256 bytes=$backup_bytes destination=$destination"
