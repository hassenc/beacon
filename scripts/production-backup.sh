#!/usr/bin/env bash
# Production backup wrapper. The destination must be an already-mounted,
# independently retained path; this script never deletes old backups.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
config_file="${1:?Usage: production-backup.sh /path/to/backup.env}"
test -r "$config_file" || { echo "Cannot read configuration file: $config_file" >&2; exit 1; }
set -a
. "$config_file"
set +a
: "${BEACON_BACKUP_DEST_DIR:?Set an off-host or independently retained BEACON_BACKUP_DEST_DIR}"
: "${BEACON_BACKUP_RETENTION_DAYS:=35}"
: "${BEACON_BACKUP_OUTPUT_DIR:=/var/lib/beacon/backups}"
: "${BEACON_BACKUP_PRUNE:=0}"
: "${BEACON_BACKUP_REQUIRE_MOUNT:=0}"
case "$BEACON_BACKUP_DEST_DIR" in
  /*) ;;
  *) echo "BEACON_BACKUP_DEST_DIR must be an absolute path" >&2; exit 1 ;;
esac
test "$BEACON_BACKUP_DEST_DIR" != "$BEACON_BACKUP_OUTPUT_DIR" || { echo "Backup destination must be separate from the local spool" >&2; exit 1; }
if [[ "$BEACON_BACKUP_REQUIRE_MOUNT" == 1 ]]; then
  command -v findmnt >/dev/null 2>&1 || { echo "findmnt is required when BEACON_BACKUP_REQUIRE_MOUNT=1" >&2; exit 1; }
  : "${BEACON_BACKUP_MOUNTPOINT:?Set BEACON_BACKUP_MOUNTPOINT when BEACON_BACKUP_REQUIRE_MOUNT=1}"
  case "$BEACON_BACKUP_DEST_DIR" in
    "$BEACON_BACKUP_MOUNTPOINT"|"$BEACON_BACKUP_MOUNTPOINT"/*) ;;
    *) echo "Backup destination must be under BEACON_BACKUP_MOUNTPOINT" >&2; exit 1 ;;
  esac
  findmnt --mountpoint "$BEACON_BACKUP_MOUNTPOINT" >/dev/null 2>&1 || { echo "Backup mountpoint is not currently mounted" >&2; exit 1; }
fi
BEACON_CONFIG_FILE="$config_file" \
BEACON_BACKUP_MODE=production \
BEACON_BACKUP_OUTPUT_DIR="$BEACON_BACKUP_OUTPUT_DIR" \
  ./scripts/backup.sh

# Retention is opt-in. When enabled, preserve the newest artifact in each
# directory and remove its sidecar together with it; never prune by default
# against an existing off-host destination.
prune_dir() {
  local dir="$1"
  [[ "$BEACON_BACKUP_PRUNE" == 1 ]] || return 0
  [[ -d "$dir" ]] || return 0
  mapfile -t old_backups < <(find "$dir" -type f -name 'beacon-*.backup' -mtime "+$BEACON_BACKUP_RETENTION_DAYS" -print | sort)
  mapfile -t all_backups < <(find "$dir" -type f -name 'beacon-*.backup' -print)
  local remaining="${#all_backups[@]}"
  for old in "${old_backups[@]}"; do
    (( remaining > 1 )) || break
    echo "Pruning expired backup $old"
    rm -f -- "$old" "${old%.backup}.json"
    ((remaining -= 1))
  done
}
prune_dir "$BEACON_BACKUP_OUTPUT_DIR"
prune_dir "$BEACON_BACKUP_DEST_DIR"
