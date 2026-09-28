#!/usr/bin/env bash
# Real disposable recovery test. It uses the reviewed Beacon binary and a
# disposable PostgreSQL container; it never touches the development database.
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
container="beacon-recovery-$RANDOM-$$"
port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
image="${BEACON_POSTGRES_IMAGE:-postgres:17-alpine}"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM
command -v docker >/dev/null 2>&1 || { echo "docker is required for the real recovery test" >&2; exit 2; }
docker info >/dev/null

docker run -d --name "$container" -e POSTGRES_USER=postgres -e POSTGRES_DB=beacon -e POSTGRES_PASSWORD=test-secret -p "127.0.0.1:$port:5432" "$image" >/dev/null
for _ in $(seq 1 60); do
  if docker exec -u postgres "$container" pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec -u postgres "$container" pg_isready -U postgres >/dev/null

go build -o "$tmp/beacon" ./cmd/beacon
printf '%064d\n' 0 > "$tmp/backup.key"
printf '%064d\n' 1 > "$tmp/app.key"
chmod 0600 "$tmp"/*.key
source_url="postgres://postgres:test-secret@127.0.0.1:$port/beacon?sslmode=disable"
export DATABASE_URL="$source_url" BEACON_KEY_FILE="$tmp/app.key" BEACON_BACKUP_KEY_FILE="$tmp/backup.key"
export BEACON_ADMIN_EMAIL=owner@example.test BEACON_ADMIN_PASSWORD='synthetic-owner-password-123'
export BEACON_SECURITY_EXPIRES=2099-01-01T00:00:00Z
BEACON_DEV=true "$tmp/beacon" migrate
BEACON_DEV=true "$tmp/beacon" seed-demo
docker exec -u postgres "$container" psql -v ON_ERROR_STOP=1 -U postgres -d beacon -c 'CREATE ROLE beacon_runtime NOLOGIN' >/dev/null
case_ref="$(docker exec -u postgres "$container" psql -At -U postgres -d beacon -c 'SELECT ref FROM cases ORDER BY ref LIMIT 1')"
docker exec -u postgres "$container" psql -v ON_ERROR_STOP=1 -U postgres -d beacon -c "INSERT INTO sessions(hash,user_id,case_ref,expires,token_version) VALUES ('synthetic-session','','$case_ref',now()+interval '1 hour',1)" >/dev/null

mkdir -p "$tmp/bin"
cat > "$tmp/bin/pg_dump" <<EOF
#!/usr/bin/env bash
exec docker exec -u postgres $container pg_dump -U postgres -d beacon -Fc
EOF
cat > "$tmp/bin/createdb" <<EOF
#!/usr/bin/env bash
set -eu
exec docker exec -u postgres $container createdb -U postgres "\${@: -1}"
EOF
cat > "$tmp/bin/dropdb" <<EOF
#!/usr/bin/env bash
set -eu
exec docker exec -u postgres $container dropdb -U postgres --if-exists "\${@: -1}"
EOF
cat > "$tmp/bin/pg_restore" <<'EOF'
#!/usr/bin/env bash
set -eu
db=''
args=()
for arg in "$@"; do
  case "$arg" in
    --dbname=*) db="$(python3 - "${arg#--dbname=}" <<'PY'
import sys
from urllib.parse import urlsplit, unquote
print(unquote(urlsplit(sys.argv[1]).path.lstrip('/')))
PY
)" ;;
    *) args+=("$arg") ;;
  esac
done
test -n "$db"
exec docker exec -i -u postgres "$PG_CONTAINER" pg_restore -U postgres --dbname="$db" "${args[@]}"
EOF
cat > "$tmp/bin/psql" <<'EOF'
#!/usr/bin/env bash
set -eu
uri="$1"
shift
db="$(python3 - "$uri" <<'PY'
import sys
from urllib.parse import urlsplit, unquote
print(unquote(urlsplit(sys.argv[1]).path.lstrip('/')))
PY
)"
if [[ "${1:-}" == -v && "${3:-}" == -f ]]; then
  file="$4"
  set -- "$1" "$2" -f -
  exec docker exec -i -u postgres "$PG_CONTAINER" psql -U postgres -d "$db" "$@" < "$file"
fi
exec docker exec -u postgres "$PG_CONTAINER" psql -U postgres -d "$db" "$@"
EOF
chmod +x "$tmp/bin"/*
export PG_CONTAINER="$container"

mkdir -p "$tmp/out" "$tmp/offhost"
mkdir -p "$tmp/staging"
export TMPDIR="$tmp/staging"
cat > "$tmp/backup.env" <<EOF
BEACON_BIN=$tmp/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_PG_SOURCE_DATABASE_URL=$source_url
BEACON_BACKUP_OUTPUT_DIR=$tmp/out
BEACON_BACKUP_DEST_DIR=$tmp/offhost
BEACON_BACKUP_PRUNE=0
BEACON_SOURCE_IDENTITY=real-disposable-postgres
BEACON_SCHEMA_IDENTITY=schema-4
BEACON_IMAGE_ID=test-binary
EOF
PATH="$tmp/bin:$root/scripts:$PATH" "$root/scripts/production-backup.sh" "$tmp/backup.env"
backup_path="$(find "$tmp/offhost" -type f -name 'beacon-*.backup' -print -quit)"
test -n "$backup_path"

cat > "$tmp/restore.env" <<EOF
BEACON_BIN=$tmp/beacon
BEACON_BACKUP_KEY_FILE=$tmp/backup.key
BEACON_KEY_FILE=$tmp/app.key
BEACON_PG_RESTORE_MAINTENANCE_URL=$source_url
BEACON_PG_RESTORE_URL_TEMPLATE=postgres://postgres:test-secret@127.0.0.1:$port/restore-%s?sslmode=disable
BEACON_PG_RESTORE_ADMIN_URL_TEMPLATE=postgres://postgres:test-secret@127.0.0.1:$port/restore-%s?sslmode=disable
BEACON_RUNTIME_GRANTS_FILE=$root/deploy/runtime-grants.sql
BEACON_RESTORE_KEEP=1
EOF

before_count="$(docker exec -u postgres "$container" psql -At -U postgres -d postgres -c "SELECT count(*) FROM pg_database WHERE datname LIKE 'restore-beacon_restore_%'")"
wrong_key="$tmp/wrong.key"
printf '%064d\n' 9 > "$wrong_key"
sed "s#BEACON_BACKUP_KEY_FILE=.*#BEACON_BACKUP_KEY_FILE=$wrong_key#" "$tmp/restore.env" > "$tmp/wrong-restore.env"
wrong_status=0
wrong_output="$(PATH="$tmp/bin:$root/scripts:$PATH" "$root/scripts/production-restore.sh" "$tmp/wrong-restore.env" "$backup_path" 2>&1)" || wrong_status=$?
test "$wrong_status" -ne 0
if ! grep -Eqi 'authentication failed|backup key|decrypt' <<< "$wrong_output"; then
  echo "wrong-key restore failed for an unexpected reason: $wrong_output" >&2
  exit 1
fi
if [[ "$wrong_status" == 0 ]]; then
  echo "wrong-key restore unexpectedly succeeded" >&2
  exit 1
fi
after_wrong_count="$(docker exec -u postgres "$container" psql -At -U postgres -d postgres -c "SELECT count(*) FROM pg_database WHERE datname LIKE 'restore-beacon_restore_%'")"
test "$before_count" = "$after_wrong_count"
test -z "$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d -name 'beacon-restore.*' -print -quit)"
restore_output="$(PATH="$tmp/bin:$root/scripts:$PATH" "$root/scripts/production-restore.sh" "$tmp/restore.env" "$backup_path")"
restore_db="$(sed -n 's/.*database=\([^ ]*\).*/\1/p' <<< "$restore_output")"
test -n "$restore_db"
test "$(docker exec -u postgres "$container" psql -At -U postgres -d "$restore_db" -c 'SELECT count(*) FROM sessions')" = 0
test "$(docker exec -u postgres "$container" psql -At -U postgres -d "$restore_db" -c 'SELECT count(*) FROM cases')" = 6
docker exec -u postgres "$container" dropdb -U postgres "$restore_db"
if find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d -name 'beacon-restore.*' -print -quit | grep -q .; then
  echo "restore staging directory was not cleaned" >&2
  exit 1
fi

corrupt="$tmp/corrupt.backup"
python3 - "$backup_path" "$corrupt" <<'PY'
import pathlib, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_bytes(data[:-1])
PY
corrupt_status=0
corrupt_output="$(PATH="$tmp/bin:$root/scripts:$PATH" "$root/scripts/production-restore.sh" "$tmp/restore.env" "$corrupt" 2>&1)" || corrupt_status=$?
test "$corrupt_status" -ne 0
if ! grep -Eqi 'authentication failed|truncated|checksum' <<< "$corrupt_output"; then
  echo "corrupt restore failed for an unexpected reason: $corrupt_output" >&2
  exit 1
fi
if [[ "$corrupt_status" == 0 ]]; then
  echo "corrupt restore unexpectedly succeeded" >&2
  exit 1
fi
after_corrupt_count="$(docker exec -u postgres "$container" psql -At -U postgres -d postgres -c "SELECT count(*) FROM pg_database WHERE datname LIKE 'restore-beacon_restore_%'")"
test "$before_count" = "$after_corrupt_count"
test -z "$(find "$TMPDIR" -mindepth 1 -maxdepth 1 -type d -name 'beacon-restore.*' -print -quit)"
echo "real production backup/restore: PASS"
