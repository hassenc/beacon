#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  echo '.env already exists; leaving it unchanged.'
  exit 0
fi
umask 077
python3 - <<'PY'
import secrets, datetime, pathlib
expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180)).strftime('%Y-%m-%dT%H:%M:%SZ')
values = {
 'POSTGRES_PASSWORD': secrets.token_hex(24),
 'BEACON_KEY': secrets.token_hex(32),
	'BEACON_BACKUP_KEY_FILE': '.beacon-backup.key',
 'BEACON_ADMIN_EMAIL': 'owner@beacon.local',
 'BEACON_ADMIN_PASSWORD': secrets.token_urlsafe(24),
 'BEACON_ORG': 'Beacon Evaluation',
 'BEACON_URL': 'http://localhost:8787',
 'BEACON_DEV': 'true',
 'BEACON_SECURITY_EXPIRES': expiry,
}
pathlib.Path('.env').write_text(''.join(f'{k}="{v}"\n' for k,v in values.items()))
pathlib.Path('.beacon-backup.key').write_text(secrets.token_hex(32) + '\n')
pathlib.Path('.beacon-backup.key').chmod(0o600)
PY
echo 'Created .env and a separate local backup key. Keep both private; use separate custody in production.'
echo 'Run docker compose up --build -d, then open http://localhost:8787.'
