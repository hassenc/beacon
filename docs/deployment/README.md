# Deployment and configuration

For evaluation, use the root README. Root Compose binds only loopback ports 8787 and 55438, persists PostgreSQL, and runs a non-root read-only application container. It is not the production configuration.

For deployment, upgrades, key rotation, monitoring and retention, follow [the operator runbook](../operations/runbook.md). Start from `deploy/compose.production.yaml` and `deploy/runtime-grants.sql`; provision and verify the destination infrastructure before accepting reports.

Reusable operational entry points are `scripts/production-backup.sh`,
`scripts/production-restore.sh` and `scripts/beacon-monitor.py`. Their private
configuration templates and opt-in systemd units are in `deploy/`. The
production backup path requires an explicit database DSN and independently
retained destination; it never falls back to the development Compose stack.

| Variable | Meaning |
|---|---|
| DATABASE_URL | Restricted runtime PostgreSQL DSN; migration command uses owner credential |
| BEACON_KEY | 32-byte encryption key encoded as 64 hexadecimal characters |
| BEACON_NEW_KEY | New key for the offline rotation command only |
| BEACON_ADMIN_EMAIL / BEACON_ADMIN_PASSWORD | One-time initial owner for explicit migration/bootstrap |
| BEACON_URL | Public origin; HTTPS outside loopback development |
| BEACON_ORG | Organization display name |
| BEACON_POLICY | Organization-authored disclosure policy |
| BEACON_SECURITY_EXPIRES | Explicit RFC3339 security.txt expiry |
| BEACON_LISTEN | Listen address; default 127.0.0.1:8787 |
| BEACON_DEV | Literal true for local evaluation; production requires MFA and restricted DB role |
| BEACON_TRUSTED_PROXY_CIDRS | Required in production: comma-separated CIDRs for the immediate proxy peer as seen inside the Beacon container; forwarded client headers are ignored otherwise. With host Caddy and loopback-published Beacon, set the observed Docker bridge/gateway CIDR only after verifying it (never `0.0.0.0/0`). |
| BEACON_SMTP_ADDR / USER / PASSWORD / FROM | SMTP host:port, optional credentials and plain sender address; verified STARTTLS required |
| BEACON_OIDC_ISSUER / CLIENT_ID / CLIENT_SECRET / ACR | HTTPS provider, confidential client credentials and production MFA assurance value |

Secrets support the corresponding `_FILE` form for database URL, encryption keys, bootstrap password, SMTP password and OIDC client secret. Setting both forms is rejected. Never put secret values in an image or repository.

For a Linux file-backed deployment, create the seven files `database_url`,
`migration_database_url`, `encryption_key`, `smtp_password`, `admin_password`
`postgres_password` and `backup.key` in a dedicated directory, then run
`sudo scripts/provision-production-secrets.sh --dir /srv/beacon-secrets --apply`
from a dedicated path permitted by the script. The command assigns group ID
65532, directory mode 0750 and file mode 0640, then tests reads as the
runtime/migration UID 65532 and denial for unrelated UID 65531. It does not
generate or print secret values. Run the same command with `--check` before
starting Compose. The backup key is mounted separately for backup operations;
keep it in separate custody even though the access check covers it.

The production Compose migration profile uses the migration database URL and
bootstrap password file, while the long-running service uses the restricted
runtime database URL. Run `docker compose --profile migration run --rm
migration` only during controlled bootstrap/upgrade work, then remove the
bootstrap secret from the deployment directory according to the operator's
credential-retention policy.

Register the exact OIDC redirect URI `BEACON_URL/auth/callback`. Provision users first and bind their exact subject in Team & deployment. Verify that your IdP's configured ACR actually represents MFA; Beacon cannot infer provider-specific assurance semantics. Issuer changes require explicit operator migration and rebinding.

Schema 4 has checksummed forward migrations and legacy payload conversion. Migration 004 repairs schema-2 cancellation rows without changing the checksum of migration 003. The runtime never migrates in production. Maintenance commands have a ten-minute timeout; rehearse larger upgrades offline. `/healthz` is a database connectivity check, not proof that delivery, backups, human coverage or legal obligations are satisfied.
