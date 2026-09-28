# Operating Beacon

## First deployment

1. Complete the release gates. Use a dedicated PostgreSQL database with backed-up storage, a migration owner and a separate `beacon_runtime` login with no role memberships or administrative attributes. Restrict database access to trusted hosts; use `sslmode=verify-full` outside an isolated local network.
2. Generate the encryption key with `beacon keygen`. Generate a separate 32-byte hex `BEACON_BACKUP_KEY_FILE` for backup archives; it must not be the deployment encryption key. Store both outside the database, with separate offline custody. On supported Linux, provision the dedicated directory with `scripts/provision-production-secrets.sh --dir /absolute/dedicated/path --apply`, then rerun it with `--check`. This creates root-owned, GID-65532, mode-0640 files in a mode-0750 directory and proves reads for the runtime/migration UID while denying an unrelated UID. A separately managed PostgreSQL service also uses `postgres_password`. Supply runtime secrets using `DATABASE_URL_FILE`, `BEACON_KEY_FILE`, and `BEACON_SMTP_PASSWORD_FILE`; the migration profile uses `migration_database_url` and `BEACON_ADMIN_PASSWORD_FILE`. Never commit them.
3. With the migration-owner credential and one-time bootstrap email/password, run `beacon migrate`. Apply `deploy/runtime-grants.sql`. Remove the bootstrap password from runtime configuration and use the restricted DSN.
4. Use `deploy/compose.production.yaml` with a reviewed, digest-pinned image, private database DSN, SMTP and real HTTPS origin. Run a host TLS proxy; `deploy/Caddyfile` is a starting configuration. Confirm DNS, certificates, ingress quotas and resource limits on the destination. Inspect `docker inspect`/request logs to determine the immediate proxy address inside the Beacon container, then set only that bridge/gateway CIDR in `BEACON_TRUSTED_PROXY_CIDRS`; never assume the host loopback address or trust all networks.
5. Sign in with the bootstrap password and enroll TOTP before workspace access. Save the ten single-use recovery codes offline. Create a second owner and independently verify recovery. Federated users require an explicitly bound subject and the configured IdP MFA assurance level.
6. Test real SMTP delivery and both reporter and internal workflows using synthetic reports. Review all acceptance gates before collecting private reports.

The runtime refuses database-owner/admin credentials. Runtime startup never applies DDL. Root Compose remains local evaluation only.

## Upgrade and rollback

Stop all Beacon workers and web instances. Take a database backup, retain the current image/configuration and matching encryption key, and restore the backup into an isolated database. Run the new `beacon migrate` there using the migration credential, then `beacon verify-data` and `beacon audit verify`. Test the upgrade before applying it to the stopped primary. Reapply grants for new tables; restart with the runtime credential. Never alter a recorded migration file.

Schema 4 adds identity-generation session binding, explicit notification states, and a forward repair for historical schema-2 cancellation rows. Migration is transactional; allow disk/WAL headroom and a maintenance window. CLI maintenance has a ten-minute timeout. For large installations rehearse capacity and duration; do not assume the 500 GB specification target is validated.

Rollback means restoring the pre-upgrade backup with its matching image and key. There are no destructive down-migrations. Do not start the old alpha against a schema-2 database.

## Key rotation

Stop every instance and back up first. Keep the current key supplied as `BEACON_KEY_FILE` and a new generated key as `BEACON_NEW_KEY_FILE`. Run `beacon rotate-key` using the migration credential. On success replace the active key file and run decryption/audit verification before restarting. Rotation is transactional and revokes all sessions and pending OIDC state. Retain old keys alongside old encrypted backups under separate custody. Do not run rotation concurrently with live application traffic.

## Monitoring and delivery

Check `/healthz`, container restarts, disk/WAL usage, database backup age and restore drills. Alert on worker error logs, `FAILED` notifications, oldest `PENDING` age, and old `created` timestamps. Review the delivery queue each shift. SMTP must support certificate-verified STARTTLS. `ACCEPTED` means the SMTP server accepted the message; it is not proof of human receipt. Messages contain a case reference and sign-in link, never a recovery token or report text.

The outbox is at-least-once: an SMTP server may accept a message just before a worker crashes. A stable Message-ID helps downstream deduplication but cannot guarantee exactly-once delivery. Failed deliveries retry with bounded backoff; the UI supports explicit retries. At startup the scheduler queues the highest elapsed threshold, not a historical flood. Review overdue cases directly even when email is unavailable.

Rate limits are shared in PostgreSQL. Beacon ignores forwarded IP headers unless `BEACON_TRUSTED_PROXY_CIDRS` explicitly contains the immediate proxy; then it uses the rightmost untrusted address in the forwarded chain. Configure proxy and ingress quotas together, and never list an untrusted network. Load/concurrency and 500 GB storage qualification remain separate acceptance tests.

The supported small-pilot intake envelope is four concurrent multipart requests, each capped at 7 MiB, with 1 MiB of multipart memory and a 32 MiB `/tmp` tmpfs. The four-request spill budget is therefore at most roughly 24 MiB before filesystem overhead. Keep the ingress body limit at or below the application limit, monitor tmpfs/database growth, and treat sustained uploads or larger evidence as a capacity review rather than silently increasing the limit.

The local qualification fixture uses these alert candidates: app memory 205 MiB,
proxy memory 102 MiB, database memory 102 MiB and database growth 51 MiB;
hard qualification limits are 256/128/128 MiB and 64 MiB growth. These are
starting points for the supported deployment, not a production guarantee.
Before accepting reports, assign a deployment owner, an alert-response owner,
an out-of-hours escalation owner and a backup owner; configure the actual
monitoring route; trigger each alert; and record human acknowledgement and
escalation timing. No owner or production route is assigned by this document.

The dependency-free `scripts/beacon-monitor.py` is the reference check
runner. Copy `deploy/monitor.env.example` to a private root-owned file and
install `deploy/beacon-monitor.service` and `.timer` only after setting a
real independent alert webhook. The monitor checks health, failed/stale
notifications, verified off-host backup age and disk free space. A backup is
fresh only when its completed sidecar and matching archive are both present;
local-only spool metadata is not accepted as off-host evidence. It keeps
deduplication/recovery state locally, alerts on newly raised conditions even
while another condition remains active, retries failed delivery on the next
run, emits only sanitized condition names and ages, and supports
`--test --fixture` for deterministic receiver tests. Outside explicit test
mode, `BEACON_ALERT_URL` is required and missing/failed delivery does not
consume alert state. A same-host monitor cannot detect total host failure;
pair it with an external observer on an independently managed network.

## Incident, offboarding and retention

Disable a compromised account from Team & deployment; this revokes its sessions. Rotate reporter access on suspected token exposure. Revoke all personal sessions or change password from Account security. For a compromised master key, isolate the service, rotate credentials and key, and assess previously copied data; rotation cannot revoke an attacker's existing copies.

A hold blocks case purge. An owner can purge a closed case with a documented reason and current revision. Live case content, evidence, reporter sessions and notifications are deleted; the audit reference and documented reason remain. Do not put personal information in purge reasons. Backups and externally distributed exports follow the operator's separate retention schedule; database deletion does not remove those copies.

For OIDC provider migration, stop the service, clear/re-provision every subject binding, reset `deployment_secrets.oidc_issuer` with the migration credential, revoke all sessions, then configure the new issuer. Subject identifiers are not portable across issuers.
