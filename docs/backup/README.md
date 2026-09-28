# Backup and restore

## What to preserve

1. PostgreSQL snapshot: users, password hashes, case metadata, encrypted reports/messages/attachments, products, sessions and audit chain.
2. The external master key (`BEACON_KEY`), public URL, organization/policy and configuration.
3. An independently retained audit checkpoint.

The data dump alone is insufficient for recovery. Store backups and the keys in separate controlled locations. The supported `scripts/backup.sh` path encrypts the complete custom-format dump with the separate `BEACON_BACKUP_KEY_FILE` using authenticated AES-GCM frames, refuses to publish a backup if dumping or encryption fails, and renames its temporary file only after success. The database is still selectively encrypted at rest; the encrypted archive protects metadata and password hashes too.

## Create and verify an evaluation backup

```sh
./scripts/backup.sh
./scripts/run-local.sh audit verify
./scripts/restore-check.sh
```

`restore-check.sh` creates an encrypted custom-format snapshot, fully authenticates it into a mode-0600 temporary dump, and only then restores it into a newly named database. It verifies all case decryption, evidence SHA-256 hashes and the audit chain, then drops only that temporary database. The primary database is unchanged. It removes both temporary files on exit.

The evaluation scripts use the local Compose `db` service and `go run` by default. For a provisioned PostgreSQL deployment, set `BEACON_BIN` to the reviewed `/beacon` binary, `BEACON_PG_SOURCE_DATABASE_URL` to the backup source, `BEACON_PG_ADMIN_DATABASE_URL` to an administrative database used only to create/drop the isolated restore database, and `BEACON_PG_DATABASE_URL_TEMPLATE` to a DSN containing one literal `%s` where the restore database name belongs. The script then uses native `pg_dump`/`createdb`/`pg_restore`/`dropdb` and does not require a Go toolchain or evaluation Compose database. Without those variables, the Docker `db` service remains an explicit evaluation default.

## Production backup and restore entry points

Use the checked-in examples as templates for private root-owned configuration:

```sh
sudo install -m 0600 deploy/production-backup.env.example /etc/beacon/production-backup.env
sudo /opt/beacon/scripts/production-backup.sh /etc/beacon/production-backup.env
```

Production mode requires an explicit source DSN, reviewed `BEACON_BIN`, separate backup key, local spool and independently retained `BEACON_BACKUP_DEST_DIR`. It copies the authenticated archive to a temporary destination name, verifies checksum and size, then atomically publishes the archive followed by a `copy_complete` sidecar containing only artifact name, timestamp, size, checksum and non-secret source/schema/image identities. Retention pruning is disabled by default; enable it only after agreeing the destination policy, and the script preserves the newest artifact. Set `BEACON_BACKUP_REQUIRE_MOUNT=1` and `BEACON_BACKUP_MOUNTPOINT` for a fail-closed exact mountpoint check; `findmnt -T` on a child path alone is not sufficient.

The opt-in systemd example is `deploy/beacon-backup.service` plus
`deploy/beacon-backup.timer`. It is deliberately not enabled by installation.
The backup destination should be an already-mounted off-host path or a
storage mount managed by the host; this repository does not invent credentials
or silently create a cloud resource.

To validate an existing retained backup without touching the source:

```sh
/opt/beacon/scripts/production-restore.sh /etc/beacon/production-restore.env /mnt/offhost/beacon/beacon-YYYYMMDDTHHMMSS-123.backup
```

The restore command authenticates the complete archive before creating a
random `beacon_restore_*` database, restores with `--no-owner`, reapplies the
runtime grants, deletes restored sessions, verifies the audit chain and all
encrypted case/evidence data, and drops the isolated database unless
`BEACON_RESTORE_KEEP=1` is explicitly set. It never starts Beacon or SMTP.
The maintenance, admin and runtime DSNs are separate explicit configuration
values. They must be URI DSNs on the same server, with one `%s` in the database
path; the runtime and admin templates must resolve to the same generated
database. The validator rejects query-string database selection and a
configured source database reuse, so the source database cannot be selected as
the destination.

For a real disposable dependency check, run
`scripts/test-production-recovery.sh`. It starts a temporary PostgreSQL
container, seeds synthetic cases, performs an actual encrypted backup and
restore with the reviewed Beacon binary, verifies restored data/audit and
session revocation, exercises wrong-key and corruption rejection, and removes
the container. It does not use the deployment host or send mail.

## Manual restoration to a new instance

Start a new PostgreSQL database of the supported major version. Stop the application on that destination. Restore with `pg_restore --no-owner` into the empty database; set DATABASE_URL to the destination and provide the original BEACON_KEY through a secure mechanism. Run `beacon audit verify` and `beacon verify-data`, comparing the audit checkpoint with the independently retained original. Run `beacon migrate` using the migration credential if upgrading, then reapply runtime grants. Start Beacon with the runtime credential and complete a synthetic reporter and team sign-in drill.

Revoke restored sessions before exposing a recovered deployment (delete from the sessions table on the destination under a documented maintenance operation). Do not overwrite a running source database. Attachment bytes are included in the database snapshot in schema 4; when storage is externalized, the backup process must be revised to preserve a consistent DB/object-store snapshot.

The archive format is Beacon Backup V2: a random archive identifier and sequence number authenticate every AES-GCM frame, and an authenticated final frame records the complete plaintext length. Truncation, frame reordering/duplication, cross-archive splicing, trailing bytes and an invalid completion frame are rejected. V1 archives are intentionally not accepted; regenerate them with the current backup command.

These procedures validate local PostgreSQL recovery. They do not yet demonstrate a fresh Linux production install or upgrades between released application versions.
