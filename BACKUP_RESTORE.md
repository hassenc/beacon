# Backup and restore

Follow [the canonical backup and restore guide](docs/backup/README.md). `scripts/backup.sh` encrypts the complete PostgreSQL dump with a separately protected `BEACON_BACKUP_KEY_FILE`, writes atomically, and fails closed on dump or encryption failure. `scripts/restore-check.sh` authenticates the complete archive before `pg_restore` touches a newly named disposable database, then verifies case decryption, evidence hashes and the audit chain.

Never overwrite a running source database. Before exposing a recovered deployment, revoke restored sessions and compare its audit checkpoint with the independently retained checkpoint.
