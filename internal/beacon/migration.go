package beacon

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrations embed.FS

const SchemaVersion = 4

func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(72401)"); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS migration_ledger(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		return e
	}
	var latest int
	if e = tx.QueryRowContext(ctx, "SELECT COALESCE(max(version),0) FROM migration_ledger").Scan(&latest); e != nil {
		return e
	}
	if latest > SchemaVersion {
		return errors.New("database schema is newer than this executable")
	}
	entries, e := migrations.ReadDir("migrations")
	if e != nil {
		return e
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, f := range entries {
		v, _ := strconv.Atoi(strings.Split(f.Name(), "_")[0])
		body, e := migrations.ReadFile("migrations/" + f.Name())
		if e != nil {
			return e
		}
		checksum := Hash(string(body))
		var old string
		e = tx.QueryRowContext(ctx, "SELECT checksum FROM migration_ledger WHERE version=$1", v).Scan(&old)
		if e == nil {
			if old != checksum {
				return fmt.Errorf("migration %d checksum mismatch", v)
			}
			continue
		}
		if e != sql.ErrNoRows {
			return e
		}
		if _, e = tx.ExecContext(ctx, string(body)); e != nil {
			return fmt.Errorf("migration %d: %w", v, e)
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO migration_ledger(version,checksum) VALUES($1,$2)", v, checksum); e != nil {
			return e
		}
	}
	var check []byte
	e = tx.QueryRowContext(ctx, "SELECT key_check FROM deployment_secrets WHERE id=1").Scan(&check)
	if e == sql.ErrNoRows {
		check = s.Crypto.Seal([]byte("beacon-key-check-v1"), "deployment")
		_, e = tx.ExecContext(ctx, "INSERT INTO deployment_secrets VALUES(1,$1)", check)
	}
	if e != nil {
		return e
	}
	plain, e := s.Crypto.Open(check, "deployment")
	if e != nil || string(plain) != "beacon-key-check-v1" {
		return errors.New("encryption key does not match deployment")
	}
	if e = s.upgradePayloads(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Ready(ctx context.Context) error {
	var v int
	if e := s.DB.QueryRowContext(ctx, "SELECT max(version) FROM migration_ledger").Scan(&v); e != nil {
		return errors.New("run beacon migrate with the migration database credential first")
	}
	if v != SchemaVersion {
		return fmt.Errorf("schema %d is incompatible with required schema %d", v, SchemaVersion)
	}
	var data []byte
	if e := s.DB.QueryRowContext(ctx, "SELECT key_check FROM deployment_secrets WHERE id=1").Scan(&data); e != nil {
		return e
	}
	plain, e := s.Crypto.Open(data, "deployment")
	if e != nil || string(plain) != "beacon-key-check-v1" {
		return errors.New("encryption key does not match deployment")
	}
	return nil
}
func (s *Store) CheckRuntimeRole(ctx context.Context) error {
	var unsafe bool
	e := s.DB.QueryRowContext(ctx, `SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=pg_roles.oid) OR EXISTS(SELECT 1 FROM pg_class c WHERE c.relowner=pg_roles.oid AND c.relnamespace=current_schema()::regnamespace) FROM pg_roles WHERE rolname=current_user`).Scan(&unsafe)
	if e != nil {
		return e
	}
	if unsafe {
		return errors.New("production runtime must use a non-owner database role without administrative privileges")
	}
	return nil
}
