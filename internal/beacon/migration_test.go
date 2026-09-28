package beacon

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"testing"
)

func TestSchemaTwoNotificationStatesAreRepaired(t *testing.T) {
	dsn := os.Getenv("BEACON_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("Set BEACON_TEST_DATABASE_URL for PostgreSQL integration tests")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "migration_" + RandomHex(8)
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	crypto, _ := NewCrypto(make([]byte, 32))
	s, err := OpenStore(context.Background(), u.String(), crypto)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.DB.Close()
		admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		admin.Close()
	})
	ctx := context.Background()
	for _, version := range []int{1, 2} {
		name := migrationName(version)
		body, readErr := migrations.ReadFile("migrations/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = s.DB.Exec(string(body)); err != nil {
			t.Fatalf("schema %d: %v", version, err)
		}
	}
	if _, err = s.DB.Exec("CREATE TABLE migration_ledger(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 2} {
		name := migrationName(version)
		body, _ := migrations.ReadFile("migrations/" + name)
		if _, err = s.DB.Exec("INSERT INTO migration_ledger(version,checksum) VALUES($1,$2)", version, Hash(string(body))); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.DB.Exec(`INSERT INTO notifications(id,dedupe,case_ref,recipient,kind,sent,last_error,attempts) VALUES
		('accepted','accepted','BCN-ACCEPTED',decode('00','hex'),'notice',now(),' ',1),
		('cancelled','cancelled','BCN-CANCELLED',decode('00','hex'),'notice',now(),'Cancelled: recipient access changed',1),
		('pending','pending','BCN-PENDING',decode('00','hex'),'notice',NULL,'',2),
		('failed','failed','BCN-FAILED',decode('00','hex'),'notice',NULL,'Delivery failed',10)`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := s.DB.Query("SELECT id,state FROM notifications ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	want := map[string]string{"accepted": "ACCEPTED", "cancelled": "CANCELLED", "pending": "PENDING", "failed": "FAILED"}
	for rows.Next() {
		var id, state string
		if err = rows.Scan(&id, &state); err != nil {
			t.Fatal(err)
		}
		if state != want[id] {
			t.Fatalf("notification %s migrated to %s, want %s", id, state, want[id])
		}
		delete(want, id)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(want) != 0 {
		t.Fatalf("missing migrated notifications: %v", want)
	}
}

func migrationName(version int) string {
	if version == 1 {
		return "001_initial.sql"
	}
	return "002_hardening.sql"
}
