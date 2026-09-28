package beacon

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lib/pq"
)

// sessionBoundaryDriver detects the old second user lookup. If Session ever
// regresses to that shape, the hook performs the identity reset at precisely
// the boundary that allowed the old session-loading race.
type sessionBoundaryDriver struct {
	hook  func()
	fired atomic.Bool
}

func (d *sessionBoundaryDriver) Open(name string) (driver.Conn, error) {
	conn, err := (&pq.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &sessionBoundaryConn{Conn: conn, driver: d}, nil
}

type sessionBoundaryConn struct {
	driver.Conn
	driver *sessionBoundaryDriver
}

func (c *sessionBoundaryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "FROM users WHERE id=$1") && !strings.Contains(query, "FOR SHARE") && c.driver.fired.CompareAndSwap(false, true) {
		c.driver.hook()
	}
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

func TestSessionLoadsValidatedActorInSingleQuery(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, err := s.UserByEmail(ctx, "owner@test.local")
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.NewSessionBound(ctx, owner.ID, "", owner.AuthGeneration)
	if err != nil {
		t.Fatal(err)
	}

	var schema string
	if err = s.DB.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("BEACON_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	driverName := "beacon_session_boundary_" + RandomHex(5)
	d := &sessionBoundaryDriver{hook: func() {
		if err := s.ChangePassword(ctx, owner, "test-password-long-enough", "replacement-session-password-long", ""); err != nil {
			t.Fatal(err)
		}
	}}
	sql.Register(driverName, d)
	db, err := sql.Open(driverName, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	reader := &Store{DB: db, Crypto: s.Crypto}
	actor, _, err := reader.Session(ctx, Hash(token))
	if err != nil {
		t.Fatal(err)
	}
	if d.fired.Load() {
		t.Fatal("Session performed a second unbound user lookup")
	}
	if actor.AuthGeneration != owner.AuthGeneration {
		t.Fatalf("session generation = %d, want %d", actor.AuthGeneration, owner.AuthGeneration)
	}

	// Reset after Session has returned. The actor from the validated session
	// must retain its old generation so the following privileged write rejects.
	if err = s.ChangePassword(ctx, owner, "test-password-long-enough", "replacement-session-password-long", ""); err != nil {
		t.Fatal(err)
	}
	added := User{ID: UUID(), Name: "Stale session owner", Email: "stale-session@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}
	if err = s.AddUser(ctx, actor, added); err == nil {
		t.Fatal("old session performed a privileged write after identity reset")
	}
}
