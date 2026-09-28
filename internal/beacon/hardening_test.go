package beacon

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pquerna/otp/totp"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lib/pq"
)

func sampleCase() Case {
	return Case{ID: UUID(), Ref: NewReference(), Title: "Synthetic", Status: "NEW", Severity: "UNKNOWN", Created: time.Now().UTC(), Updated: time.Now().UTC(), Revision: 1, Payload: Payload{Description: "private report", Steps: "steps", Impact: "impact", Attachments: []Attachment{{ID: UUID(), Name: "sample.txt", SHA256: Hash("evidence bytes"), Data: []byte("evidence bytes"), Visibility: "REPORTER_VISIBLE"}}}}
}
func TestMFAAndLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u, _ := s.UserByEmail(ctx, "owner@test.local")
	oldSession, _ := s.NewSession(ctx, u.ID, "")
	secret, _, e := s.BeginMFA(ctx, u, "test-password-long-enough")
	if e != nil {
		t.Fatal(e)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	codes, e := s.ConsumeMFA(ctx, u.ID, code, true)
	if e != nil || len(codes) != 10 {
		t.Fatal(e)
	}
	if _, _, e = s.Session(ctx, Hash(oldSession)); e == nil {
		t.Fatal("enrollment did not revoke old session")
	}
	if _, e = s.ConsumeMFA(ctx, u.ID, code, false); e == nil {
		t.Fatal("TOTP replay accepted")
	}
	if _, e = s.ConsumeMFA(ctx, u.ID, codes[0], false); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ConsumeMFA(ctx, u.ID, codes[0], false); e == nil {
		t.Fatal("recovery code reused")
	}
	u, e = s.User(ctx, u.ID)
	if e != nil {
		t.Fatal(e)
	}
	v := User{ID: UUID(), Name: "Engineer", Email: "engineer@test.local", Role: "ENGINEER", Password: PasswordHash("temporary-test-password")}
	if e = s.AddUser(ctx, u, v); e != nil {
		t.Fatal(e)
	}
	sess, _ := s.NewSession(ctx, v.ID, "")
	if e = s.ManageUser(ctx, u, v.ID, "VIEWER", "", true); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Session(ctx, Hash(sess)); e == nil {
		t.Fatal("disabled user retained session")
	}
	if e = s.ManageUser(ctx, u, u.ID, "VIEWER", "", true); e == nil {
		t.Fatal("owner disabled itself")
	}
}

func TestStaleGenerationCannotCompleteMFAEnrollment(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")
	secret, _, err := s.BeginMFA(ctx, owner, "test-password-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.ChangePassword(ctx, owner, "test-password-long-enough", "replacement-test-password-long-enough", ""); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, err = s.ConsumeMFABound(ctx, owner.ID, code, true, owner.AuthGeneration); err == nil {
		t.Fatal("stale generation completed MFA enrollment")
	}
	current, err := s.User(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.MFAEnabled {
		t.Fatal("denied stale MFA enrollment changed account state")
	}
}
func TestReporterRotationAndPurge(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u, _ := s.UserByEmail(ctx, "owner@test.local")
	c := sampleCase()
	if e := s.CreateCase(ctx, c, "old-token"); e != nil {
		t.Fatal(e)
	}
	sess, _ := s.NewSession(ctx, "", c.Ref)
	next, e := s.RotateReporter(ctx, c.Ref, "reporter")
	if e != nil {
		t.Fatal(e)
	}
	if s.CheckRecovery(ctx, c.Ref, "old-token") || !s.CheckRecovery(ctx, c.Ref, next) {
		t.Fatal("rotation failed")
	}
	if _, _, e = s.Session(ctx, Hash(sess)); e == nil {
		t.Fatal("old reporter session survived")
	}
	newSession, e := s.NewSession(ctx, "", c.Ref)
	if e != nil {
		t.Fatal(e)
	}
	if _, ref, e := s.Session(ctx, Hash(newSession)); e != nil || ref != c.Ref {
		t.Fatal("new token session unusable", e)
	}
	if e = s.PurgeCase(ctx, u, c.Ref, c.Revision, "retention decision"); e == nil {
		t.Fatal("open case purged")
	}
	e = s.ChangeCase(ctx, u, c.Ref, 1, "test.close", func(c *Case) error { c.Status = "CLOSED"; c.LegalHold = true; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if s.PurgeCase(ctx, u, c.Ref, 2, "retention decision") == nil {
		t.Fatal("held case purged")
	}
	e = s.ChangeCase(ctx, u, c.Ref, 2, "test.release", func(c *Case) error { c.LegalHold = false; return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = s.PurgeCase(ctx, u, c.Ref, 3, "retention decision"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Case(ctx, c.Ref); e != sql.ErrNoRows {
		t.Fatal("case retained")
	}
	if _, e = s.Evidence(ctx, c.Ref, c.Payload.Attachments[0].ID); e != sql.ErrNoRows {
		t.Fatal("file retained")
	}
	if _, _, e = s.Verify(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestRecoveryProofIsBoundToRotation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := sampleCase()
	if err := s.CreateCase(ctx, c, "old-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateReporter(ctx, c.Ref, "reporter"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecoverSession(ctx, c.Ref, "old-token"); err == nil {
		t.Fatal("recovery proof from before rotation was accepted")
	}
}

func TestStaleActorCannotPerformPrivilegedWrite(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")
	second := User{ID: UUID(), Name: "Second owner", Email: "second-owner@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}
	if err := s.AddUser(ctx, owner, second); err != nil {
		t.Fatal(err)
	}
	second, _ = s.User(ctx, second.ID)
	if err := s.ManageUser(ctx, owner, owner.ID, "OWNER", "", true); err == nil {
		t.Fatal("last owner could be disabled")
	}
	// Disabling the actor is allowed after a second owner exists.
	if err := s.ManageUser(ctx, second, owner.ID, "OWNER", "", true); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, owner, User{ID: UUID(), Name: "Should fail", Email: "stale@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}); err == nil {
		t.Fatal("stale disabled actor performed privileged write")
	}
}

func TestStaleGenerationCannotPerformPrivilegedWrite(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")
	second := User{ID: UUID(), Name: "Second owner", Email: "generation-owner@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}
	if err := s.AddUser(ctx, owner, second); err != nil {
		t.Fatal(err)
	}

	// Model a request that authenticated before the password change committed.
	if err := s.ChangePassword(ctx, owner, "test-password-long-enough", "replacement-test-password-long-enough", ""); err != nil {
		t.Fatal(err)
	}
	newUser := User{ID: UUID(), Name: "Stale owner", Email: "stale-generation@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}
	if err := s.AddUser(ctx, owner, newUser); err == nil {
		t.Fatal("stale generation performed privileged write")
	}
	if _, err := s.User(ctx, newUser.ID); err == nil {
		t.Fatal("denied stale write created a user")
	}
}

func TestStaleActorCannotPerformCaseManagerAction(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")
	second := User{ID: UUID(), Name: "Second owner", Email: "second-case-owner@test.local", Role: "OWNER", Password: PasswordHash("another-long-test-password")}
	if err := s.AddUser(ctx, owner, second); err != nil {
		t.Fatal(err)
	}
	second, _ = s.User(ctx, second.ID)
	c := sampleCase()
	c.Owner = owner.ID
	if err := s.CreateCase(ctx, c, "token"); err != nil {
		t.Fatal(err)
	}
	// The actor remains active and assigned, but is demoted before the callback.
	stale := owner
	if err := s.ManageUser(ctx, second, owner.ID, "ENGINEER", "", false); err != nil {
		t.Fatal(err)
	}
	current, err := s.User(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the generation current so this test reaches the manager-only callback
	// and verifies role enforcement independently of generation enforcement.
	stale.AuthGeneration = current.AuthGeneration
	var before int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE object=$1", c.Ref).Scan(&before); err != nil {
		t.Fatal(err)
	}
	err = s.ChangeCaseWithActor(ctx, stale, c.Ref, c.Revision, "case.hold", func(c *Case, actor User) error {
		if !CanManage(actor) {
			return errors.New("Owner/Triage access required")
		}
		c.LegalHold = true
		return nil
	})
	if err == nil {
		t.Fatal("stale manager performed case action")
	}
	got, err := s.Case(ctx, c.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.LegalHold {
		t.Fatal("denied action mutated case")
	}
	var after int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE object=$1", c.Ref).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("denied action recorded an audit event")
	}
}

func TestFullExportIncludesUncappedCaseHistory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")
	c := sampleCase()
	c.Payload.Attachments = nil
	if err := s.CreateCase(ctx, c, "token"); err != nil {
		t.Fatal(err)
	}
	const formerExportCap = 100000
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var previous string
		if err := tx.QueryRowContext(ctx, "SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1").Scan(&previous); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT nextval(pg_get_serial_sequence('audit_events','sequence')) FROM generate_series(1,$1)", formerExportCap+1)
		if err != nil {
			return err
		}
		sequences := make([]int64, 0, formerExportCap+1)
		for rows.Next() {
			var sequence int64
			if err := rows.Scan(&sequence); err != nil {
				rows.Close()
				return err
			}
			sequences = append(sequences, sequence)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		at := time.Now().UTC().Truncate(time.Microsecond)
		times := make([]time.Time, 0, len(sequences))
		actors := make([]string, 0, len(sequences))
		actions := make([]string, 0, len(sequences))
		objects := make([]string, 0, len(sequences))
		metadata := make([]string, 0, len(sequences))
		previouses := make([]string, 0, len(sequences))
		hashes := make([]string, 0, len(sequences))
		for i, sequence := range sequences {
			event := AuditEvent{Sequence: sequence, At: at.Add(time.Duration(i) * time.Microsecond), Actor: owner.ID, Action: "case.history", Object: c.Ref, Metadata: fmt.Sprintf("History %d", i), Previous: previous}
			event.Hash = eventHash(event)
			times = append(times, event.At)
			actors = append(actors, event.Actor)
			actions = append(actions, event.Action)
			objects = append(objects, event.Object)
			metadata = append(metadata, event.Metadata)
			previouses = append(previouses, event.Previous)
			hashes = append(hashes, event.Hash)
			previous = event.Hash
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(sequence,at,actor,action,object,metadata,previous,hash) OVERRIDING SYSTEM VALUE
			SELECT * FROM unnest($1::bigint[],$2::timestamptz[],$3::text[],$4::text[],$5::text[],$6::text[],$7::text[],$8::text[])`,
			pq.Array(sequences), pq.Array(times), pq.Array(actors), pq.Array(actions), pq.Array(objects), pq.Array(metadata), pq.Array(previouses), pq.Array(hashes))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.Case(ctx, c.Ref)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.ExportSnapshot(ctx, owner, c.Ref, current.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Audit) <= formerExportCap {
		t.Fatalf("full export returned only %d audit events; expected more than former cap", len(snapshot.Audit))
	}
	if snapshot.Case.Revision != current.Revision {
		t.Fatalf("export revision boundary = %d, want %d", snapshot.Case.Revision, current.Revision)
	}
	if len(snapshot.Audit) < 2 || snapshot.Audit[0].Action != "case.created" || snapshot.Audit[len(snapshot.Audit)-1].Action != "case.exported" {
		t.Fatal("export did not preserve the case history boundary events")
	}
	for i, event := range snapshot.Audit {
		if event.Hash == "" || event.Hash != eventHash(event) {
			t.Fatalf("audit event %d has an invalid hash", i)
		}
		if i > 0 && event.Previous != snapshot.Audit[i-1].Hash {
			t.Fatalf("audit event %d does not link to the previous exported event", i)
		}
	}
}

type exportQueryGateDriver struct {
	hook  func()
	fired atomic.Bool
}

func (d *exportQueryGateDriver) Open(name string) (driver.Conn, error) {
	conn, err := (&pq.Driver{}).Open(name)
	if err != nil {
		return nil, err
	}
	return &exportQueryGateConn{Conn: conn, driver: d}, nil
}

type exportQueryGateConn struct {
	driver.Conn
	driver *exportQueryGateDriver
}

func (c *exportQueryGateConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "SELECT data FROM cases WHERE ref=$1 FOR UPDATE") && c.driver.fired.CompareAndSwap(false, true) {
		c.driver.hook()
	}
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

func gatedExportStore(t *testing.T, s *Store, hook func()) *Store {
	t.Helper()
	var schema string
	if err := s.DB.QueryRow("SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	dsn, err := url.Parse(os.Getenv("BEACON_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	query := dsn.Query()
	query.Set("search_path", schema)
	dsn.RawQuery = query.Encode()
	driverName := "beacon_export_boundary_" + RandomHex(5)
	sql.Register(driverName, &exportQueryGateDriver{hook: hook})
	db, err := sql.Open(driverName, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Store{DB: db, Crypto: s.Crypto}
}

func waitForExportGate(t *testing.T, gate <-chan struct{}) {
	t.Helper()
	select {
	case <-gate:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reaching the controlled export race boundary")
	}
}

func assertExportEvidence(t *testing.T, snapshot CaseExportSnapshot, c Case) {
	t.Helper()
	evidence, ok := snapshot.Evidence[c.Payload.Attachments[0].ID]
	if !ok || !bytes.Equal(evidence, []byte("evidence bytes")) {
		t.Fatal("export did not preserve the synthetic evidence bytes")
	}
	if Hash(string(evidence)) != c.Payload.Attachments[0].SHA256 {
		t.Fatal("exported evidence hash does not match the attachment manifest")
	}
	if len(snapshot.Audit) < 2 || snapshot.Audit[len(snapshot.Audit)-1].Action != "case.exported" {
		t.Fatal("export did not end at its case.exported audit boundary")
	}
	for i, event := range snapshot.Audit {
		if event.Object != c.Ref || event.Hash == "" || event.Hash != eventHash(event) {
			t.Fatalf("audit event %d is not a valid event for the exported case", i)
		}
		if i > 0 && event.Previous != snapshot.Audit[i-1].Hash {
			t.Fatalf("audit event %d is not linked to the preceding exported event", i)
		}
	}
}

func TestExportSnapshotSerializesConcurrentEdit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")

	run := func(t *testing.T, exportFirst bool) {
		t.Helper()
		c := sampleCase()
		if err := s.CreateCase(ctx, c, "token-"+c.Ref); err != nil {
			t.Fatal(err)
		}
		current, err := s.Case(ctx, c.Ref)
		if err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		boundary := gatedExportStore(t, s, func() { close(gate) })
		type exportResult struct {
			snapshot CaseExportSnapshot
			err      error
		}
		exported := make(chan exportResult, 1)
		edited := make(chan error, 1)
		if exportFirst {
			go func() {
				snapshot, err := boundary.ExportSnapshot(ctx, owner, c.Ref, current.Revision)
				exported <- exportResult{snapshot: snapshot, err: err}
			}()
			waitForExportGate(t, gate)
			go func() {
				edited <- s.ChangeCase(ctx, owner, c.Ref, current.Revision, "case.edited", func(updated *Case) error {
					updated.Title = "Concurrent edit"
					return nil
				})
			}()
		} else {
			go func() {
				edited <- boundary.ChangeCase(ctx, owner, c.Ref, current.Revision, "case.edited", func(updated *Case) error {
					updated.Title = "Concurrent edit"
					return nil
				})
			}()
			waitForExportGate(t, gate)
			go func() {
				snapshot, err := s.ExportSnapshot(ctx, owner, c.Ref, current.Revision)
				exported <- exportResult{snapshot: snapshot, err: err}
			}()
		}
		editErr := <-edited
		export := <-exported
		if editErr != nil {
			t.Fatal(editErr)
		}
		if exportFirst {
			if export.err != nil {
				t.Fatal(export.err)
			}
			if export.snapshot.Case.Revision != current.Revision || export.snapshot.Case.Title != c.Title {
				t.Fatal("export-first snapshot crossed the edit boundary")
			}
			assertExportEvidence(t, export.snapshot, c)
		} else if export.err == nil || !strings.Contains(export.err.Error(), "case changed") {
			t.Fatalf("mutation-first export did not reject its stale revision: %v", export.err)
		}
	}

	t.Run("export-first", func(t *testing.T) { run(t, true) })
	t.Run("mutation-first", func(t *testing.T) { run(t, false) })
}

func TestExportSnapshotSerializesConcurrentPurge(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, _ := s.UserByEmail(ctx, "owner@test.local")

	run := func(t *testing.T, exportFirst bool) {
		t.Helper()
		c := sampleCase()
		if err := s.CreateCase(ctx, c, "token-"+c.Ref); err != nil {
			t.Fatal(err)
		}
		current, err := s.Case(ctx, c.Ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeCase(ctx, owner, c.Ref, current.Revision, "case.closed", func(updated *Case) error {
			updated.Status = "CLOSED"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		current, err = s.Case(ctx, c.Ref)
		if err != nil {
			t.Fatal(err)
		}
		gate := make(chan struct{})
		boundary := gatedExportStore(t, s, func() { close(gate) })
		type exportResult struct {
			snapshot CaseExportSnapshot
			err      error
		}
		exported := make(chan exportResult, 1)
		purged := make(chan error, 1)
		if exportFirst {
			go func() {
				snapshot, err := boundary.ExportSnapshot(ctx, owner, c.Ref, current.Revision)
				exported <- exportResult{snapshot: snapshot, err: err}
			}()
			waitForExportGate(t, gate)
			go func() {
				purged <- s.PurgeCase(ctx, owner, c.Ref, current.Revision, "concurrent purge qualification")
			}()
		} else {
			go func() {
				purged <- boundary.PurgeCase(ctx, owner, c.Ref, current.Revision, "concurrent purge qualification")
			}()
			waitForExportGate(t, gate)
			go func() {
				snapshot, err := s.ExportSnapshot(ctx, owner, c.Ref, current.Revision)
				exported <- exportResult{snapshot: snapshot, err: err}
			}()
		}
		purgeErr := <-purged
		export := <-exported
		if purgeErr != nil {
			t.Fatal(purgeErr)
		}
		if exportFirst {
			if export.err != nil {
				t.Fatal(export.err)
			}
			if export.snapshot.Case.Revision != current.Revision || export.snapshot.Case.Status != "CLOSED" {
				t.Fatal("export-first snapshot crossed the purge boundary")
			}
			assertExportEvidence(t, export.snapshot, c)
		} else if export.err == nil || !strings.Contains(export.err.Error(), "no rows") {
			t.Fatalf("purge-first export did not reject its missing case: %v", export.err)
		}
	}

	t.Run("export-first", func(t *testing.T) { run(t, true) })
	t.Run("purge-first", func(t *testing.T) { run(t, false) })
}

type fakeMail struct {
	mu       sync.Mutex
	messages []string
	fail     bool
}

func (f *fakeMail) Send(ctx context.Context, to, id, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("simulated smtp failure")
	}
	f.messages = append(f.messages, to+subject+body)
	return nil
}
func TestOutboxRetryAndDeduplication(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := sampleCase()
	c.Payload.Email = "reporter@test.local"
	c.CRA = &CRA{Classification: "VULNERABILITY", Awareness: time.Now().Add(-23 * time.Hour), Policy: DefaultPolicy()}
	if e := s.CreateCase(ctx, c, "token"); e != nil {
		t.Fatal(e)
	}
	if e := s.ScheduleDeadlines(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	var n int
	s.DB.QueryRow("SELECT count(*) FROM notifications").Scan(&n)
	if e := s.ScheduleDeadlines(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	u, _ := s.UserByEmail(ctx, "owner@test.local")
	if e := s.ChangeCase(ctx, u, c.Ref, 1, "case.assessment", func(c *Case) error { c.Title = "Edited title"; return nil }); e != nil {
		t.Fatal(e)
	}
	if e := s.ScheduleDeadlines(ctx, time.Now()); e != nil {
		t.Fatal(e)
	}
	var n2 int
	s.DB.QueryRow("SELECT count(*) FROM notifications").Scan(&n2)
	if n != n2 {
		t.Fatal("duplicate scheduled notifications")
	}
	sender := &fakeMail{fail: true}
	if _, e := s.DeliverOne(ctx, sender, "https://security.example.com"); e != nil {
		t.Fatal(e)
	}
	var attempts int
	s.DB.QueryRow("SELECT max(attempts) FROM notifications").Scan(&attempts)
	if attempts != 1 {
		t.Fatal("failed attempt not counted")
	}
	sender.fail = false
	s.DB.Exec("UPDATE notifications SET available=now()")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				found, e := s.DeliverOne(ctx, sender, "https://security.example.com")
				if e != nil {
					t.Error(e)
					return
				}
				if !found {
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(sender.messages) != n {
		t.Fatalf("delivery count %d vs %d", len(sender.messages), n)
	}
	for _, msg := range sender.messages {
		if strings.Contains(msg, "private report") || strings.Contains(msg, "evidence bytes") {
			t.Fatal("email leaked case details")
		}
	}
	if _, e := s.DB.Exec("UPDATE notifications SET state='FAILED'"); e != nil {
		t.Fatal(e)
	}
	failed, stale, e := s.NotificationAlert(ctx)
	if e != nil || failed != n || stale != 0 {
		t.Fatalf("queue health alert mismatch: failed=%d stale=%d want failed=%d", failed, stale, n)
	}
}
func TestEnvelopeRotationAndMigrationLedger(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := sampleCase()
	if e := s.CreateCase(ctx, c, "token"); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	s.DB.QueryRow("SELECT data FROM cases WHERE ref=$1", c.Ref).Scan(&raw)
	if bytes.Contains(raw, []byte("evidence bytes")) {
		t.Fatal("unencrypted file")
	}
	c2, e := s.Case(ctx, c.Ref)
	if e != nil || c2.Payload.Attachments[0].Data != nil {
		t.Fatal("case read loaded evidence", e)
	}
	key := bytes.Repeat([]byte{3}, 32)
	next, _ := NewCrypto(key)
	if e = s.RotateKey(ctx, next); e != nil {
		t.Fatal(e)
	}
	if s.Ready(ctx) == nil {
		t.Fatal("old key still accepted")
	}
	fresh := &Store{DB: s.DB, Crypto: next}
	if e = fresh.Ready(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = fresh.VerifyData(ctx); e != nil {
		t.Fatal(e)
	}
	data, e := fresh.Evidence(ctx, c.Ref, c.Payload.Attachments[0].ID)
	if e != nil || string(data) != "evidence bytes" {
		t.Fatal("rotation corrupted evidence", e)
	}
	if e = fresh.Migrate(ctx); e != nil {
		t.Fatal("idempotent migration failed", e)
	}
	s.DB.Exec("UPDATE migration_ledger SET checksum='tampered' WHERE version=1")
	if fresh.Migrate(ctx) == nil {
		t.Fatal("changed migration accepted")
	}
}
func TestPacketDoesNotLeakPrivateContext(t *testing.T) {
	c := sampleCase()
	c.Payload.Email = "private@example.com"
	c.Payload.Messages = []Message{{Visibility: "INTERNAL", Body: "private-legal-deliberation"}}
	c.CRA = &CRA{ConfirmedBy: "private-user-id", Filings: []Filing{{Notes: "private-filing-note", RecordedBy: "private-user-id"}}, Changes: []AwarenessChange{{Reason: "private-correction"}}}
	b, _ := json.Marshal(BuildPacket(c, "Example"))
	for _, v := range []string{"private@example.com", "private-legal", "private-user-id", "private-filing", "private-correction", "evidence bytes"} {
		if bytes.Contains(b, []byte(v)) {
			t.Fatalf("packet leaked %s", v)
		}
	}
}
func TestProductionRequiresMFA(t *testing.T) {
	s := testStore(t)
	u, _ := s.UserByEmail(context.Background(), "owner@test.local")
	token, _ := s.NewSession(context.Background(), u.ID, "")
	app, e := NewApp(s, Config{URL: "https://security.example.com", Organization: "Example", Expires: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "/app", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-beacon_session", Value: token})
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/account/security" {
		t.Fatal("unenrolled local user accessed production workspace")
	}
}

func TestAlphaPayloadUpgrade(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := sampleCase()
	// Re-create the alpha representation without wrapped keys or detached evidence.
	payload, _ := json.Marshal(c.Payload)
	meta := c
	meta.Payload = Payload{}
	raw, _ := json.Marshal(diskCase{Case: meta, Encrypted: s.Crypto.Seal(payload, c.ID)})
	// Read the original encoding AAD from the compatibility decoder: case ID.
	if _, e := s.DB.Exec("INSERT INTO cases(ref,token_hash,data) VALUES($1,$2,$3)", c.Ref, Hash("old"), raw); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	got, e := s.Case(ctx, c.Ref)
	if e != nil || got.Payload.Description != c.Payload.Description || got.Payload.Attachments[0].Data != nil {
		t.Fatal("legacy case not upgraded", e)
	}
	b, e := s.Evidence(ctx, c.Ref, c.Payload.Attachments[0].ID)
	if e != nil || string(b) != "evidence bytes" {
		t.Fatal("legacy evidence lost", e)
	}
}
func TestQueueBeyondThousand(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	u, _ := s.UserByEmail(ctx, "owner@test.local")
	c := sampleCase()
	c.Title = "Oldest findable report"
	c.Created = time.Now().Add(-time.Hour)
	c.Payload.Attachments = nil
	if e := s.CreateCase(ctx, c, "token"); e != nil {
		t.Fatal(e)
	}
	// Representative metadata volume; synthetic rows remain inside an isolated test schema.
	b, _ := s.encode(sampleCase())
	_, e := s.DB.Exec(`INSERT INTO cases(ref,token_hash,data) SELECT 'LOAD-'||n, 'hash-'||n,$1::jsonb FROM generate_series(1,10000) n`, b)
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	cs, total, e := s.Queue(ctx, u, "Oldest findable", "", 1)
	if e != nil || total != 1 || len(cs) != 1 || cs[0].Ref != c.Ref {
		t.Fatal("old report missing", e, total)
	}
	t.Logf("10,001-case search: %s", time.Since(start))
	cs, total, e = s.Queue(ctx, u, "", "", 1)
	if e != nil || total != 10001 || len(cs) != 50 {
		t.Fatal("page bounds", e, total, len(cs))
	}
	engineer := User{ID: UUID(), Role: "ENGINEER"}
	cs, total, e = s.Queue(ctx, engineer, "", "", 1)
	if e != nil || total != 0 || len(cs) != 0 {
		t.Fatal("unauthorized search result", e)
	}
}
func TestPersistentRateLimits(t *testing.T) {
	s := testStore(t)
	cfg := Config{URL: "http://localhost:8787", Organization: "Test", Dev: true, Expires: time.Now().Add(time.Hour)}
	a, e := NewApp(s, cfg)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewApp(s, cfg)
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "/login", nil)
	if !a.allow(r, "test", 1) || b.allow(r, "test", 1) {
		t.Fatal("rate limit did not span instances")
	}
}

func TestFormSecurityPolicySupportsBrowserOriginChecks(t *testing.T) {
	s := testStore(t)
	app, err := NewApp(s, Config{URL: "http://localhost:8787", Organization: "Test", Dev: true, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/report", nil))
	if got := w.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Fatalf("browser-compatible referrer policy = %q", got)
	}
}

func TestPublicPostAdmissionIsBounded(t *testing.T) {
	s := testStore(t)
	app, err := NewApp(s, Config{URL: "http://localhost:8787", Organization: "Test", Dev: true, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := strings.Repeat("x", maxPostBody+1)
	r := httptest.NewRequest("POST", "/unknown", strings.NewReader(tooLarge))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("oversized URL-encoded body returned %d", w.Code)
	}
	for i := 0; i < maxConcurrentUpload; i++ {
		app.uploadSlots <- struct{}{}
	}
	var multipartBody bytes.Buffer
	mw := multipart.NewWriter(&multipartBody)
	if err := mw.WriteField("csrf", "irrelevant"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("POST", "/unknown", &multipartBody)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("fifth multipart request returned %d", w.Code)
	}
	for i := 0; i < maxConcurrentUpload; i++ {
		<-app.uploadSlots
	}
}

func TestFrenchKeepsSubmittedDataAndOptionValues(t *testing.T) {
	s := testStore(t)
	cfg := Config{URL: "http://localhost:8787", Organization: "Your name", Dev: true, Expires: time.Now().Add(time.Hour)}
	app, e := NewApp(s, cfg)
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/report?lang=fr", nil))
	body := w.Body.String()
	for _, want := range []string{`lang="fr"`, `Votre signalement est privé`, `Your name`, `value="unknown"`, `Envoyer le signalement privé`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(body, `value="INCONNU"`) {
		t.Fatal("translation changed a form value")
	}
}
func TestWatcherAuthorization(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	c := sampleCase()
	u := User{ID: UUID(), Role: "ENGINEER"}
	c.Watchers = []string{u.ID}
	if e := s.CreateCase(ctx, c, "token"); e != nil {
		t.Fatal(e)
	}
	if !CanRead(u, c) || !CanWrite(u, c) {
		t.Fatal("explicit watcher denied")
	}
	cs, n, e := s.Queue(ctx, u, "", "", 1)
	if e != nil || n != 1 || len(cs) != 1 {
		t.Fatal("watcher queue missing", e)
	}
	c.Watchers = nil
	if CanRead(u, c) {
		t.Fatal("unassigned engineer accepted")
	}
}
func TestRuntimeRoleCannotRewriteAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	role := "runtime_" + RandomHex(8)
	if _, e := s.DB.Exec("CREATE ROLE " + role); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Exec("RESET ROLE"); s.DB.Exec("DROP OWNED BY " + role); s.DB.Exec("DROP ROLE " + role) })
	s.DB.SetMaxOpenConns(1)
	var schema string
	s.DB.QueryRow("SELECT current_schema()").Scan(&schema)
	for _, q := range []string{"GRANT USAGE ON SCHEMA " + schema + " TO " + role, "GRANT SELECT,INSERT ON audit_events TO " + role, "GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA " + schema + " TO " + role, "SET ROLE " + role} {
		if _, e := s.DB.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.CheckRuntimeRole(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec("UPDATE audit_events SET metadata='tampered'"); e == nil {
		t.Fatal("runtime rewrote audit")
	}
	if _, e := s.DB.Exec("TRUNCATE audit_events"); e == nil {
		t.Fatal("runtime truncated audit")
	}
	if _, e := s.DB.Exec("CREATE TABLE unexpected(id int)"); e == nil {
		t.Fatal("runtime applied DDL")
	}
	if _, e := s.DB.Exec("RESET ROLE"); e != nil {
		t.Fatal(e)
	}
	if s.CheckRuntimeRole(ctx) == nil {
		t.Fatal("database owner accepted as runtime")
	}
}
