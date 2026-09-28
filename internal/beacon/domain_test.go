package beacon

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func instant(s string) time.Time {
	t, e := time.Parse(time.RFC3339, s)
	if e != nil {
		panic(e)
	}
	return t
}
func TestDeadlines(t *testing.T) {
	awareness := instant("2026-09-15T10:17:00+02:00")
	c := &CRA{Classification: "VULNERABILITY", Awareness: awareness, Policy: DefaultPolicy()}
	ds := Deadlines(c, awareness)
	if !ds[0].Due.Equal(instant("2026-09-16T08:17:00Z")) || !ds[1].Due.Equal(instant("2026-09-18T08:17:00Z")) {
		t.Fatal("initial deadlines do not use awareness")
	}
	if ds[2].Due != nil {
		t.Fatal("final date guessed without corrective trigger")
	}
	c.Filings = []Filing{{Stage: "early", At: awareness.Add(time.Hour)}}
	ds = Deadlines(c, awareness)
	if !ds[1].Due.Equal(awareness.Add(72 * time.Hour)) {
		t.Fatal("early filing moved notification deadline")
	}
	correct := instant("2026-10-24T09:00:00Z")
	c.CorrectiveAt = &correct
	ds = Deadlines(c, awareness)
	if !ds[2].Due.Equal(instant("2026-11-07T09:00:00Z")) {
		t.Fatal("corrective trigger incorrect")
	}
	c.Classification = "INCIDENT"
	c.Filings = []Filing{{Stage: "notification", At: instant("2027-01-31T23:30:00Z")}}
	ds = Deadlines(c, awareness)
	if !ds[2].Due.Equal(instant("2027-02-28T23:30:00Z")) {
		t.Fatal("month must clamp, not overflow into March")
	}
	if !CalendarMonths(instant("2028-01-31T12:00:00Z"), 1).Equal(instant("2028-02-29T12:00:00Z")) {
		t.Fatal("leap month")
	}
	c = &CRA{Classification: "VULNERABILITY", Awareness: awareness, Policy: DefaultPolicy()}
	ds = Deadlines(c, awareness.Add(24*time.Hour))
	if ds[0].State != "OVERDUE" {
		t.Fatal("boundary must be due")
	}
	c.Filings = []Filing{{Stage: "early", At: awareness.Add(25 * time.Hour)}}
	if Deadlines(c, awareness)[0].State != "SUBMITTED LATE" {
		t.Fatal("late filing hidden")
	}
	old := c.Policy
	c.Policy = Policy{Version: "test", EarlyHours: 12, NotificationHours: 48, FinalDays: 7, IncidentMonths: 2}
	if !Deadlines(c, awareness)[1].Due.Equal(awareness.Add(48 * time.Hour)) {
		t.Fatal("policy ignored")
	}
	if old.NotificationHours != 72 {
		t.Fatal("policy snapshot mutated")
	}
}
func TestFilingValidation(t *testing.T) {
	now := instant("2026-09-20T12:00:00Z")
	c := &CRA{Classification: "INCIDENT", Awareness: now.Add(-time.Hour), Policy: DefaultPolicy()}
	cases := []Filing{{Stage: "final", At: now, Representative: "AR"}, {Stage: "early", At: now.Add(time.Hour), Representative: "AR"}, {Stage: "early", At: now.Add(-2 * time.Hour), Representative: "AR"}, {Stage: "fake", At: now, Representative: "AR"}, {Stage: "early", At: now}}
	for _, f := range cases {
		if c.AddFiling(f, now) == nil {
			t.Fatalf("accepted invalid filing %+v", f)
		}
	}
	f := Filing{Stage: "early", At: now, Representative: "AR"}
	if e := c.AddFiling(f, now); e != nil {
		t.Fatal(e)
	}
	if c.AddFiling(f, now) == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestAuthorizationAndProjection(t *testing.T) {
	c := Case{Owner: "assigned", Status: "TRIAGE", Payload: Payload{Email: "secret@example.com", ReporterName: "private reporter", Messages: []Message{{ID: "s_1", Visibility: "INTERNAL", Body: "secret legal advice"}, {ID: "s_2", Visibility: "REPORTER_VISIBLE", Author: "private employee", Body: "Acknowledged"}}, Attachments: []Attachment{{ID: "private", Visibility: "INTERNAL", Data: []byte("secret")}, {ID: "public", Visibility: "REPORTER_VISIBLE", Data: []byte("download-only")}}}}
	for _, test := range []struct {
		role, id            string
		read, write, manage bool
	}{{"OWNER", "o", true, true, true}, {"TRIAGE", "t", true, true, true}, {"VIEWER", "v", true, false, false}, {"ENGINEER", "assigned", true, true, false}, {"ENGINEER", "other", false, false, false}, {"REPORTER", "r", false, false, false}, {"", "", false, false, false}} {
		u := User{ID: test.id, Role: test.role}
		if CanRead(u, c) != test.read || CanWrite(u, c) != test.write || CanManage(u) != test.manage {
			t.Fatalf("authorization mismatch for %s", test.role)
		}
	}
	b, _ := json.Marshal(Public(c))
	for _, secret := range []string{"secret", "private", "download-only", "TRIAGE"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("public projection leaked %q: %s", secret, b)
		}
	}
}
func TestCrypto(t *testing.T) {
	c, e := NewCrypto(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	sealed := c.Seal([]byte("unpublished vulnerability"), "case-a")
	if strings.Contains(string(sealed), "unpublished") {
		t.Fatal("plaintext leaked")
	}
	if _, e = c.Open(sealed, "case-b"); e == nil {
		t.Fatal("cross-case ciphertext substitution")
	}
	sealed[len(sealed)-1] ^= 1
	if _, e = c.Open(sealed, "case-a"); e == nil {
		t.Fatal("tamper accepted")
	}
	if _, e = c.Open([]byte("bad"), "case-a"); e == nil {
		t.Fatal("short ciphertext")
	}
	hash := PasswordHash("a sufficiently long test password")
	if !PasswordOK("a sufficiently long test password", hash) || PasswordOK("wrong", hash) {
		t.Fatal("password verification")
	}
	if PasswordOK("wrong", "bogus") {
		t.Fatal("invalid password hash")
	}
}
func TestTransitions(t *testing.T) {
	if !Transition("NEW", "ACKNOWLEDGED") || Transition("NEW", "CLOSED") || Transition("CLOSED", "NEW") || !Transition("TRIAGE", "OUT_OF_SCOPE") {
		t.Fatal("invalid state machine")
	}
}
func TestAuditTamper(t *testing.T) {
	a := AuditEvent{Sequence: 1, At: instant("2026-09-15T10:00:00Z"), Actor: "owner", Action: "case.created", Object: "A"}
	a.Hash = eventHash(a)
	if eventHash(a) != a.Hash {
		t.Fatal("unstable hash")
	}
	a.Actor = "attacker"
	if eventHash(a) == a.Hash {
		t.Fatal("actor not protected")
	}
}
func TestConfig(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://example.com/path", "https://user:pass@example.com", "https://example.com?x=1"} {
		c := Config{URL: raw, Organization: "Acme", Expires: time.Now().Add(time.Hour)}
		if c.Validate() == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestIntermediateReportsDoNotChangeDeadlines(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	c := CRA{Classification: "INCIDENT", Awareness: now.Add(-time.Hour), Policy: DefaultPolicy()}
	before := Deadlines(&c, now)
	for i := 0; i < 2; i++ {
		if e := c.AddFiling(Filing{Stage: "intermediate", At: now, Representative: "CSIRT requested update"}, now); e != nil {
			t.Fatal(e)
		}
	}
	after := Deadlines(&c, now)
	if len(after) != len(before) || after[2].Due != nil || !after[0].Due.Equal(*before[0].Due) {
		t.Fatal("intermediate filing changed clocks")
	}
}
