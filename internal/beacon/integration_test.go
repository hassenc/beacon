package beacon

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("BEACON_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("Set BEACON_TEST_DATABASE_URL for PostgreSQL integration tests")
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "test_" + RandomHex(8)
	if _, e = db.Exec("CREATE SCHEMA " + name); e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", name)
	u.RawQuery = q.Encode()
	crypto, _ := NewCrypto(make([]byte, 32))
	s, e := OpenStore(context.Background(), u.String(), crypto)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DB.Close(); db.Exec("DROP SCHEMA " + name + " CASCADE"); db.Close() })
	if e = s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e = s.Bootstrap(context.Background(), "owner@test.local", "test-password-long-enough"); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestIntegration(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	owner, e := s.UserByEmail(ctx, "owner@test.local")
	if e != nil {
		t.Fatal(e)
	}
	config := Config{URL: "http://localhost:8787", Organization: "Test organization", Dev: true, Expires: time.Now().Add(180 * 24 * time.Hour)}
	app, e := NewApp(s, config)
	if e != nil {
		t.Fatal(e)
	}
	h := app.Handler()
	request := func(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		r := httptest.NewRequest(method, path, body)
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.RemoteAddr = "127.0.0.1:1234"
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	cookie := func(w *httptest.ResponseRecorder, name string) *http.Cookie {
		t.Helper()
		for _, c := range w.Result().Cookies() {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("missing cookie %s", name)
		return nil
	}
	get := request("GET", "/report", nil)
	if get.Code != 200 {
		t.Fatal(get.Body.String())
	}
	csrf := cookie(get, "beacon_csrf")
	signedIn := request("POST", "/login", url.Values{"csrf": {csrf.Value}, "email": {"owner@test.local"}, "password": {"test-password-long-enough"}}, csrf)
	if signedIn.Code != 303 {
		t.Fatalf("password login failed: %d %s", signedIn.Code, signedIn.Body.String())
	}
	signedCookie := cookie(signedIn, "beacon_session")
	if request("GET", "/app", nil, signedCookie).Code != 200 {
		t.Fatal("login session cannot open workspace")
	}
	wrongLogin := request("POST", "/login", url.Values{"csrf": {csrf.Value}, "email": {"owner@test.local"}, "password": {"wrong"}}, csrf)
	if strings.Contains(wrongLogin.Header().Get("Set-Cookie"), "beacon_session=") || !strings.Contains(wrongLogin.Body.String(), "incorrect") {
		t.Fatal("bad login accepted")
	}

	form := url.Values{"csrf": {csrf.Value}, "title": {"Test vulnerability <script>alert(1)</script>"}, "product": {"unknown"}, "description": {"secret-description-19872"}, "steps": {"secret-steps-19872"}, "impact": {"secret-impact-19872"}, "email": {"researcher@test.local"}}
	// Multipart intake with an HTML-looking hostile attachment.
	var mb bytes.Buffer
	mw := multipart.NewWriter(&mb)
	for k, vs := range form {
		mw.WriteField(k, vs[0])
	}
	file, _ := mw.CreateFormFile("evidence", "exploit.html")
	file.Write([]byte("<script>hostile_attachment_19872</script>"))
	mw.Close()
	r := httptest.NewRequest("POST", "/report", &mb)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(csrf)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	ref := regexp.MustCompile(`BCN-\d{4}-[0-9a-f]{10}`).FindString(w.Body.String())
	token := regexp.MustCompile(`BCN-RCVR-[0-9a-f]{64}`).FindString(w.Body.String())
	if ref == "" || token == "" {
		t.Fatal("receipt missing reference/token")
	}
	var raw, tokenHash string
	if e = s.DB.QueryRow("SELECT data::text,token_hash FROM cases WHERE ref=$1", ref).Scan(&raw, &tokenHash); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"secret-description-19872", "secret-steps-19872", "researcher@test.local", "hostile_attachment_19872", token} {
		if strings.Contains(raw, secret) {
			t.Fatalf("plaintext stored: %s", secret)
		}
	}
	if tokenHash != Hash(token) {
		t.Fatal("recovery token not hashed")
	}
	if request("POST", "/report", form).Code != 403 {
		t.Fatal("CSRF-free public submission accepted")
	}
	badOrigin := httptest.NewRequest("POST", "/report", strings.NewReader(form.Encode()))
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badOrigin.Header.Set("Origin", "https://evil.example")
	badOrigin.AddCookie(csrf)
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, badOrigin)
	if wr.Code != 403 {
		t.Fatal("cross-origin POST accepted")
	}
	w = request("POST", "/recover", url.Values{"csrf": {csrf.Value}, "ref": {ref}, "token": {token}}, csrf)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	reporterCookie := cookie(w, "beacon_reporter")
	ownerToken, e := s.NewSession(ctx, owner.ID, "")
	if e != nil {
		t.Fatal(e)
	}
	ownerCookie := &http.Cookie{Name: "beacon_session", Value: ownerToken}
	c, e := s.Case(ctx, ref)
	if e != nil {
		t.Fatal(e)
	}
	change := func(action string, f url.Values) *httptest.ResponseRecorder {
		t.Helper()
		c, _ = s.Case(ctx, ref)
		f.Set("csrf", csrf.Value)
		f.Set("revision", fmtInt(c.Revision))
		return request("POST", "/app/cases/"+ref+"/"+action, f, csrf, ownerCookie)
	}
	w = change("update", url.Values{"status": {"ACKNOWLEDGED"}, "severity": {"HIGH"}, "owner": {owner.ID}})
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	w = change("message", url.Values{"visibility": {"INTERNAL"}, "body": {"confidential-legal-note-2987"}})
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	w = change("message", url.Values{"visibility": {"REPORTER_VISIBLE"}, "body": {"Thanks, we are investigating."}})
	if w.Code != 400 {
		t.Fatal("external message without confirmation accepted")
	}
	w = change("message", url.Values{"visibility": {"REPORTER_VISIBLE"}, "body": {"Thanks, we are investigating."}, "confirm": {"yes"}})
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	w = request("GET", "/reporter", nil, reporterCookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Thanks, we are investigating.") || strings.Contains(w.Body.String(), "confidential-legal-note-2987") {
		t.Fatal("reporter boundary failed", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatal("stored XSS")
	}
	// Reporters cannot reuse their session for the internal route.
	w = request("GET", "/app/cases/"+ref, nil, &http.Cookie{Name: "beacon_session", Value: reporterCookie.Value})
	if w.Code != 303 {
		t.Fatal("reporter reached internal case")
	}
	w = request("POST", "/reporter/messages", url.Values{"csrf": {csrf.Value}, "body": {"Additional reproduction details"}}, csrf, reporterCookie)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	// Read-only and assignment boundaries must hold at every internal route.
	for _, role := range []string{"VIEWER", "ENGINEER"} {
		u := User{ID: UUID(), Name: role, Email: strings.ToLower(role) + "@test.local", Role: role, Password: PasswordHash("another-long-test-password")}
		if e = s.AddUser(ctx, owner, u); e != nil {
			t.Fatal(e)
		}
		tok, _ := s.NewSession(ctx, u.ID, "")
		uc := &http.Cookie{Name: "beacon_session", Value: tok}
		w = request("GET", "/app/cases/"+ref, nil, uc)
		if role == "VIEWER" && w.Code != 200 {
			t.Fatal("viewer cannot read")
		}
		if role == "ENGINEER" && w.Code != 404 {
			t.Fatal("unassigned engineer could read")
		}
		w = request("POST", "/app/cases/"+ref+"/export", url.Values{"csrf": {csrf.Value}, "confirm": {"yes"}}, csrf, uc)
		if w.Code != 403 && w.Code != 404 {
			t.Fatal("unauthorized export")
		}
		w = request("POST", "/app/cases/"+ref+"/message", url.Values{"csrf": {csrf.Value}, "revision": {"3"}, "body": {"attack"}, "visibility": {"INTERNAL"}}, csrf, uc)
		if w.Code != 403 && w.Code != 404 {
			t.Fatal("unauthorized mutation")
		}
		w = request("GET", "/app", nil, uc)
		if role == "ENGINEER" && strings.Contains(w.Body.String(), ref) {
			t.Fatal("list leaked unassigned case")
		}
	}
	c, _ = s.Case(ctx, ref)
	attachment := c.Payload.Attachments[0]
	w = request("GET", "/reporter/files/"+attachment.ID, nil, reporterCookie)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatal("unsafe download headers")
	}
	w = change("activate", url.Values{"classification": {"VULNERABILITY"}, "awareness": {time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}, "confirm": {"yes"}})
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/app", "/app/cases/" + ref, "/app/products", "/app/deadlines", "/app/audit", "/app/settings", "/app/security", "/", "/.well-known/security.txt"} {
		w = request("GET", path, nil, ownerCookie)
		if w.Code != 200 {
			t.Fatalf("page %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	w = change("export", url.Values{"confirm": {"yes"}})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	z, e := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, f := range z.File {
		if f.Name == "attachments/"+attachment.ID {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			if Hash(string(data)) != attachment.SHA256 {
				t.Fatal("export lost original attachment bytes")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("attachment missing in export")
	}
	// Optimistic concurrency: one of two edits from the same revision must fail.
	c, _ = s.Case(ctx, ref)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.ChangeCase(ctx, owner, ref, c.Revision, "test.concurrent", func(c *Case) error { c.Severity = "MEDIUM"; return nil })
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("lost-update prevention failed")
	}
	if _, _, e = s.Verify(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("UPDATE audit_events SET actor='attacker'"); e == nil {
		t.Fatal("audit update permitted")
	}
	// A different key must fail startup instead of hiding existing reports.
	wrong, _ := NewCrypto(bytes.Repeat([]byte{1}, 32))
	wrongStore := &Store{DB: s.DB, Crypto: wrong}
	if wrongStore.Migrate(ctx) == nil {
		t.Fatal("incorrect master key accepted")
	}
	// Re-read through a fresh Store to establish persistence, not in-memory behavior.
	fresh := &Store{DB: s.DB, Crypto: s.Crypto}
	restored, e := fresh.Case(ctx, ref)
	if e != nil || restored.Payload.Description != "secret-description-19872" {
		t.Fatal("persistence failed")
	}
	// Logout revokes the stored session.
	w = request("POST", "/logout", url.Values{"csrf": {csrf.Value}}, csrf, ownerCookie)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	if request("GET", "/app", nil, ownerCookie).Code != 303 {
		t.Fatal("logged-out session remains valid")
	}
}
func fmtInt(i int) string { return strconv.Itoa(i) }
