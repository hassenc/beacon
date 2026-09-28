package beacon

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

const (
	maxPostBody         = 7 << 20
	multipartMemory     = 1 << 20
	maxConcurrentUpload = 4
)

type Config struct {
	URL               string
	Organization      string
	Listen            string
	Dev               bool
	Expires           time.Time
	Policy            string
	SMTP              SMTPConfig
	OIDC              OIDCConfig
	TrustedProxyCIDRs []string
}

func (c Config) Validate() error {
	u, e := url.Parse(c.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (!c.Dev && u.Scheme != "https") || (c.Dev && u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("BEACON_URL must be an origin, using HTTPS outside local development")
	}
	if c.Organization == "" || c.Expires.IsZero() {
		return errors.New("Set organization and explicit security.txt expiration")
	}
	if !c.Dev && !c.Expires.After(time.Now().UTC()) {
		return errors.New("BEACON_SECURITY_EXPIRES must be in the future outside local development")
	}
	for _, value := range c.TrustedProxyCIDRs {
		if _, _, e := net.ParseCIDR(strings.TrimSpace(value)); e != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q", value)
		}
	}
	if c.Dev && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return errors.New("Development mode requires a loopback public URL")
	}
	return nil
}

type App struct {
	Store          *Store
	Config         Config
	views          map[string]*template.Template
	passwordSlots  chan struct{}
	uploadSlots    chan struct{}
	trustedProxies []*net.IPNet
	dummyHash      string
	federation     *federation
}
type Page struct {
	PageNumber, TotalMatches                                                                                                 int
	PreviousURL, NextURL                                                                                                     string
	Secret, OTPURL                                                                                                           string
	RecoveryCodes                                                                                                            []string
	Notifications                                                                                                            []Notification
	NotificationAlert                                                                                                        bool
	SMTPEnabled, SSOEnabled                                                                                                  bool
	Language                                                                                                                 string
	PacketJSON                                                                                                               string
	Title, Active, CSRF, Organization, Version, Error, Notice, Query, Filter, Token, Ref, Mode, Now, SecurityText, AuditHash string
	User                                                                                                                     User
	Case                                                                                                                     Case
	Public                                                                                                                   PublicCase
	Cases                                                                                                                    []Case
	Products                                                                                                                 []Product
	Users                                                                                                                    []User
	Events                                                                                                                   []AuditEvent
	Deadlines                                                                                                                []Deadline
	AllDeadlines                                                                                                             []CaseDeadline
	Statuses, Severities, Roles                                                                                              []string
	CanManage, CanWrite, Dev                                                                                                 bool
	OpenCount, NewCount, CriticalCount, CRAOpen, AuditCount                                                                  int
	Policy                                                                                                                   string
}
type CaseDeadline struct {
	Ref, Title string
	Deadline   Deadline
}

func NewApp(s *Store, c Config) (*App, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	a := &App{Store: s, Config: c, views: map[string]*template.Template{}, passwordSlots: make(chan struct{}, 2), uploadSlots: make(chan struct{}, maxConcurrentUpload), dummyHash: PasswordHash(RandomHex(32))}
	for _, value := range c.TrustedProxyCIDRs {
		_, network, _ := net.ParseCIDR(strings.TrimSpace(value))
		a.trustedProxies = append(a.trustedProxies, network)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var err error
	a.federation, err = newFederation(ctx, c.OIDC, c.URL, c.Dev)
	if err != nil {
		return nil, err
	}
	if c.OIDC.Issuer != "" {
		result, e := s.DB.ExecContext(ctx, "UPDATE deployment_secrets SET oidc_issuer=$1 WHERE id=1 AND (oidc_issuer='' OR oidc_issuer=$1)", c.OIDC.Issuer)
		if e != nil {
			return nil, e
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			return nil, errors.New("OIDC issuer changed: explicitly unbind existing subjects before migrating identity providers")
		}
	}
	funcs := template.FuncMap{"listlifecycle": func() []string { return []string{"SUPPORTED", "MAINTENANCE", "END_OF_LIFE"} }, "contains": Contains, "initial": func(s string) string {
		r := []rune(s)
		if len(r) == 0 {
			return ""
		}
		return string(r[0])
	}, "date": func(t time.Time) string { return t.UTC().Format("02 Jan 2006 · 15:04 UTC") }, "shortdate": func(t time.Time) string { return t.UTC().Format("02 Jan · 15:04") }, "lower": strings.ToLower, "label": func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", " ") }, "size": func(n int) string { return fmt.Sprintf("%.1f KB", float64(n)/1024) }, "selected": func(a, b string) bool { return a == b }, "canmanage": CanManage, "external": ExternalStatus}
	for _, name := range []string{"portal", "report", "receipt", "login", "recover", "reporter", "queue", "case", "products", "audit", "deadlines", "settings", "security", "error", "account", "notifications", "packet"} {
		for _, lang := range []string{"en", "fr"} {
			suffix := ""
			key := name
			if lang == "fr" {
				suffix = ".fr"
				key += "_fr"
			}
			funcs["label"] = func(s string) string { return localizedLabel(s, lang) }
			t, e := template.New("base").Funcs(funcs).ParseFS(webFS, "web/base"+suffix+".html", "web/"+name+suffix+".html")
			if e != nil {
				return nil, e
			}
			a.views[key] = t
		}

	}
	return a, nil
}
func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /app/cases/{ref}/packet", a.packetPage)
	m.HandleFunc("GET /account/security", a.account)
	m.HandleFunc("POST /account/{action}", a.accountAction)
	m.HandleFunc("POST /app/users/manage", a.manageUser)
	m.HandleFunc("POST /reporter/token", a.reporterRotate)
	m.HandleFunc("GET /app/notifications", a.notificationPage)
	m.HandleFunc("POST /app/notifications", a.notificationPage)
	m.HandleFunc("GET /auth/login", a.oidcStart)
	m.HandleFunc("GET /auth/callback", a.oidcCallback)
	m.HandleFunc("GET /{$}", a.portal)
	m.HandleFunc("GET /report", a.report)
	m.HandleFunc("POST /report", a.submit)
	m.HandleFunc("GET /login", a.login)
	m.HandleFunc("POST /login", a.signin)
	m.HandleFunc("POST /logout", a.logout)
	m.HandleFunc("GET /recover", a.recover)
	m.HandleFunc("POST /recover", a.recoverAccess)
	m.HandleFunc("GET /reporter", a.reporter)
	m.HandleFunc("POST /reporter/messages", a.reporterMessage)
	m.HandleFunc("GET /reporter/files/{id}", a.reporterFile)
	m.HandleFunc("GET /app", a.queue)
	m.HandleFunc("GET /app/cases/{ref}", a.caseView)
	m.HandleFunc("POST /app/cases/{ref}/{action}", a.caseAction)
	m.HandleFunc("GET /app/cases/{ref}/files/{id}", a.internalFile)
	m.HandleFunc("GET /app/products", a.products)
	m.HandleFunc("POST /app/products/{id}", a.productEdit)
	m.HandleFunc("POST /app/products", a.createProduct)
	m.HandleFunc("GET /app/audit", a.auditPage)
	m.HandleFunc("GET /app/deadlines", a.deadlines)
	m.HandleFunc("GET /app/settings", a.settings)
	m.HandleFunc("POST /app/users", a.createUser)
	m.HandleFunc("GET /app/security", a.securityPage)
	m.HandleFunc("GET /.well-known/security.txt", a.securityTxt)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.Store.DB.PingContext(ctx) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	m.HandleFunc("GET /assets/style.css", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/style.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(b)
	})
	return a.middleware(m)
}
func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Chrome serializes Origin as "null" for basic form POSTs when the
		// referrer policy is no-referrer. Keep same-origin referrers private
		// from other origins while preserving the Origin header used below.
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if !a.Config.Dev {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.Method == "POST" {
			if kind, limit := postRateLimit(r.URL.Path); kind != "" && !a.allow(r, kind, limit) {
				a.fail(w, r, 429, "Request limit reached. Please retry later.")
				return
			}
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				select {
				case a.uploadSlots <- struct{}{}:
					defer func() { <-a.uploadSlots }()
				default:
					a.fail(w, r, 429, "Upload capacity is busy. Please retry shortly.")
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxPostBody)
			if origin := r.Header.Get("Origin"); origin != "" && origin != a.Config.URL {
				a.fail(w, r, 403, "Invalid request origin")
				return
			}
			var err error
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				err = r.ParseMultipartForm(multipartMemory)
				if r.MultipartForm != nil {
					defer r.MultipartForm.RemoveAll()
				}
			} else {
				err = r.ParseForm()
			}
			if err != nil {
				a.fail(w, r, 400, "Invalid form or request exceeds 7 MB")
				return
			}
			cookie, e := r.Cookie(a.cookieName("csrf"))
			value := r.FormValue("csrf")
			if e != nil || !a.Store.Crypto.ValidCSRF(cookie.Value) || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(value)) != 1 {
				a.fail(w, r, 403, "Your form session expired. Reload the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) cookieName(kind string) string {
	if a.Config.Dev {
		return "beacon_" + kind
	}
	return "__Host-beacon_" + kind
}
func (a *App) cookie(w http.ResponseWriter, kind, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(kind), Value: value, Path: "/", HttpOnly: true, Secure: !a.Config.Dev, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}
func (a *App) csrf(w http.ResponseWriter, r *http.Request) string {
	c, e := r.Cookie(a.cookieName("csrf"))
	if e == nil && a.Store.Crypto.ValidCSRF(c.Value) {
		return c.Value
	}
	v := RandomHex(32)
	v += "." + a.Store.Crypto.Sign(v)
	a.cookie(w, "csrf", v, 28800)
	return v
}
func (a *App) principal(r *http.Request, kind string) (User, string, error) {
	c, e := r.Cookie(a.cookieName(kind))
	if e != nil {
		return User{}, "", e
	}
	return a.Store.Session(r.Context(), Hash(c.Value))
}
func (a *App) internal(w http.ResponseWriter, r *http.Request) (User, bool) {
	u, ref, e := a.principal(r, "session")
	if e != nil || u.ID == "" || ref != "" {
		http.Redirect(w, r, "/login", 303)
		return User{}, false
	}
	if !a.Config.Dev && !u.MFAEnabled && u.OIDCSubject == "" {
		http.Redirect(w, r, "/account/security", 303)
		return User{}, false
	}
	return u, true
}
func (a *App) reporterRef(w http.ResponseWriter, r *http.Request) (string, bool) {
	u, ref, e := a.principal(r, "reporter")
	if e != nil || u.ID != "" || ref == "" {
		http.Redirect(w, r, "/recover", 303)
		return "", false
	}
	return ref, true
}
func (a *App) render(w http.ResponseWriter, r *http.Request, name string, p Page) {
	p.Language = language(r)
	if r.URL.Query().Get("lang") != "" {
		http.SetCookie(w, &http.Cookie{Name: "beacon_language", Value: p.Language, Path: "/", Secure: !a.Config.Dev, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 31536000})
	}
	p.Title = translate(p.Title, p.Language)
	p.Error = translate(p.Error, p.Language)
	p.Notice = translate(p.Notice, p.Language)
	if p.Language == "fr" {
		name += "_fr"
	}
	p.CSRF = a.csrf(w, r)
	p.SSOEnabled = a.federation != nil
	p.SMTPEnabled = a.Config.SMTP.Address != ""
	p.Organization = a.Config.Organization
	p.Version = Version
	p.Dev = a.Config.Dev
	p.Now = time.Now().UTC().Format("02 Jan 2006 · 15:04 UTC")
	p.Statuses = Statuses
	p.Severities = Severities
	p.Roles = Roles
	p.Policy = a.Config.Policy
	var b bytes.Buffer
	if e := a.views[name].ExecuteTemplate(&b, "base", p); e != nil {
		slog.Error("template rendering failed", "view", name)
		http.Error(w, "Unable to display page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b.Bytes())
}
func (a *App) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, translate(msg, language(r)), status)
}
func (a *App) storageError(w http.ResponseWriter, r *http.Request, e error) {
	slog.Error("database operation failed")
	a.fail(w, r, 500, "The operation could not be completed. No success has been recorded. Please retry.")
}
func (a *App) allow(r *http.Request, kind string, limit int) bool {
	host := a.clientHost(r)
	// Hash client addresses; rate windows survive restarts and span replicas.
	key := Hash(kind + ":" + host)
	var count int
	err := a.Store.DB.QueryRowContext(r.Context(), `INSERT INTO rate_limits(key,started,count) VALUES($1,now(),1) ON CONFLICT(key) DO UPDATE SET started=CASE WHEN rate_limits.started<now()-interval '1 hour' THEN now() ELSE rate_limits.started END,count=CASE WHEN rate_limits.started<now()-interval '1 hour' THEN 1 ELSE rate_limits.count+1 END RETURNING count`, key).Scan(&count)
	return err == nil && count <= limit
}
func postRateLimit(path string) (string, int) {
	switch {
	case path == "/report":
		return "submit", 10
	case path == "/recover":
		return "recovery", 20
	case path == "/login":
		return "login", 20
	case path == "/reporter/messages":
		return "message", 60
	case strings.HasPrefix(path, "/account/"):
		return "account", 20
	default:
		return "", 0
	}
}
func (a *App) clientHost(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil || net.ParseIP(host) == nil {
		return "unknown"
	}
	remote := net.ParseIP(host)
	trusted := func(ip net.IP) bool {
		for _, network := range a.trustedProxies {
			if network.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trusted(remote) {
		return remote.String()
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(forwarded[i]))
		if ip != nil && !trusted(ip) {
			return ip.String()
		}
	}
	return remote.String()
}
func (a *App) passwordCheck(w http.ResponseWriter, r *http.Request) bool {
	select {
	case a.passwordSlots <- struct{}{}:
		return true
	default:
		a.fail(w, r, 429, "Authentication is busy. Please retry shortly.")
		return false
	}
}
func field(r *http.Request, key string, max int) (string, error) {
	v := strings.TrimSpace(r.FormValue(key))
	if v == "" || len(v) > max {
		return "", fmt.Errorf("%s is required (maximum %d characters)", key, max)
	}
	return v, nil
}
func (a *App) portal(w http.ResponseWriter, r *http.Request) {
	ps, e := a.Store.Products(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "portal", Page{Title: "Product security", Products: ps})
}
func (a *App) report(w http.ResponseWriter, r *http.Request) {
	ps, e := a.Store.Products(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "report", Page{Title: "Report a vulnerability", Products: ps})
}
func attachments(r *http.Request, visibility string) ([]Attachment, error) {
	if r.MultipartForm == nil {
		return nil, nil
	}
	files := r.MultipartForm.File["evidence"]
	if len(files) > 3 {
		return nil, errors.New("Attach up to three files per submission")
	}
	var as []Attachment
	total := 0
	for _, f := range files {
		if f.Size == 0 {
			continue
		}
		if f.Size > 5<<20 {
			return nil, errors.New("Each file must be 5 MB or smaller")
		}
		file, e := f.Open()
		if e != nil {
			return nil, e
		}
		b, e := io.ReadAll(io.LimitReader(file, (5<<20)+1))
		file.Close()
		if e != nil {
			return nil, e
		}
		total += len(b)
		if len(b) > 5<<20 || total > 10<<20 {
			return nil, errors.New("Evidence exceeds the 10 MB combined limit")
		}
		name := filepath.Base(strings.ReplaceAll(f.Filename, "\\", "/"))
		if len(name) > 180 {
			name = name[:180]
		}
		as = append(as, Attachment{ID: UUID(), Name: name, SHA256: Hash(string(b)), Data: b, At: time.Now().UTC(), Visibility: visibility, Scan: "UNSCANNED"})
	}
	return as, nil
}
func (a *App) submit(w http.ResponseWriter, r *http.Request) {
	c := Case{ID: UUID(), Ref: NewReference(), Status: "NEW", Severity: "UNKNOWN", Created: time.Now().UTC(), Updated: time.Now().UTC(), Revision: 1}
	var e error
	for _, f := range []struct {
		k string
		v *string
		n int
	}{{"title", &c.Title, 200}, {"description", &c.Payload.Description, 30000}, {"steps", &c.Payload.Steps, 30000}, {"impact", &c.Payload.Impact, 15000}} {
		*f.v, e = field(r, f.k, f.n)
		if e != nil {
			a.fail(w, r, 400, e.Error())
			return
		}
	}
	c.Product = r.FormValue("product")
	c.ProductName = "Unknown / Other"
	ps, e := a.Store.Products(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	valid := c.Product == "unknown"
	for _, p := range ps {
		if p.ID == c.Product {
			valid = true
			c.ProductName = p.Name
		}
	}
	if !valid {
		a.fail(w, r, 400, "Choose an affected product")
		return
	}
	c.AffectedVersion = strings.TrimSpace(r.FormValue("version"))
	c.Payload.ReporterName = strings.TrimSpace(r.FormValue("name"))
	c.Payload.Email = strings.TrimSpace(r.FormValue("email"))
	if len(c.AffectedVersion) > 200 || len(c.Payload.ReporterName) > 200 || len(c.Payload.Email) > 254 {
		a.fail(w, r, 400, "Version or contact information is too long")
		return
	}
	if c.Payload.Email != "" {
		if _, e = mail.ParseAddress(c.Payload.Email); e != nil {
			a.fail(w, r, 400, "Enter a valid email address")
			return
		}
	}
	c.Payload.Attachments, e = attachments(r, "REPORTER_VISIBLE")
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	token := "BCN-RCVR-" + RandomHex(32)
	if e = a.Store.CreateCase(r.Context(), c, token); e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "receipt", Page{Title: "Report received", Ref: c.Ref, Token: token})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, "login", Page{Title: "Team sign in"})
}
func (a *App) signin(w http.ResponseWriter, r *http.Request) {
	if !a.passwordCheck(w, r) {
		return
	}
	defer func() { <-a.passwordSlots }()
	password := r.FormValue("password")
	if len(password) > 1024 {
		a.fail(w, r, 400, "Invalid credentials")
		return
	}
	u, e := a.Store.UserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(r.FormValue("email"))))
	stored := u.Password
	if e != nil {
		stored = a.dummyHash
	}
	ok := PasswordOK(password, stored)
	if e != nil || !ok || u.Disabled || u.OIDCSubject != "" {
		if err := a.Store.Audit(r.Context(), "anonymous", "login.failed", "authentication", "Invalid credentials"); err != nil {
			a.storageError(w, r, err)
			return
		}
		a.render(w, r, "login", Page{Title: "Team sign in", Error: "Email or password is incorrect."})
		return
	}
	if u.MFAEnabled {
		if _, err := a.Store.ConsumeMFABound(r.Context(), u.ID, strings.TrimSpace(r.FormValue("code")), false, u.AuthGeneration); err != nil {
			if auditErr := a.Store.Audit(r.Context(), "anonymous", "mfa.failed", "authentication", "Invalid MFA proof"); auditErr != nil {
				a.storageError(w, r, auditErr)
				return
			}
			a.render(w, r, "login", Page{Title: "Team sign in", Error: "Invalid or already used MFA code."})
			return
		}
	}
	token, e := a.Store.NewSessionBound(r.Context(), u.ID, "", u.AuthGeneration)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.cookie(w, "session", token, 28800)
	http.Redirect(w, r, "/app", 303)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	for _, kind := range []string{"session", "reporter"} {
		if c, e := r.Cookie(a.cookieName(kind)); e == nil {
			if e = a.Store.RevokeSession(r.Context(), Hash(c.Value)); e != nil {
				a.storageError(w, r, e)
				return
			}
		}
		a.cookie(w, kind, "", -1)
	}
	http.Redirect(w, r, "/", 303)
}
func (a *App) recover(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, "recover", Page{Title: "Return to your report"})
}
func (a *App) recoverAccess(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.FormValue("ref"))
	token := strings.TrimSpace(r.FormValue("token"))
	session, e := a.Store.RecoverSession(r.Context(), ref, token)
	if e != nil {
		a.render(w, r, "recover", Page{Title: "Return to your report", Error: "The case reference or recovery token is incorrect."})
		return
	}
	a.cookie(w, "reporter", session, 28800)
	http.Redirect(w, r, "/reporter", 303)
}
func (a *App) reporter(w http.ResponseWriter, r *http.Request) {
	ref, ok := a.reporterRef(w, r)
	if !ok {
		return
	}
	c, e := a.Store.Case(r.Context(), ref)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "reporter", Page{Title: c.Title, Public: Public(c)})
}
func (a *App) reporterMessage(w http.ResponseWriter, r *http.Request) {
	ref, ok := a.reporterRef(w, r)
	if !ok {
		return
	}
	body, e := field(r, "body", 20000)
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	cookie, e := r.Cookie(a.cookieName("reporter"))
	if e != nil {
		a.fail(w, r, 403, "Reporter session expired")
		return
	}
	if e = a.Store.ReporterMessage(r.Context(), ref, Hash(cookie.Value), body); e != nil {
		a.storageError(w, r, e)
		return
	}
	http.Redirect(w, r, "/reporter", 303)
}
func (a *App) queue(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	cs, e := a.Store.Cases(r.Context(), u)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 || page > 100000 {
		page = 1
	}
	p := Page{PageNumber: page, Title: "Case queue", Active: "cases", User: u, Query: r.URL.Query().Get("q"), Filter: r.URL.Query().Get("status")}
	for _, c := range cs {
		if c.Status != "CLOSED" && c.Status != "RESOLVED" && !Contains([]string{"DUPLICATE", "NOT_REPRODUCIBLE", "OUT_OF_SCOPE", "REJECTED"}, c.Status) {
			p.OpenCount++
		}
		if c.Status == "NEW" {
			p.NewCount++
		}
		if c.Severity == "CRITICAL" {
			p.CriticalCount++
		}
		if c.CRA != nil {
			p.CRAOpen++
		}
	}
	p.Cases, p.TotalMatches, e = a.Store.Queue(r.Context(), u, p.Query, p.Filter, page)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	params := url.Values{"q": {p.Query}, "status": {p.Filter}}
	if page > 1 {
		params.Set("page", strconv.Itoa(page-1))
		p.PreviousURL = "/app?" + params.Encode()
	}
	if page*50 < p.TotalMatches {
		params.Set("page", strconv.Itoa(page+1))
		p.NextURL = "/app?" + params.Encode()
	}

	a.render(w, r, "queue", p)
}
func (a *App) caseView(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	c, e := a.Store.Case(r.Context(), r.PathValue("ref"))
	if e != nil || !CanRead(u, c) {
		a.fail(w, r, 404, "Case not found")
		return
	}
	if e = a.Store.Audit(r.Context(), u.ID, "case.viewed", c.Ref, ""); e != nil {
		a.storageError(w, r, e)
		return
	}
	us, e := a.Store.Users(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	ev, e := a.Store.Events(r.Context(), c.Ref, 100)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "case", Page{Title: c.Title, Active: "cases", User: u, Case: c, Users: us, Events: ev, CanManage: CanManage(u), CanWrite: CanWrite(u, c), Deadlines: Deadlines(c.CRA, time.Now().UTC())})
}
func parseTime(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339, v)
	if e != nil {
		return t, errors.New("Use an ISO timestamp with offset, for example 2026-09-15T10:00:00Z")
	}
	return t.UTC(), nil
}
func (a *App) caseAction(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	ref := r.PathValue("ref")
	action := r.PathValue("action")
	c, e := a.Store.Case(r.Context(), ref)
	if e != nil || !CanRead(u, c) {
		a.fail(w, r, 404, "Case not found")
		return
	}
	if action == "packet" {
		a.packetExport(w, r, u, c)
		return
	}
	if action == "revoke" {
		if !CanManage(u) {
			a.fail(w, r, 403, "Owner/Triage required")
			return
		}
		if _, e := a.Store.RotateReporterAs(r.Context(), ref, u); e != nil {
			a.storageError(w, r, e)
			return
		}
		http.Redirect(w, r, "/app/cases/"+ref, 303)
		return
	}
	if action == "purge" {
		if r.FormValue("confirm") != ref {
			a.fail(w, r, 400, "Type the case reference to confirm purge")
			return
		}
		if e := a.Store.PurgeCase(r.Context(), u, ref, parseRevision(r), r.FormValue("reason")); e != nil {
			a.fail(w, r, 400, e.Error())
			return
		}
		http.Redirect(w, r, "/app", 303)
		return
	}
	if action == "export" {
		a.export(w, r, u, ref)
		return
	}
	if !CanWrite(u, c) {
		a.fail(w, r, 403, "Read-only access")
		return
	}
	rev, e := strconv.Atoi(r.FormValue("revision"))
	if e != nil {
		a.fail(w, r, 400, "Missing case revision")
		return
	}
	if !Contains([]string{"update", "message", "attachment", "activate", "filing", "corrective", "assessment", "affected", "duplicate", "reference", "awareness", "hold", "watchers"}, action) {
		a.fail(w, r, 404, "Action not found")
		return
	}
	if action == "update" && r.FormValue("owner") != "" {
		selectedOwner, err := a.Store.User(r.Context(), r.FormValue("owner"))
		if err != nil || selectedOwner.Role == "VIEWER" {
			a.fail(w, r, 400, "Choose a valid case owner")
			return
		}
	}
	if action == "duplicate" {
		target, e := a.Store.Case(r.Context(), r.FormValue("duplicate"))
		if e != nil || !CanRead(u, target) {
			a.fail(w, r, 400, "Duplicate target not found")
			return
		}
	}
	e = a.Store.ChangeCaseWithActor(r.Context(), u, ref, rev, "case."+action, func(c *Case, actor User) error {
		switch action {
		case "assessment", "affected", "duplicate", "reference", "awareness", "hold", "watchers":
			return a.extraAction(r, actor, c, action)
		case "update":
			status := r.FormValue("status")
			severity := r.FormValue("severity")
			owner := r.FormValue("owner")
			if !Transition(c.Status, status) {
				return errors.New("Invalid transition: follow the response stages in order")
			}
			if !Contains(Severities, severity) {
				return errors.New("Invalid severity")
			}
			if !CanManage(actor) && (owner != c.Owner || severity != c.Severity) {
				return errors.New("Only Owner/Triage may assign or change severity")
			}
			c.Status = status
			c.Severity = severity
			c.Owner = owner
		case "message":
			body, e := field(r, "body", 20000)
			if e != nil {
				return e
			}
			vis := r.FormValue("visibility")
			if !Contains([]string{"INTERNAL", "REPORTER_VISIBLE"}, vis) {
				return errors.New("Choose message visibility")
			}
			if len(c.Payload.Messages) >= 500 {
				return errors.New("Case message limit reached")
			}
			if vis == "REPORTER_VISIBLE" {
				if !CanManage(actor) {
					return errors.New("Only Owner/Triage may message reporters")
				}
				if r.FormValue("confirm") != "yes" {
					return errors.New("Confirm that this message may be shared with the reporter")
				}
			}
			c.Payload.Messages = append(c.Payload.Messages, Message{ID: "s_" + UUID(), At: time.Now().UTC(), Author: actor.Name, Visibility: vis, Body: body})
		case "attachment":
			as, e := attachments(r, "INTERNAL")
			if e != nil {
				return e
			}
			if len(as) == 0 {
				return errors.New("Choose a file")
			}
			total := 0
			for _, v := range append(c.Payload.Attachments, as...) {
				total += v.Size + len(v.Data)
			}
			if total > 20<<20 || len(c.Payload.Attachments)+len(as) > 20 {
				return errors.New("Case evidence limit: 20 files and 20 MB")
			}
			c.Payload.Attachments = append(c.Payload.Attachments, as...)
		case "activate":
			if !CanManage(actor) {
				return errors.New("Only Owner/Triage may activate regulatory tracking")
			}
			if c.CRA != nil {
				return errors.New("CRA tracking is already active")
			}
			class := r.FormValue("classification")
			if !Contains([]string{"VULNERABILITY", "INCIDENT"}, class) {
				return errors.New("Choose a confirmed workflow classification")
			}
			t, e := parseTime(r.FormValue("awareness"))
			if e != nil {
				return e
			}
			if t.After(time.Now()) || t.Before(time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)) {
				return errors.New("Awareness must be on or after 11 Sep 2026 and no later than now")
			}
			if r.FormValue("confirm") != "yes" {
				return errors.New("Confirm the organization's recorded awareness time")
			}
			c.CRA = &CRA{Classification: class, Awareness: t, ConfirmedBy: actor.ID, Activated: time.Now().UTC(), Policy: DefaultPolicy()}
		case "filing":
			if !CanManage(actor) || c.CRA == nil {
				return errors.New("CRA tracking and Owner/Triage access required")
			}
			t, e := parseTime(r.FormValue("submitted"))
			if e != nil {
				return e
			}
			representative, e := field(r, "representative", 200)
			if e != nil {
				return e
			}
			reference := r.FormValue("reference")
			notes := r.FormValue("notes")
			if len(reference) > 300 || len(notes) > 2000 {
				return errors.New("Filing reference or notes too long")
			}
			return c.CRA.AddFiling(Filing{Stage: r.FormValue("stage"), At: t, Representative: representative, Reference: reference, Notes: notes, RecordedBy: actor.ID, RecordedAt: time.Now().UTC()}, time.Now().UTC())
		case "corrective":
			if !CanManage(actor) || c.CRA == nil || c.CRA.Classification != "VULNERABILITY" {
				return errors.New("An active vulnerability workflow and Owner/Triage access are required")
			}
			if c.CRA.CorrectiveAt != nil {
				return errors.New("Corrective timestamp already recorded")
			}
			t, e := parseTime(r.FormValue("corrective"))
			if e != nil {
				return e
			}
			if t.After(time.Now()) {
				return errors.New("Corrective measure availability cannot be in the future")
			}
			c.CRA.CorrectiveAt = &t
		}
		return nil
	})
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	http.Redirect(w, r, "/app/cases/"+ref, 303)
}
func (a *App) export(w http.ResponseWriter, r *http.Request, u User, ref string) {
	if r.FormValue("confirm") != "yes" {
		a.fail(w, r, 400, "Confirm export of internal case information")
		return
	}
	revision := parseRevision(r)
	if revision < 1 {
		current, err := a.Store.Case(r.Context(), ref)
		if err != nil {
			a.fail(w, r, 404, "Case not found")
			return
		}
		revision = current.Revision
	}
	snapshot, e := a.Store.ExportSnapshot(r.Context(), u, ref, revision)
	if e != nil {
		if e.Error() == "Not permitted" {
			a.fail(w, r, 403, "Only Owner/Triage may export")
			return
		}
		a.fail(w, r, 400, e.Error())
		return
	}
	c := snapshot.Case
	ev := snapshot.Audit
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	write := func(name string, data []byte) error {
		f, e := z.Create(name)
		if e != nil {
			return e
		}
		_, e = f.Write(data)
		return e
	}
	files := append([]Attachment(nil), c.Payload.Attachments...)
	for i := range c.Payload.Attachments {
		c.Payload.Attachments[i].Data = nil
	}
	record := struct {
		FormatVersion string
		Case          Case
		Audit         []AuditEvent
	}{"1", c, ev}
	data, e := json.MarshalIndent(record, "", "  ")
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	if e = write("case.json", data); e != nil {
		a.storageError(w, r, e)
		return
	}
	var hashes strings.Builder
	for _, f := range files {
		path := "attachments/" + f.ID
		fmt.Fprintf(&hashes, "%s  %s\n", f.SHA256, path)
		content, ok := snapshot.Evidence[f.ID]
		if !ok {
			a.storageError(w, r, errors.New("evidence missing from export snapshot"))
			return
		}
		if e = write(path, content); e != nil {
			a.storageError(w, r, e)
			return
		}
	}
	if e = write("hashes.txt", []byte(hashes.String())); e != nil {
		a.storageError(w, r, e)
		return
	}
	if e = write("README.txt", []byte(fmt.Sprintf("CONFIDENTIAL — full internal case archive. Contains internal notes and reporter identity. Review before sharing. Attachments are untrusted; filenames and SHA-256 values are in case.json. This is not an automatic ENISA filing or a sanitized CRA submission packet. Snapshot boundary: case revision %d at %s. Audit references alone do not independently authenticate an export.\n", c.Revision, snapshot.BoundaryAt.Format(time.RFC3339Nano)))); e != nil {
		a.storageError(w, r, e)
		return
	}
	if e = z.Close(); e != nil {
		a.storageError(w, r, e)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": c.Ref + ".zip"}))
	w.Write(b.Bytes())
}
func (a *App) download(w http.ResponseWriter, r *http.Request, c Case, actor string, public bool) {
	for _, f := range c.Payload.Attachments {
		if f.ID != r.PathValue("id") || (public && f.Visibility != "REPORTER_VISIBLE") {
			continue
		}
		if e := a.Store.Audit(r.Context(), actor, "attachment.downloaded", c.Ref, f.ID); e != nil {
			a.storageError(w, r, e)
			return
		}
		content, err := a.Store.Evidence(r.Context(), c.Ref, f.ID)
		if err != nil {
			a.storageError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
		w.Write(content)
		return
	}
	a.fail(w, r, 404, "File not found")
}
func (a *App) internalFile(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	c, e := a.Store.Case(r.Context(), r.PathValue("ref"))
	if e != nil || !CanRead(u, c) {
		a.fail(w, r, 404, "File not found")
		return
	}
	a.download(w, r, c, u.ID, false)
}
func (a *App) reporterFile(w http.ResponseWriter, r *http.Request) {
	ref, ok := a.reporterRef(w, r)
	if !ok {
		return
	}
	c, e := a.Store.Case(r.Context(), ref)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.download(w, r, c, "reporter", true)
}
func (a *App) products(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	ps, e := a.Store.Products(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "products", Page{Title: "Product registry", Active: "products", User: u, Products: ps, CanManage: CanManage(u)})
}
func (a *App) createProduct(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if !CanManage(u) {
		a.fail(w, r, 403, "Only Owner/Triage may create products")
		return
	}
	p := Product{ID: UUID(), Lifecycle: r.FormValue("lifecycle")}
	for _, f := range []struct {
		k string
		v *string
	}{{"name", &p.Name}, {"family", &p.Family}, {"versions", &p.Versions}, {"owner", &p.Owner}} {
		v, e := field(r, f.k, 200)
		if e != nil {
			a.fail(w, r, 400, e.Error())
			return
		}
		*f.v = v
	}
	if !Contains([]string{"SUPPORTED", "MAINTENANCE", "END_OF_LIFE"}, p.Lifecycle) {
		a.fail(w, r, 400, "Invalid lifecycle")
		return
	}
	if e := a.Store.AddProduct(r.Context(), u, p); e != nil {
		a.storageError(w, r, e)
		return
	}
	http.Redirect(w, r, "/app/products", 303)
}
func (a *App) auditPage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if u.Role == "ENGINEER" {
		a.fail(w, r, 403, "Use the timeline of an assigned case")
		return
	}
	ev, e := a.Store.Events(r.Context(), "", 200)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	n, hash, e := a.Store.Verify(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "audit", Page{Title: "Audit trail", Active: "audit", User: u, Events: ev, AuditCount: n, AuditHash: hash})
}
func (a *App) deadlines(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	cs, e := a.Store.Cases(r.Context(), u)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	p := Page{Title: "CRA response", Active: "deadlines", User: u}
	for _, c := range cs {
		for _, d := range Deadlines(c.CRA, time.Now().UTC()) {
			p.AllDeadlines = append(p.AllDeadlines, CaseDeadline{c.Ref, c.Title, d})
		}
	}
	a.render(w, r, "deadlines", p)
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if u.Role != "OWNER" {
		a.fail(w, r, 403, "Owner access required")
		return
	}
	us, e := a.Store.Users(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "settings", Page{Title: "Team & deployment", Active: "settings", User: u, Users: us})
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if u.Role != "OWNER" {
		a.fail(w, r, 403, "Owner access required")
		return
	}
	name, e := field(r, "name", 200)
	if e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if _, e = mail.ParseAddress(email); e != nil || len(email) > 254 {
		a.fail(w, r, 400, "Invalid email")
		return
	}
	password := r.FormValue("password")
	role := r.FormValue("role")
	if len(password) < 16 || len(password) > 1024 || !Contains(Roles, role) {
		a.fail(w, r, 400, "Use a 16–1024 character password and a valid role")
		return
	}
	if !a.passwordCheck(w, r) {
		return
	}
	defer func() { <-a.passwordSlots }()
	v := User{ID: UUID(), Name: name, Email: email, Role: role, Password: PasswordHash(password)}
	if e = a.Store.AddUser(r.Context(), u, v); e != nil {
		a.fail(w, r, 400, "Could not create user; the email may already exist")
		return
	}
	http.Redirect(w, r, "/app/settings", 303)
}
func (a *App) securityContent() string {
	return fmt.Sprintf("Contact: %s/report\nExpires: %s\nCanonical: %s/.well-known/security.txt\nPreferred-Languages: en\n", a.Config.URL, a.Config.Expires.UTC().Format(time.RFC3339), a.Config.URL)
}
func (a *App) securityTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, a.securityContent())
}
func (a *App) securityPage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	notice := "Expiration is configured explicitly; it does not renew automatically."
	if time.Until(a.Config.Expires) < 30*24*time.Hour {
		notice = "Action required: security.txt expires within 30 days or has expired."
	}
	if a.Config.Dev {
		notice += " Local HTTP is for testing; publish over HTTPS."
	}
	a.render(w, r, "security", Page{Title: "Security entry point", Active: "security", User: u, SecurityText: a.securityContent(), Notice: notice})
}
func KeyFromHex(s string) ([]byte, error) {
	b, e := hex.DecodeString(s)
	if e != nil {
		return nil, e
	}
	if len(b) != 32 {
		return nil, errors.New("BEACON_KEY must contain 64 hexadecimal characters")
	}
	return b, nil
}
