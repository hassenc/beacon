package beacon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	"time"
)

//go:embed policy.json
var policyJSON []byte

func DefaultPolicy() Policy {
	var p Policy
	if err := json.Unmarshal(policyJSON, &p); err != nil {
		panic(err)
	}
	return p
}

type Store struct {
	DB     *sql.DB
	Crypto *Crypto
}
type diskCase struct {
	Case       Case
	Encrypted  []byte
	WrappedKey []byte
}
type CaseExportSnapshot struct {
	Case       Case
	Audit      []AuditEvent
	Evidence   map[string][]byte
	BoundaryAt time.Time
}

func OpenStore(ctx context.Context, dsn string, c *Crypto) (*Store, error) {
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	if e = db.PingContext(ctx); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db, c}, nil
}
func (s *Store) encode(c Case) ([]byte, error) {
	secret, e := json.Marshal(c.Payload)
	if e != nil {
		return nil, e
	}
	c.Payload = Payload{}
	key := make([]byte, 32)
	rand.Read(key)
	local, _ := NewCrypto(key)
	return json.Marshal(diskCase{Case: c, Encrypted: local.Seal(secret, c.ID), WrappedKey: s.Crypto.Seal(key, "case-key:"+c.ID)})
}
func (s *Store) decode(b []byte) (Case, error) {
	var d diskCase
	if e := json.Unmarshal(b, &d); e != nil {
		return Case{}, e
	}
	local := s.Crypto
	if len(d.WrappedKey) > 0 {
		key, e := s.Crypto.Open(d.WrappedKey, "case-key:"+d.Case.ID)
		if e != nil {
			return Case{}, e
		}
		local, e = NewCrypto(key)
		if e != nil {
			return Case{}, e
		}
	}
	b, e := local.Open(d.Encrypted, d.Case.ID)
	if e != nil {
		return Case{}, e
	}
	e = json.Unmarshal(b, &d.Case.Payload)
	return d.Case, e
}
func eventHash(a AuditEvent) string {
	a.Hash = ""
	a.At = a.At.UTC()
	b, _ := json.Marshal(a)
	return Hash(string(b))
}
func (s *Store) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(72402)"); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit()
}
func audit(ctx context.Context, tx *sql.Tx, actor, action, object, meta string) error {
	a := AuditEvent{At: time.Now().UTC().Truncate(time.Microsecond), Actor: actor, Action: action, Object: object, Metadata: meta}
	e := tx.QueryRowContext(ctx, "SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1").Scan(&a.Previous)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if e = tx.QueryRowContext(ctx, "SELECT nextval(pg_get_serial_sequence('audit_events','sequence'))").Scan(&a.Sequence); e != nil {
		return e
	}
	a.Hash = eventHash(a)
	_, e = tx.ExecContext(ctx, "INSERT INTO audit_events(sequence,at,actor,action,object,metadata,previous,hash) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8)", a.Sequence, a.At, actor, action, object, meta, a.Previous, a.Hash)
	return e
}
func (s *Store) Audit(ctx context.Context, actor, action, object, meta string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error { return audit(ctx, tx, actor, action, object, meta) })
}
func (s *Store) CreateCase(ctx context.Context, c Case, token string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		files := c.Payload.Attachments
		c.Payload.Attachments = append([]Attachment(nil), files...)
		for i := range c.Payload.Attachments {
			c.Payload.Attachments[i].Size = len(files[i].Data)
			c.Payload.Attachments[i].Data = nil
		}
		b, e := s.encode(c)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, "INSERT INTO cases(ref,token_hash,data) VALUES($1,$2,$3)", c.Ref, Hash(token), b)
		if e != nil {
			return e
		}
		if e = s.saveEvidence(ctx, tx, c.Ref, files); e != nil {
			return e
		}
		if e = s.enqueueCase(ctx, tx, c, "receipt", true); e != nil {
			return e
		}
		return audit(ctx, tx, "reporter", "case.created", c.Ref, "Anonymous or identified submission")
	})
}
func (s *Store) Case(ctx context.Context, ref string) (Case, error) {
	var b []byte
	e := s.DB.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1", ref).Scan(&b)
	if e != nil {
		return Case{}, e
	}
	return s.decode(b)
}
func (s *Store) Cases(ctx context.Context, u User) ([]Case, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT jsonb_build_object('Case',data->'Case') FROM cases WHERE ($1 OR data->'Case'->>'Owner'=$2 OR (data->'Case'->'Watchers') ? $2) ORDER BY data->'Case'->>'Created' DESC", u.Role == "OWNER" || u.Role == "TRIAGE" || u.Role == "VIEWER", u.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Case
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var d diskCase
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		if CanRead(u, d.Case) {
			out = append(out, d.Case)
		}
	}
	return out, rows.Err()
}
func (s *Store) ChangeCase(ctx context.Context, u User, ref string, revision int, action string, fn func(*Case) error) error {
	return s.changeCase(ctx, u, ref, revision, action, func(c *Case, _ User) error { return fn(c) })
}
func (s *Store) ChangeCaseWithActor(ctx context.Context, u User, ref string, revision int, action string, fn func(*Case, User) error) error {
	return s.changeCase(ctx, u, ref, revision, action, fn)
}
func (s *Store) changeCase(ctx context.Context, u User, ref string, revision int, action string, fn func(*Case, User) error) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var b []byte
		e := tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&b)
		if e != nil {
			return e
		}
		c, e := s.decode(b)
		if e != nil {
			return e
		}
		current, e := lockUser(ctx, tx, u.ID)
		if e != nil {
			return e
		}
		if e = validateActor(u, current); e != nil {
			return e
		}
		beforeStatus, beforeSeverity, beforeOwner := c.Status, c.Severity, c.Owner
		if !CanWrite(current, c) {
			return errors.New("Not permitted")
		}
		if revision != c.Revision {
			return errors.New("This case changed. Reload before trying again")
		}
		if e = fn(&c, current); e != nil {
			return e
		}
		if c.Owner != "" {
			assigned, e := lockUser(ctx, tx, c.Owner)
			if e != nil || assigned.Disabled || assigned.Role == "VIEWER" {
				return errors.New("case owner must be an active non-viewer")
			}
		}
		for _, watcher := range c.Watchers {
			watcherUser, e := lockUser(ctx, tx, watcher)
			if e != nil || watcherUser.Disabled {
				return errors.New("case watcher must be active")
			}
		}
		if c.DuplicateOf != "" {
			var targetRaw []byte
			if e = tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1", c.DuplicateOf).Scan(&targetRaw); e != nil {
				return errors.New("duplicate target no longer exists")
			}
			target, e := s.decode(targetRaw)
			if e != nil || !CanRead(current, target) {
				return errors.New("duplicate target is not accessible")
			}
		}
		c.Revision++
		c.Updated = time.Now().UTC()
		if e = s.detachEvidence(ctx, tx, &c); e != nil {
			return e
		}
		b, e = s.encode(c)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE cases SET data=$1 WHERE ref=$2", b, ref); e != nil {
			return e
		}
		if action == "case.message" {
			external := false
			if len(c.Payload.Messages) > 0 {
				external = c.Payload.Messages[len(c.Payload.Messages)-1].Visibility == "REPORTER_VISIBLE"
			}
			if e = s.enqueueCase(ctx, tx, c, "message", external); e != nil {
				return e
			}
		}
		return audit(ctx, tx, current.ID, action, ref, fmt.Sprintf("revision %d; status %s → %s; severity %s → %s; owner %s → %s", c.Revision, beforeStatus, c.Status, beforeSeverity, c.Severity, beforeOwner, c.Owner))
	})
}
func (s *Store) ReporterMessage(ctx context.Context, ref, sessionHash, body string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var b []byte
		if e := tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&b); e != nil {
			return e
		}
		c, e := s.decode(b)
		if e != nil {
			return e
		}
		var currentVersion, valid int
		if e = tx.QueryRowContext(ctx, "SELECT token_version FROM cases WHERE ref=$1", ref).Scan(&currentVersion); e != nil {
			return e
		}
		if e = tx.QueryRowContext(ctx, "SELECT 1 FROM sessions WHERE hash=$1 AND case_ref=$2 AND token_version=$3 AND expires>now() FOR UPDATE", sessionHash, ref, currentVersion).Scan(&valid); e != nil {
			return errors.New("reporter access was revoked; reload the report")
		}
		if len(c.Payload.Messages) >= 500 {
			return errors.New("Case message limit reached")
		}
		c.Payload.Messages = append(c.Payload.Messages, Message{ID: "r_" + UUID(), At: time.Now().UTC(), Author: "Reporter", Visibility: "REPORTER_VISIBLE", Body: body})
		c.Revision++
		c.Updated = time.Now().UTC()
		if e = s.detachEvidence(ctx, tx, &c); e != nil {
			return e
		}
		b, e = s.encode(c)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, "UPDATE cases SET data=$1 WHERE ref=$2", b, ref); e != nil {
			return e
		}
		if e = s.enqueueCase(ctx, tx, c, "reporter-message", false); e != nil {
			return e
		}
		return audit(ctx, tx, "reporter", "reporter.message", ref, "Reporter-visible message")
	})
}
func (s *Store) Products(ctx context.Context) ([]Product, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT data FROM products ORDER BY data->>'Name'")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var ps []Product
	for rows.Next() {
		var b []byte
		var p Product
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &p); e != nil {
			return nil, e
		}
		ps = append(ps, p)
	}
	return ps, rows.Err()
}
func lockUser(ctx context.Context, tx *sql.Tx, id string) (User, error) {
	return scanUser(tx.QueryRowContext(ctx, "SELECT id,name,email,role,password,disabled,mfa_enabled,oidc_subject,auth_generation FROM users WHERE id=$1 FOR SHARE", id))
}
func validateActor(actor, current User) error {
	if actor.ID == "" || actor.ID != current.ID || actor.Disabled || current.Disabled || actor.AuthGeneration != current.AuthGeneration {
		return errors.New("authentication state changed; retry")
	}
	return nil
}
func (s *Store) AddProduct(ctx context.Context, u User, p Product) error {
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, u.ID)
		if e != nil {
			return e
		}
		if e = validateActor(u, current); e != nil {
			return e
		}
		if !CanManage(current) {
			return errors.New("Not permitted")
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO products VALUES($1,$2)", p.ID, b); e != nil {
			return e
		}
		return audit(ctx, tx, current.ID, "product.created", p.ID, p.Name)
	})
}
func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	e := row.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.Password, &u.Disabled, &u.MFAEnabled, &u.OIDCSubject, &u.AuthGeneration)
	return u, e
}
func (s *Store) User(ctx context.Context, id string) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT id,name,email,role,password,disabled,mfa_enabled,oidc_subject,auth_generation FROM users WHERE id=$1", id))
}
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT id,name,email,role,password,disabled,mfa_enabled,oidc_subject,auth_generation FROM users WHERE email=$1", email))
}
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,name,email,role,password,disabled,mfa_enabled,oidc_subject,auth_generation FROM users ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var us []User
	for rows.Next() {
		u, e := scanUser(rows)
		if e != nil {
			return nil, e
		}
		us = append(us, u)
	}
	return us, rows.Err()
}
func (s *Store) AddUser(ctx context.Context, actor User, u User) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, actor.ID)
		if e != nil {
			return e
		}
		if e = validateActor(actor, current); e != nil {
			return e
		}
		if current.Role != "OWNER" {
			return errors.New("Not permitted")
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO users(id,name,email,role,password) VALUES($1,$2,$3,$4,$5)", u.ID, u.Name, u.Email, u.Role, u.Password); e != nil {
			return e
		}
		return audit(ctx, tx, current.ID, "user.created", u.ID, u.Role)
	})
}
func (s *Store) Bootstrap(ctx context.Context, email, password string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); e != nil {
			return e
		}
		if n > 0 {
			return nil
		}
		if len(password) < 16 || email == "" {
			return errors.New("First start requires BEACON_ADMIN_EMAIL and BEACON_ADMIN_PASSWORD of at least 16 characters")
		}
		id := UUID()
		if _, e := tx.ExecContext(ctx, "INSERT INTO users(id,name,email,role,password) VALUES($1,'Security owner',$2,'OWNER',$3)", id, email, PasswordHash(password)); e != nil {
			return e
		}
		return audit(ctx, tx, id, "organization.initialized", "beacon", Version)
	})
}
func (s *Store) Session(ctx context.Context, hash string) (User, string, error) {
	var id, ref string
	var u User
	e := s.DB.QueryRowContext(ctx, `SELECT s.user_id,s.case_ref,
		COALESCE(u.id,''),COALESCE(u.name,''),COALESCE(u.email,''),COALESCE(u.role,''),COALESCE(u.password,''),
		COALESCE(u.disabled,false),COALESCE(u.mfa_enabled,false),COALESCE(u.oidc_subject,''),COALESCE(u.auth_generation,1)
		FROM sessions s LEFT JOIN cases c ON c.ref=s.case_ref LEFT JOIN users u ON u.id=s.user_id
		WHERE s.hash=$1 AND s.expires>now() AND (s.case_ref='' OR c.token_version=s.token_version)
		AND (s.user_id='' OR (NOT u.disabled AND s.auth_generation=u.auth_generation))`, hash).
		Scan(&id, &ref, &u.ID, &u.Name, &u.Email, &u.Role, &u.Password, &u.Disabled, &u.MFAEnabled, &u.OIDCSubject, &u.AuthGeneration)
	if e != nil {
		return User{}, "", e
	}
	if id != "" {
		if u.Disabled {
			return User{}, "", errors.New("account disabled")
		}
		return u, "", nil
	}
	return User{}, ref, nil
}
func (s *Store) NewSession(ctx context.Context, user, ref string) (string, error) {
	return s.newSession(ctx, user, ref, nil)
}
func (s *Store) NewSessionBound(ctx context.Context, user, ref string, generation int64) (string, error) {
	return s.newSession(ctx, user, ref, &generation)
}
func (s *Store) newSession(ctx context.Context, user, ref string, expectedGeneration *int64) (string, error) {
	token := RandomHex(32)
	e := s.transaction(ctx, func(tx *sql.Tx) error {
		if _, e := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires<now()"); e != nil {
			return e
		}
		generation := int64(1)
		if user != "" {
			var disabled bool
			if e := tx.QueryRowContext(ctx, "SELECT auth_generation,disabled FROM users WHERE id=$1 FOR SHARE", user).Scan(&generation, &disabled); e != nil {
				return e
			} else if disabled || expectedGeneration != nil && generation != *expectedGeneration {
				return errors.New("authentication state changed; retry sign-in")
			}
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO sessions(hash,user_id,case_ref,expires,token_version,auth_generation) VALUES($1,$2,$3,$4,COALESCE((SELECT token_version FROM cases WHERE ref=$3),1),$5)", Hash(token), user, ref, time.Now().Add(8*time.Hour), generation); e != nil {
			return e
		}
		actor := user
		if actor == "" {
			actor = "reporter"
		}
		return audit(ctx, tx, actor, "session.created", ref, "8-hour session")
	})
	return token, e
}

// RecoverSession validates the recovery token and creates the session while the
// case row is locked. Rotation therefore cannot commit between proof and use.
func (s *Store) RecoverSession(ctx context.Context, ref, token string) (string, error) {
	session := RandomHex(32)
	e := s.transaction(ctx, func(tx *sql.Tx) error {
		var stored string
		var version int
		if e := tx.QueryRowContext(ctx, "SELECT token_hash,token_version FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&stored, &version); e != nil {
			return errors.New("invalid recovery credentials")
		}
		if subtle.ConstantTimeCompare([]byte(stored), []byte(Hash(token))) != 1 {
			return errors.New("invalid recovery credentials")
		}
		if _, e := tx.ExecContext(ctx, "INSERT INTO sessions(hash,user_id,case_ref,expires,token_version,auth_generation) VALUES($1,'',$2,$3,$4,1)", Hash(session), ref, time.Now().Add(8*time.Hour), version); e != nil {
			return e
		}
		return audit(ctx, tx, "reporter", "session.created", ref, "8-hour session")
	})
	if e != nil {
		return "", e
	}
	return session, nil
}
func (s *Store) CheckRecovery(ctx context.Context, ref, token string) bool {
	var n int
	e := s.DB.QueryRowContext(ctx, "SELECT count(*) FROM cases WHERE ref=$1 AND token_hash=$2", ref, Hash(token)).Scan(&n)
	return e == nil && n == 1
}

// ExportSnapshot locks the case while recording the export and reading its
// complete audit history and evidence. Callers receive one revision boundary,
// never a mixture assembled from independent reads.
func (s *Store) ExportSnapshot(ctx context.Context, u User, ref string, revision int) (CaseExportSnapshot, error) {
	var out CaseExportSnapshot
	e := s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, u.ID)
		if e != nil {
			return e
		}
		if e = validateActor(u, current); e != nil {
			return e
		}
		if !CanManage(current) {
			return errors.New("Not permitted")
		}
		var b []byte
		if e = tx.QueryRowContext(ctx, "SELECT data FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&b); e != nil {
			return e
		}
		out.Case, e = s.decode(b)
		if e != nil {
			return e
		}
		if out.Case.Revision != revision {
			return errors.New("This case changed. Reload before exporting")
		}
		out.BoundaryAt = time.Now().UTC()
		if e = audit(ctx, tx, current.ID, "case.exported", ref, fmt.Sprintf("revision %d; complete snapshot", revision)); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, "SELECT sequence,at,actor,action,object,metadata,previous,hash FROM audit_events WHERE object=$1 ORDER BY sequence", ref)
		if e != nil {
			return e
		}
		for rows.Next() {
			var a AuditEvent
			if e = rows.Scan(&a.Sequence, &a.At, &a.Actor, &a.Action, &a.Object, &a.Metadata, &a.Previous, &a.Hash); e != nil {
				rows.Close()
				return e
			}
			out.Audit = append(out.Audit, a)
		}
		if e = rows.Err(); e != nil {
			rows.Close()
			return e
		}
		rows.Close()
		out.Evidence = map[string][]byte{}
		for _, f := range out.Case.Payload.Attachments {
			var encrypted []byte
			if e = tx.QueryRowContext(ctx, "SELECT encrypted FROM evidence WHERE case_ref=$1 AND id=$2", ref, f.ID).Scan(&encrypted); e != nil {
				return e
			}
			content, e := s.Crypto.OpenEnvelope(encrypted, "evidence:"+ref+":"+f.ID)
			if e != nil {
				return e
			}
			out.Evidence[f.ID] = content
		}
		return nil
	})
	return out, e
}
func (s *Store) Events(ctx context.Context, object string, limit int) ([]AuditEvent, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT sequence,at,actor,action,object,metadata,previous,hash FROM audit_events WHERE ($1='' OR object=$1) ORDER BY sequence DESC LIMIT $2", object, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var as []AuditEvent
	for rows.Next() {
		var a AuditEvent
		if e = rows.Scan(&a.Sequence, &a.At, &a.Actor, &a.Action, &a.Object, &a.Metadata, &a.Previous, &a.Hash); e != nil {
			return nil, e
		}
		as = append(as, a)
	}
	return as, rows.Err()
}
func (s *Store) Verify(ctx context.Context) (int, string, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT sequence,at,actor,action,object,metadata,previous,hash FROM audit_events ORDER BY sequence")
	if e != nil {
		return 0, "", e
	}
	defer rows.Close()
	prev := ""
	n := 0
	for rows.Next() {
		var a AuditEvent
		if e = rows.Scan(&a.Sequence, &a.At, &a.Actor, &a.Action, &a.Object, &a.Metadata, &a.Previous, &a.Hash); e != nil {
			return n, prev, e
		}
		if a.Previous != prev || eventHash(a) != a.Hash {
			return n, prev, fmt.Errorf("audit verification failed at event %d", a.Sequence)
		}
		prev = a.Hash
		n++
	}
	return n, prev, rows.Err()
}

// VerifyData checks that a backup can be decrypted and every original file matches its manifest.
func (s *Store) VerifyData(ctx context.Context) (int, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT data FROM cases")
	if e != nil {
		return 0, e
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return n, e
		}
		c, e := s.decode(b)
		if e != nil {
			return n, e
		}
		for _, f := range c.Payload.Attachments {
			content, err := s.Evidence(ctx, c.Ref, f.ID)
			if err != nil {
				return n, err
			}
			if Hash(string(content)) != f.SHA256 {
				return n, fmt.Errorf("attachment checksum mismatch in %s", c.Ref)
			}
		}
		n++
	}
	return n, rows.Err()
}
