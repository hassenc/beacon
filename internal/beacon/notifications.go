package beacon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type recipient struct {
	Address  string
	Reporter bool
}
type Notification struct {
	ID, Ref, Kind, Error, State string
	Created                     time.Time
	Attempts                    int
	Sent                        *time.Time
}

func (s *Store) enqueue(ctx context.Context, tx *sql.Tx, ref, kind, dedupe string, r recipient) error {
	if _, e := mail.ParseAddress(r.Address); e != nil {
		return nil
	}
	id := UUID()
	b, _ := json.Marshal(r)
	_, e := tx.ExecContext(ctx, "INSERT INTO notifications(id,dedupe,case_ref,recipient,kind) VALUES($1,$2,$3,$4,$5) ON CONFLICT(dedupe) DO NOTHING", id, dedupe+":"+Hash(r.Address), ref, s.Crypto.Seal(b, "notification:"+id), kind)
	return e
}
func (s *Store) enqueueCase(ctx context.Context, tx *sql.Tx, c Case, kind string, external bool) error {
	rows, e := tx.QueryContext(ctx, "SELECT email FROM users WHERE NOT disabled AND (role IN ('OWNER','TRIAGE') OR ((id=$1 OR id=ANY($2)) AND role='ENGINEER'))", c.Owner, pq.Array(c.Watchers))
	if e != nil {
		return e
	}
	var recipients []recipient
	for rows.Next() {
		var email string
		if e = rows.Scan(&email); e != nil {
			rows.Close()
			return e
		}
		recipients = append(recipients, recipient{Address: email})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if external && c.Payload.Email != "" {
		recipients = append(recipients, recipient{Address: c.Payload.Email, Reporter: true})
	}
	dedupe := fmt.Sprintf("%s:%s:%d", c.Ref, kind, c.Revision)
	if strings.HasPrefix(kind, "deadline:") {
		dedupe = c.Ref + ":" + kind
	}
	for _, r := range recipients {
		if e = s.enqueue(ctx, tx, c.Ref, kind, dedupe, r); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) ScheduleDeadlines(ctx context.Context, now time.Time) error {
	cs, e := s.Cases(ctx, User{ID: "scheduler", Role: "OWNER"})
	if e != nil {
		return e
	}
	for _, c := range cs {
		if c.CRA == nil {
			continue
		}
		for _, d := range Deadlines(c.CRA, now) {
			if d.Due == nil || d.Submitted != nil {
				continue
			}
			start := c.CRA.Awareness
			if d.Stage == "final" {
				if c.CRA.Classification == "VULNERABILITY" && c.CRA.CorrectiveAt != nil {
					start = *c.CRA.CorrectiveAt
				} else {
					for _, f := range c.CRA.Filings {
						if f.Stage == "notification" {
							start = f.At
						}
					}
				}
			}
			total := d.Due.Sub(start)
			if total <= 0 {
				continue
			}
			pct := int(now.Sub(start) * 100 / total)
			threshold := 0
			for _, n := range []int{50, 75, 90, 100} {
				if pct >= n {
					threshold = n
				}
			}
			if threshold == 0 {
				continue
			}
			kind := fmt.Sprintf("deadline:%s:%d:%s", d.Stage, threshold, d.Due.UTC().Format(time.RFC3339))
			e = s.transaction(ctx, func(tx *sql.Tx) error { return s.enqueueCase(ctx, tx, c, kind, false) })
			if e != nil {
				return e
			}
		}
	}
	return nil
}

type MailSender interface {
	Send(context.Context, string, string, string, string) error
}
type SMTPConfig struct {
	Address, Username, Password, From, PublicURL string
	TLSRootCAs                                   *x509.CertPool
}

func LoadSMTPRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("SMTP CA file contains no certificates")
	}
	return pool, nil
}

func (c SMTPConfig) Validate() error {
	host, _, e := net.SplitHostPort(c.Address)
	if e != nil || host == "" {
		return errors.New("SMTP address must be host:port")
	}
	a, e := mail.ParseAddress(c.From)
	if e != nil || a.Address != c.From || strings.ContainsAny(c.From, "\r\n") {
		return errors.New("SMTP sender must be a plain email address")
	}
	return nil
}
func (c SMTPConfig) Send(ctx context.Context, to, id, subject, body string) error {
	if e := c.Validate(); e != nil {
		return e
	}
	a, e := mail.ParseAddress(to)
	if e != nil || a.Address != to || strings.ContainsAny(to+subject+id, "\r\n") {
		return errors.New("invalid mail header")
	}
	host, _, _ := net.SplitHostPort(c.Address)
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, e := dialer.DialContext(ctx, "tcp", c.Address)
	if e != nil {
		return e
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	client, e := smtp.NewClient(conn, host)
	if e != nil {
		return e
	}
	defer client.Close()
	tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: c.TLSRootCAs}
	if e = client.StartTLS(tlsConfig); e != nil {
		return e
	}
	if c.Username != "" {
		if e = client.Auth(smtp.PlainAuth("", c.Username, c.Password, host)); e != nil {
			return e
		}
	}
	if e = client.Mail(c.From); e != nil {
		return e
	}
	if e = client.Rcpt(to); e != nil {
		return e
	}
	w, e := client.Data()
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nMessage-ID: <%s@beacon.local>\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", c.From, to, id, subject, body)
	if e != nil {
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	return client.Quit()
}
func (s *Store) DeliverOne(ctx context.Context, sender MailSender, publicURL string) (bool, error) {
	var n Notification
	var b []byte
	lease := RandomHex(32)
	e := s.DB.QueryRowContext(ctx, `UPDATE notifications SET lease_until=now()+interval '2 minutes',lease_token=$1,attempts=attempts+1 WHERE id=(SELECT id FROM notifications WHERE state IN ('PENDING','FAILED') AND sent IS NULL AND attempts<10 AND available<=now() AND (lease_until IS NULL OR lease_until<now()) ORDER BY created FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,case_ref,kind,recipient,attempts`, lease).Scan(&n.ID, &n.Ref, &n.Kind, &b, &n.Attempts)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	plain, e := s.Crypto.Open(b, "notification:"+n.ID)
	if e != nil {
		return true, s.markLeasedFailure(ctx, n.ID, n.Ref, lease, "Notification payload unavailable")
	}
	var r recipient
	if e = json.Unmarshal(plain, &r); e != nil {
		return true, s.markLeasedFailure(ctx, n.ID, n.Ref, lease, "Notification payload invalid")
	}
	// Re-check access and deadline state when delivering, not only when queued.
	c, e := s.Case(ctx, n.Ref)
	if e != nil {
		return true, s.markLeasedFailure(ctx, n.ID, n.Ref, lease, "Notification case unavailable")
	}
	valid := true
	if !r.Reporter {
		u, err := s.UserByEmail(ctx, r.Address)
		valid = err == nil && CanRead(u, c)
	}
	if strings.HasPrefix(n.Kind, "deadline:") {
		validDeadline := false
		for _, d := range Deadlines(c.CRA, time.Now().UTC()) {
			if d.Due != nil && d.Submitted == nil && strings.HasPrefix(n.Kind, "deadline:"+d.Stage+":") && strings.HasSuffix(n.Kind, ":"+d.Due.UTC().Format(time.RFC3339)) {
				validDeadline = true
			}
		}
		valid = valid && validDeadline
	}
	if !valid {
		err := s.transaction(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "UPDATE notifications SET state='CANCELLED',sent=now(),last_error='Cancelled: recipient access or deadline changed',lease_until=NULL,lease_token='' WHERE id=$1 AND lease_token=$2", n.ID, lease); err != nil {
				return err
			}
			return audit(ctx, tx, "worker", "notification.cancelled", n.Ref, n.ID)
		})
		return true, err
	}
	path := "/app/cases/" + n.Ref
	if r.Reporter {
		path = "/recover"
	}
	body := "Beacon case " + n.Ref + " requires your attention.\n\n" + publicURL + path + "\n\nSign in to view the update. No vulnerability details are included in this email."
	e = sender.Send(ctx, r.Address, n.ID, "Beacon case "+n.Ref+" update", body)
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		if e != nil {
			delay := time.Duration(1<<min(n.Attempts, 9)) * time.Minute
			_, err := tx.ExecContext(ctx, "UPDATE notifications SET state=CASE WHEN attempts>=10 THEN 'FAILED' ELSE 'PENDING' END,last_error='Delivery failed; check SMTP configuration or availability',available=$1,lease_until=NULL,lease_token='' WHERE id=$2 AND lease_token=$3", time.Now().Add(delay), n.ID, lease)
			if err != nil {
				return err
			}
			return audit(ctx, tx, "worker", "notification.failed", n.Ref, n.ID)
		}
		result, err := tx.ExecContext(ctx, "UPDATE notifications SET state='ACCEPTED',sent=now(),last_error='',lease_until=NULL,lease_token='' WHERE id=$1 AND lease_token=$2", n.ID, lease)
		if err != nil {
			return err
		}
		count, _ := result.RowsAffected()
		if count == 0 {
			return errors.New("notification lease lost")
		}
		return audit(ctx, tx, "worker", "notification.delivered", n.Ref, n.ID)
	})
	return true, err
}
func (s *Store) markLeasedFailure(ctx context.Context, id, ref, lease, message string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE notifications SET state=CASE WHEN attempts>=10 THEN 'FAILED' ELSE 'PENDING' END,last_error=$1,available=$2,lease_until=NULL,lease_token='' WHERE id=$3 AND lease_token=$4", message, time.Now().Add(time.Minute), id, lease); err != nil {
			return err
		}
		return audit(ctx, tx, "worker", "notification.failed", ref, id)
	})
}
func (s *Store) Notifications(ctx context.Context) ([]Notification, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,case_ref,kind,created,attempts,sent,last_error,state FROM notifications ORDER BY created DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var ns []Notification
	for rows.Next() {
		var n Notification
		if e = rows.Scan(&n.ID, &n.Ref, &n.Kind, &n.Created, &n.Attempts, &n.Sent, &n.Error, &n.State); e != nil {
			return nil, e
		}
		ns = append(ns, n)
	}
	return ns, rows.Err()
}

// NotificationAlert exposes only queue health, so an operator alert never
// needs to include recipients or case content.
func (s *Store) NotificationAlert(ctx context.Context) (failed, stalePending int, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE state='FAILED'), count(*) FILTER (WHERE state='PENDING' AND created < now()-interval '15 minutes') FROM notifications`).Scan(&failed, &stalePending)
	return
}
func (s *Store) RunWorker(ctx context.Context, sender MailSender, publicURL string) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		err := s.ScheduleDeadlines(workCtx, time.Now().UTC())
		if err == nil && sender != nil {
			for i := 0; i < 20; i++ {
				found, e := s.DeliverOne(workCtx, sender, publicURL)
				if e != nil || !found {
					if e != nil {
						slog.Error("notification worker delivery failed")
					}
					break
				}
			}
		}
		if err != nil {
			slog.Error("notification scheduling failed")
		}
		if failed, stale, alertErr := s.NotificationAlert(workCtx); alertErr != nil {
			slog.Error("notification health check failed")
		} else if failed > 0 || stale > 0 {
			slog.Error("notification delivery alert", "failed", failed, "pending_older_than_15m", stale)
		}
		_, _ = s.DB.ExecContext(workCtx, "DELETE FROM oidc_states WHERE expires<now(); DELETE FROM rate_limits WHERE started<now()-interval '2 hours'; DELETE FROM sessions WHERE expires<now()")
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
