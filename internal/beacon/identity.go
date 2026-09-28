package beacon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Store) BeginMFA(ctx context.Context, u User, password string) (string, string, error) {
	if u.Disabled || !PasswordOK(password, u.Password) {
		return "", "", errors.New("current password is incorrect")
	}
	key, e := totp.Generate(totp.GenerateOpts{Issuer: "Beacon", AccountName: u.Email, SecretSize: 32})
	if e != nil {
		return "", "", e
	}
	e = s.transaction(ctx, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx, "UPDATE users SET mfa_secret=$1,mfa_last_step=-1 WHERE id=$2 AND NOT mfa_enabled AND NOT disabled AND auth_generation=$3", s.Crypto.Seal([]byte(key.Secret()), "mfa:"+u.ID), u.ID, u.AuthGeneration)
		if e != nil {
			return e
		}
		n, _ := res.RowsAffected()
		if n != 1 {
			return errors.New("MFA is already enabled")
		}
		return audit(ctx, tx, u.ID, "mfa.enrollment.started", u.ID, "")
	})
	return key.Secret(), key.URL(), e
}
func totpStep(secret, code string, now time.Time) (int64, bool) {
	opts := totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	base := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		step := base + offset
		valid, e := totp.ValidateCustom(code, secret, time.Unix(step*30, 0), opts)
		if e == nil && valid {
			return step, true
		}
	}
	return 0, false
}
func (s *Store) ConsumeMFA(ctx context.Context, id, code string, enroll bool) ([]string, error) {
	return s.consumeMFA(ctx, id, code, enroll, nil)
}
func (s *Store) ConsumeMFABound(ctx context.Context, id, code string, enroll bool, generation int64) ([]string, error) {
	return s.consumeMFA(ctx, id, code, enroll, &generation)
}
func (s *Store) consumeMFA(ctx context.Context, id, code string, enroll bool, expectedGeneration *int64) ([]string, error) {
	var codes []string
	e := s.transaction(ctx, func(tx *sql.Tx) error {
		var b []byte
		var enabled, disabled bool
		var generation int64
		var last int64
		var recovery pq.StringArray
		if e := tx.QueryRowContext(ctx, "SELECT mfa_secret,mfa_enabled,mfa_last_step,recovery_hashes,disabled,auth_generation FROM users WHERE id=$1 FOR UPDATE", id).Scan(&b, &enabled, &last, &recovery, &disabled, &generation); e != nil {
			return e
		}
		if disabled || enroll == enabled || expectedGeneration != nil && generation != *expectedGeneration {
			return errors.New("invalid MFA state")
		}
		if !enroll {
			for i, h := range recovery {
				if Hash(code) == h {
					recovery = append(recovery[:i], recovery[i+1:]...)
					if _, e := tx.ExecContext(ctx, "UPDATE users SET recovery_hashes=$1 WHERE id=$2", recovery, id); e != nil {
						return e
					}
					return audit(ctx, tx, id, "mfa.recovery.used", id, "")
				}
			}
		}
		secret, e := s.Crypto.Open(b, "mfa:"+id)
		if e != nil {
			return errors.New("enroll an authenticator first")
		}
		step, valid := totpStep(string(secret), code, time.Now())
		if !valid || step <= last {
			return errors.New("invalid or already used authenticator code")
		}
		if enroll {
			recovery = nil
			for i := 0; i < 10; i++ {
				v := RandomHex(16)
				codes = append(codes, v)
				recovery = append(recovery, Hash(v))
			}
		}
		set := "mfa_enabled=true,mfa_last_step=$1,recovery_hashes=$2"
		if enroll {
			set += ",auth_generation=auth_generation+1"
		}
		if _, e = tx.ExecContext(ctx, "UPDATE users SET "+set+" WHERE id=$3", step, recovery, id); e != nil {
			return e
		}
		if enroll {
			if _, e = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=$1", id); e != nil {
				return e
			}
			return audit(ctx, tx, id, "mfa.enabled", id, "Existing sessions revoked")
		}
		return nil
	})
	return codes, e
}
func (s *Store) ChangePassword(ctx context.Context, u User, old, next, code string) error {
	if len(next) < 16 || len(next) > 1024 || !PasswordOK(old, u.Password) {
		return errors.New("current password or new password length is invalid")
	}
	if u.MFAEnabled {
		if _, e := s.ConsumeMFABound(ctx, u.ID, code, false, u.AuthGeneration); e != nil {
			return e
		}
	}
	hash := PasswordHash(next)
	return s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, u.ID)
		if e != nil || current.Disabled || current.AuthGeneration != u.AuthGeneration || !PasswordOK(old, current.Password) {
			return errors.New("authentication state changed; retry with the current credentials")
		}
		if _, e := tx.ExecContext(ctx, "UPDATE users SET password=$1,auth_generation=auth_generation+1 WHERE id=$2", hash, u.ID); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=$1", u.ID); e != nil {
			return e
		}
		return audit(ctx, tx, u.ID, "password.changed", u.ID, "All sessions revoked")
	})
}
func (s *Store) ManageUser(ctx context.Context, actor User, id, role, subject string, disabled bool) error {
	if !Contains(Roles, role) || id == actor.ID {
		return errors.New("an owner may manage another account only")
	}
	if len(subject) > 500 {
		return errors.New("OIDC subject too long")
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		current, e := lockUser(ctx, tx, actor.ID)
		if e != nil {
			return e
		}
		if e = validateActor(actor, current); e != nil {
			return e
		}
		if current.Role != "OWNER" {
			return errors.New("an owner may manage another account only")
		}
		var oldRole string
		if e := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id=$1 FOR UPDATE", id).Scan(&oldRole); e != nil {
			return e
		}
		if oldRole == "OWNER" && (disabled || role != "OWNER") {
			var n int
			if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE role='OWNER' AND NOT disabled").Scan(&n); e != nil {
				return e
			}
			if n < 2 {
				return errors.New("cannot remove the last active owner")
			}
		}
		if _, e := tx.ExecContext(ctx, "UPDATE users SET role=$1,disabled=$2,oidc_subject=$3,auth_generation=auth_generation+1 WHERE id=$4", role, disabled, subject, id); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=$1", id); e != nil {
			return e
		}
		return audit(ctx, tx, current.ID, "user.updated", id, fmt.Sprintf("role=%s disabled=%t; sessions revoked", role, disabled))
	})
}
func (s *Store) RevokeSession(ctx context.Context, hash string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var user, ref string
		e := tx.QueryRowContext(ctx, "DELETE FROM sessions WHERE hash=$1 RETURNING user_id,case_ref", hash).Scan(&user, &ref)
		if e == sql.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		if user == "" {
			user = "reporter"
		}
		return audit(ctx, tx, user, "session.revoked", ref, "")
	})
}
func (s *Store) RotateReporter(ctx context.Context, ref, actor string) (string, error) {
	return s.rotateReporter(ctx, ref, actor, "", nil)
}
func (s *Store) RotateReporterBound(ctx context.Context, ref, actor, sessionHash string) (string, error) {
	return s.rotateReporter(ctx, ref, actor, sessionHash, nil)
}
func (s *Store) RotateReporterAs(ctx context.Context, ref string, actor User) (string, error) {
	return s.rotateReporter(ctx, ref, actor.ID, "", &actor)
}
func (s *Store) rotateReporter(ctx context.Context, ref, actor, sessionHash string, actorSnapshot *User) (string, error) {
	token := "BCN-RCVR-" + RandomHex(32)
	e := s.transaction(ctx, func(tx *sql.Tx) error {
		if actor != "reporter" {
			current, e := lockUser(ctx, tx, actor)
			if e != nil {
				return e
			}
			if actorSnapshot != nil {
				if e = validateActor(*actorSnapshot, current); e != nil {
					return e
				}
			}
			if !CanManage(current) {
				return errors.New("Not permitted")
			}
		}
		var version int
		if e := tx.QueryRowContext(ctx, "SELECT token_version FROM cases WHERE ref=$1 FOR UPDATE", ref).Scan(&version); e != nil {
			return e
		}
		if actor == "reporter" && sessionHash != "" {
			var valid int
			if e := tx.QueryRowContext(ctx, "SELECT 1 FROM sessions WHERE hash=$1 AND case_ref=$2 AND token_version=$3 AND expires>now() FOR UPDATE", sessionHash, ref, version).Scan(&valid); e != nil {
				return errors.New("reporter access was revoked; reload the report")
			}
		}
		if _, e := tx.ExecContext(ctx, "UPDATE cases SET token_hash=$1,token_version=token_version+1 WHERE ref=$2", Hash(token), ref); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, "DELETE FROM sessions WHERE case_ref=$1", ref); e != nil {
			return e
		}
		return audit(ctx, tx, actor, "reporter.access.rotated", ref, "Previous token and sessions revoked")
	})
	return token, e
}
func (a *App) account(w http.ResponseWriter, r *http.Request) {
	u, ref, e := a.principal(r, "session")
	if e != nil || u.ID == "" || ref != "" {
		http.Redirect(w, r, "/login", 303)
		return
	}
	a.render(w, r, "account", Page{Title: "Account security", User: u, Active: "account"})
}
func (a *App) accountAction(w http.ResponseWriter, r *http.Request) {
	u, ref, e := a.principal(r, "session")
	if e != nil || u.ID == "" || ref != "" {
		a.fail(w, r, 403, "Sign in first")
		return
	}
	if !a.allow(r, "account", 20) {
		a.fail(w, r, 429, "Too many attempts")
		return
	}
	if !a.passwordCheck(w, r) {
		return
	}
	defer func() { <-a.passwordSlots }()
	if len(r.FormValue("password")) > 1024 || len(r.FormValue("new_password")) > 1024 {
		a.fail(w, r, 400, "Password is too long")
		return
	}
	p := Page{Title: "Account security", User: u, Active: "account"}
	switch r.PathValue("action") {
	case "enroll":
		p.Secret, p.OTPURL, e = a.Store.BeginMFA(r.Context(), u, r.FormValue("password"))
	case "confirm":
		p.RecoveryCodes, e = a.Store.ConsumeMFABound(r.Context(), u.ID, r.FormValue("code"), true, u.AuthGeneration)
		if e == nil {
			p.Notice = "MFA enabled. Save these recovery codes once, then sign in again."
			p.User = User{}
			a.cookie(w, "session", "", -1)
		} else {
			_ = a.Store.Audit(r.Context(), u.ID, "mfa.enrollment.failed", u.ID, "Invalid MFA proof")
		}
	case "password":
		e = a.Store.ChangePassword(r.Context(), u, r.FormValue("password"), r.FormValue("new_password"), r.FormValue("code"))
		if e == nil {
			a.cookie(w, "session", "", -1)
			http.Redirect(w, r, "/login", 303)
			return
		}
	case "sessions":
		e = a.Store.transaction(r.Context(), func(tx *sql.Tx) error {
			current, e := lockUser(r.Context(), tx, u.ID)
			if e != nil {
				return e
			}
			if e = validateActor(u, current); e != nil {
				return e
			}
			if _, e := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id=$1", u.ID); e != nil {
				return e
			}
			return audit(r.Context(), tx, u.ID, "sessions.revoked", u.ID, "")
		})
		if e == nil {
			a.cookie(w, "session", "", -1)
			http.Redirect(w, r, "/login", 303)
			return
		}
	default:
		a.fail(w, r, 404, "Action not found")
		return
	}
	if e != nil {
		p.Error = e.Error()
	}
	a.render(w, r, "account", p)
}
func (a *App) manageUser(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if e := a.Store.ManageUser(r.Context(), u, r.FormValue("id"), r.FormValue("role"), strings.TrimSpace(r.FormValue("subject")), r.FormValue("disabled") == "yes"); e != nil {
		a.fail(w, r, 400, e.Error())
		return
	}
	http.Redirect(w, r, "/app/settings", 303)
}
func (a *App) reporterRotate(w http.ResponseWriter, r *http.Request) {
	ref, ok := a.reporterRef(w, r)
	if !ok {
		return
	}
	cookie, e := r.Cookie(a.cookieName("reporter"))
	if e != nil {
		a.fail(w, r, 403, "Reporter session expired")
		return
	}
	token, e := a.Store.RotateReporterBound(r.Context(), ref, "reporter", Hash(cookie.Value))
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.cookie(w, "reporter", "", -1)
	a.render(w, r, "receipt", Page{Title: "Recovery token rotated", Ref: ref, Token: token})
}
func (a *App) notificationPage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.internal(w, r)
	if !ok {
		return
	}
	if !CanManage(u) {
		a.fail(w, r, 403, "Owner/Triage access required")
		return
	}
	if r.Method == "POST" {
		e := a.Store.transaction(r.Context(), func(tx *sql.Tx) error {
			current, e := lockUser(r.Context(), tx, u.ID)
			if e != nil {
				return e
			}
			if e = validateActor(u, current); e != nil {
				return e
			}
			if !CanManage(current) {
				return errors.New("Owner/Triage access required")
			}
			if _, e := tx.ExecContext(r.Context(), "UPDATE notifications SET state='PENDING',attempts=0,available=now(),sent=NULL,lease_until=NULL,lease_token='' WHERE id=$1 AND state IN ('FAILED','CANCELLED') AND (lease_until IS NULL OR lease_until<now())", r.FormValue("id")); e != nil {
				return e
			}
			return audit(r.Context(), tx, current.ID, "notification.retry", r.FormValue("id"), "")
		})
		if e != nil {
			a.storageError(w, r, e)
			return
		}
		http.Redirect(w, r, "/app/notifications", 303)
		return
	}
	ns, e := a.Store.Notifications(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	failed, stale, e := a.Store.NotificationAlert(r.Context())
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.render(w, r, "notifications", Page{Title: "Delivery queue", User: u, Notifications: ns, NotificationAlert: failed > 0 || stale > 0, SMTPEnabled: a.Config.SMTP.Address != ""})
}
func parseRevision(r *http.Request) int { n, _ := strconv.Atoi(r.FormValue("revision")); return n }
