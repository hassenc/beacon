package beacon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

type OIDCConfig struct{ Issuer, ClientID, ClientSecret, RequiredACR string }
type federation struct {
	OAuth    oauth2.Config
	Verifier *oidc.IDTokenVerifier
	ACR      string
}
type oidcState struct{ Nonce, Verifier string }

func newFederation(ctx context.Context, c OIDCConfig, base string, dev bool) (*federation, error) {
	if c.Issuer == "" {
		return nil, nil
	}
	u, e := url.Parse(c.Issuer)
	if e != nil || u.Host == "" || u.Scheme != "https" || c.ClientID == "" || c.ClientSecret == "" || (!dev && c.RequiredACR == "") {
		return nil, errors.New("OIDC requires HTTPS issuer, client ID/secret, and a production MFA ACR value")
	}
	provider, e := oidc.NewProvider(ctx, c.Issuer)
	if e != nil {
		return nil, errors.New("OIDC provider discovery failed")
	}
	return &federation{OAuth: oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: base + "/auth/callback", Endpoint: provider.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, Verifier: provider.Verifier(&oidc.Config{ClientID: c.ClientID}), ACR: c.RequiredACR}, nil
}
func (a *App) oidcStart(w http.ResponseWriter, r *http.Request) {
	if a.federation == nil {
		a.fail(w, r, 404, "SSO is not configured")
		return
	}
	if !a.allow(r, "oidc", 20) {
		a.fail(w, r, 429, "Too many attempts")
		return
	}
	state, browser := RandomHex(32), RandomHex(32)
	s := oidcState{RandomHex(32), oauth2.GenerateVerifier()}
	b, _ := json.Marshal(s)
	if _, e := a.Store.DB.ExecContext(r.Context(), "INSERT INTO oidc_states VALUES($1,$2,$3,$4)", Hash(state), Hash(browser), a.Store.Crypto.Seal(b, "oidc:"+Hash(state)), time.Now().Add(5*time.Minute)); e != nil {
		a.storageError(w, r, e)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookieName("oidc"), Value: browser, Path: "/", HttpOnly: true, Secure: !a.Config.Dev, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	options := []oauth2.AuthCodeOption{oidc.Nonce(s.Nonce), oauth2.S256ChallengeOption(s.Verifier)}
	if a.federation.ACR != "" {
		options = append(options, oauth2.SetAuthURLParam("acr_values", a.federation.ACR))
	}
	http.Redirect(w, r, a.federation.OAuth.AuthCodeURL(state, options...), 303)
}
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if a.federation == nil {
		a.fail(w, r, 404, "SSO is not configured")
		return
	}
	cookie, e := r.Cookie(a.cookieName("oidc"))
	if e != nil {
		a.fail(w, r, 403, "SSO browser state missing")
		return
	}
	state := r.URL.Query().Get("state")
	var b []byte
	e = a.Store.DB.QueryRowContext(r.Context(), "DELETE FROM oidc_states WHERE hash=$1 AND browser_hash=$2 AND expires>now() RETURNING payload", Hash(state), Hash(cookie.Value)).Scan(&b)
	a.cookie(w, "oidc", "", -1)
	if e != nil {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Invalid or expired browser state")
		a.fail(w, r, 403, "SSO state invalid or expired")
		return
	}
	plain, e := a.Store.Crypto.Open(b, "oidc:"+Hash(state))
	if e != nil {
		a.fail(w, r, 403, "SSO state invalid")
		return
	}
	var s oidcState
	if json.Unmarshal(plain, &s) != nil {
		a.fail(w, r, 403, "SSO state invalid")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, e := a.federation.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(s.Verifier))
	if e != nil {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Provider exchange failed")
		a.fail(w, r, 403, "SSO exchange failed")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Provider identity token missing")
		a.fail(w, r, 403, "SSO identity token missing")
		return
	}
	identity, e := a.federation.Verifier.Verify(ctx, raw)
	if e != nil || identity.Nonce != s.Nonce {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Provider identity verification failed")
		a.fail(w, r, 403, "SSO identity verification failed")
		return
	}
	var claims struct {
		ACR string `json:"acr"`
	}
	if identity.Claims(&claims) != nil || (a.federation.ACR != "" && claims.ACR != a.federation.ACR) {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Required assurance missing")
		a.fail(w, r, 403, "Required identity-provider assurance was not satisfied")
		return
	}
	var id string
	e = a.Store.DB.QueryRowContext(ctx, "SELECT id FROM users WHERE oidc_subject=$1 AND NOT disabled", identity.Subject).Scan(&id)
	if e == sql.ErrNoRows {
		_ = a.Store.Audit(r.Context(), "anonymous", "oidc.failed", "authentication", "Unprovisioned provider subject")
		a.fail(w, r, 403, "An owner must provision this exact identity-provider subject first")
		return
	}
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	u, e := a.Store.User(ctx, id)
	if e != nil || u.Disabled || u.OIDCSubject != identity.Subject {
		a.fail(w, r, 403, "SSO identity is no longer provisioned")
		return
	}
	session, e := a.Store.NewSessionBound(ctx, id, "", u.AuthGeneration)
	if e != nil {
		a.storageError(w, r, e)
		return
	}
	a.cookie(w, "session", session, 28800)
	http.Redirect(w, r, "/app", 303)
}
