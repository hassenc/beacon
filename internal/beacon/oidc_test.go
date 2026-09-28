package beacon

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

func TestOIDCCallbackSecurity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	var encoded, expectedVerifier string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/keys" {
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &private.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
			return
		}
		if e := r.ParseForm(); e != nil || r.Form.Get("code_verifier") != expectedVerifier {
			http.Error(w, "PKCE missing", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": encoded})
	}))
	defer issuer.Close()
	app, e := NewApp(s, Config{URL: "http://localhost:8787", Organization: "Test", Dev: true, Expires: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	app.federation = &federation{OAuth: oauth2.Config{ClientID: "beacon-test", ClientSecret: "test-only", Endpoint: oauth2.Endpoint{AuthURL: issuer.URL + "/authorize", TokenURL: issuer.URL + "/token"}}, Verifier: oidc.NewVerifier(issuer.URL, oidc.NewRemoteKeySet(ctx, issuer.URL+"/keys"), &oidc.Config{ClientID: "beacon-test"}), ACR: "mfa"}
	s.DB.Exec("UPDATE users SET oidc_subject='subject-1'")
	for _, scenario := range []string{"valid", "wrong-nonce", "wrong-audience", "expired", "wrong-acr", "unprovisioned", "wrong-browser", "tampered"} {
		t.Run(scenario, func(t *testing.T) {
			start := httptest.NewRecorder()
			app.oidcStart(start, httptest.NewRequest("GET", "/auth/login", nil))
			location, _ := url.Parse(start.Header().Get("Location"))
			state := location.Query().Get("state")
			nonce := location.Query().Get("nonce")
			var encrypted []byte
			if e := s.DB.QueryRow("SELECT payload FROM oidc_states WHERE hash=$1", Hash(state)).Scan(&encrypted); e != nil {
				t.Fatal(e)
			}
			plain, _ := s.Crypto.Open(encrypted, "oidc:"+Hash(state))
			var stored oidcState
			json.Unmarshal(plain, &stored)
			expectedVerifier = stored.Verifier
			claims := map[string]any{"iss": issuer.URL, "aud": "beacon-test", "sub": "subject-1", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce, "acr": "mfa"}
			switch scenario {
			case "wrong-nonce":
				claims["nonce"] = "wrong"
			case "wrong-audience":
				claims["aud"] = "other"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			case "wrong-acr":
				claims["acr"] = "password"
			case "unprovisioned":
				claims["sub"] = "other"
			}
			encoded, e = jwt.Signed(signer).Claims(claims).Serialize()
			if e != nil {
				t.Fatal(e)
			}
			if scenario == "tampered" {
				encoded = encoded[:len(encoded)-20] + "invalidsignature"
			}
			req := httptest.NewRequest("GET", "/auth/callback?state="+state+"&code=test", nil)
			cookie := start.Result().Cookies()[0]
			if scenario == "wrong-browser" {
				cookie.Value = "wrong"
			}
			req.AddCookie(cookie)
			out := httptest.NewRecorder()
			app.oidcCallback(out, req)
			if scenario == "valid" {
				if out.Code != 303 || out.Header().Get("Location") != "/app" {
					t.Fatalf("login failed: %d %s", out.Code, out.Body.String())
				}
			} else if out.Code != 403 {
				t.Fatalf("invalid identity accepted: %d", out.Code)
			}
			if scenario != "wrong-browser" {
				replay := httptest.NewRecorder()
				app.oidcCallback(replay, req)
				if replay.Code != 403 {
					t.Fatal("replayed callback accepted")
				}
			}
		})
	}
}
