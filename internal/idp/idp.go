// Package idp is cleanroom-auth's mini OpenID Connect provider: discovery,
// JWKS, authorization-code flow with PKCE (S256), RS256 id_tokens and
// access tokens, a userinfo endpoint, and a client-credentials grant for
// the machine (agent) client.
//
// Fixture identities only: one demo user and two demo clients, all with
// obviously-synthetic secrets ("fixture-..."). Signing keys are generated
// at startup and never leave memory.
package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"cleanroom/internal/jwtmini"
)

// User is a fixture account.
type User struct {
	Username string
	Password string // fixture value, demo only
	Sub      string
	Name     string
	Email    string
	Tenant   string
}

// Client is a registered OAuth2 client fixture.
type Client struct {
	ID           string
	Secret       string // fixture value, demo only
	RedirectURIs []string
	Grants       []string // authorization_code, client_credentials
	Scopes       []string // scopes this client may ever receive
	Role         string   // role claim minted into access tokens
	Tenant       string   // tenant claim for client-credentials tokens
}

type authCode struct {
	ClientID, RedirectURI, Challenge, Scope, Sub, Tenant, Role, Nonce string
	ExpiresAt                                                         time.Time
	Used                                                              bool
}

// Provider is the OIDC provider. Safe for concurrent use.
type Provider struct {
	Issuer  string // e.g. http://localhost:8401 (no trailing slash)
	Key     *rsa.PrivateKey
	Users   map[string]*User   // by username
	Clients map[string]*Client // by client id
	Now     func() time.Time   // injectable clock for tests

	mu       sync.Mutex
	codes    map[string]*authCode
	sessions map[string]string // session cookie value -> sub
}

// New builds a provider with the standard fixture identities.
func New(issuer string) (*Provider, error) {
	key, err := jwtmini.GenerateKey()
	if err != nil {
		return nil, err
	}
	p := &Provider{
		Issuer:   strings.TrimSuffix(issuer, "/"),
		Key:      key,
		Now:      time.Now,
		codes:    map[string]*authCode{},
		sessions: map[string]string{},
		Users: map[string]*User{
			"fixture-user": {
				Username: "fixture-user", Password: "fixture-password",
				Sub: "user-1001", Name: "Fixture User",
				Email: "fixture.user@example.invalid", Tenant: "tenant-acme",
			},
		},
		Clients: map[string]*Client{
			"demo-client": {
				ID: "demo-client", Secret: "fixture-client-secret",
				RedirectURIs: []string{"http://localhost:8402/callback"},
				Grants:       []string{"authorization_code"},
				Scopes:       []string{"openid", "profile", "records:read", "records:write"},
				Role:         "human",
			},
			"agent-client": {
				ID: "agent-client", Secret: "fixture-agent-secret",
				Grants: []string{"client_credentials"},
				Scopes: []string{"records:read"}, // an agent client can never hold write scope
				Role:   "agent", Tenant: "tenant-acme",
			},
		},
	}
	return p, nil
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Handler returns the provider's HTTP routes.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /login", p.login)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"userinfo_endpoint":                     p.Issuer + "/userinfo",
		"jwks_uri":                              p.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "records:read", "records:write"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, jwtmini.JWKS(&p.Key.PublicKey))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Provider) sessionUser(r *http.Request) *User {
	c, err := r.Cookie("cleanroom_session")
	if err != nil {
		return nil
	}
	p.mu.Lock()
	sub, ok := p.sessions[c.Value]
	p.mu.Unlock()
	if !ok {
		return nil
	}
	for _, u := range p.Users {
		if u.Sub == sub {
			return u
		}
	}
	return nil
}

// authorize implements the authorization endpoint. Unauthenticated users
// get a login form that round-trips the original parameters through
// POST /login; authenticated users get a code redirect immediately.
// PKCE (S256) is required.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, ok := p.Clients[q.Get("client_id")]
	if !ok {
		oauthError(w, 400, "invalid_client", "unknown client_id")
		return
	}
	if q.Get("response_type") != "code" {
		oauthError(w, 400, "unsupported_response_type", "only response_type=code")
		return
	}
	redirectURI := q.Get("redirect_uri")
	validRedirect := false
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			validRedirect = true
		}
	}
	if !validRedirect {
		oauthError(w, 400, "invalid_request", "redirect_uri not registered for client")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		oauthError(w, 400, "invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if !scopeAllowed(client, q.Get("scope")) {
		oauthError(w, 400, "invalid_scope", "requested scope exceeds client's allowed scopes")
		return
	}
	user := p.sessionUser(r)
	if user == nil {
		// Minimal login form: fixtures only, demo-grade by design.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html><title>cleanroom-auth login</title>
<form method="POST" action="/login">
<label>Username <input name="username"></label>
<label>Password <input name="password" type="password"></label>
<input type="hidden" name="return" value="/authorize?%s">
<button type="submit">Sign in (fixture user: fixture-user)</button>
</form>`, q.Encode())
		return
	}
	code := randomHex(32)
	p.mu.Lock()
	p.codes[code] = &authCode{
		ClientID: client.ID, RedirectURI: redirectURI,
		Challenge: q.Get("code_challenge"), Scope: q.Get("scope"),
		Sub: user.Sub, Tenant: user.Tenant, Role: client.Role, Nonce: q.Get("nonce"),
		ExpiresAt: p.now().Add(5 * time.Minute),
	}
	p.mu.Unlock()
	target, _ := url.Parse(redirectURI)
	tq := target.Query()
	tq.Set("code", code)
	if st := q.Get("state"); st != "" {
		tq.Set("state", st)
	}
	target.RawQuery = tq.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *Provider) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "bad form")
		return
	}
	u, ok := p.Users[r.Form.Get("username")]
	if !ok || u.Password != r.Form.Get("password") {
		oauthError(w, 401, "access_denied", "invalid fixture credentials")
		return
	}
	sid := randomHex(24)
	p.mu.Lock()
	p.sessions[sid] = u.Sub
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "cleanroom_session", Value: sid, Path: "/", HttpOnly: true})
	ret := r.Form.Get("return")
	if !strings.HasPrefix(ret, "/authorize?") {
		ret = "/"
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

func scopeAllowed(client *Client, scope string) bool {
	for _, s := range strings.Fields(scope) {
		found := false
		for _, a := range client.Scopes {
			if a == s {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func hasGrant(client *Client, grant string) bool {
	for _, g := range client.Grants {
		if g == grant {
			return true
		}
	}
	return false
}

func (p *Provider) authenticateClient(r *http.Request) *Client {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	c, found := p.Clients[id]
	if !found || c.Secret != secret {
		return nil
	}
	return c
}

// AccessTokenTTL is the lifetime of minted access tokens.
const AccessTokenTTL = 10 * time.Minute

func (p *Provider) mintAccessToken(sub, role, tenant, scope string) (string, error) {
	now := p.now()
	return jwtmini.Sign(p.Key, map[string]any{
		"iss": p.Issuer, "sub": sub, "aud": "records-api",
		"iat": now.Unix(), "exp": now.Add(AccessTokenTTL).Unix(),
		"scope": scope, "role": role, "tenant": tenant,
	})
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "bad form")
		return
	}
	client := p.authenticateClient(r)
	if client == nil {
		oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		p.tokenAuthCode(w, r, client)
	case "client_credentials":
		p.tokenClientCredentials(w, r, client)
	default:
		oauthError(w, 400, "unsupported_grant_type", "supported: authorization_code, client_credentials")
	}
}

func (p *Provider) tokenAuthCode(w http.ResponseWriter, r *http.Request, client *Client) {
	if !hasGrant(client, "authorization_code") {
		oauthError(w, 400, "unauthorized_client", "client may not use authorization_code")
		return
	}
	codeVal := r.Form.Get("code")
	p.mu.Lock()
	code, ok := p.codes[codeVal]
	alreadyUsed := ok && code.Used
	if ok {
		code.Used = true // single-use, consumed on first presentation
	}
	p.mu.Unlock()
	if !ok || alreadyUsed || code.ClientID != client.ID {
		oauthError(w, 400, "invalid_grant", "unknown or already-used authorization code")
		return
	}
	if p.now().After(code.ExpiresAt) {
		oauthError(w, 400, "invalid_grant", "authorization code expired")
		return
	}
	if r.Form.Get("redirect_uri") != code.RedirectURI {
		oauthError(w, 400, "invalid_grant", "redirect_uri mismatch")
		return
	}
	verifier := r.Form.Get("code_verifier")
	if verifier == "" {
		oauthError(w, 400, "invalid_request", "code_verifier required")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != code.Challenge {
		oauthError(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}
	access, err := p.mintAccessToken(code.Sub, code.Role, code.Tenant, code.Scope)
	if err != nil {
		oauthError(w, 500, "server_error", err.Error())
		return
	}
	now := p.now()
	idClaims := map[string]any{
		"iss": p.Issuer, "sub": code.Sub, "aud": client.ID,
		"iat": now.Unix(), "exp": now.Add(AccessTokenTTL).Unix(),
	}
	if code.Nonce != "" {
		idClaims["nonce"] = code.Nonce
	}
	for _, u := range p.Users {
		if u.Sub == code.Sub {
			idClaims["name"] = u.Name
			idClaims["email"] = u.Email
		}
	}
	idToken, err := jwtmini.Sign(p.Key, idClaims)
	if err != nil {
		oauthError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token": access, "id_token": idToken,
		"token_type": "Bearer", "expires_in": int(AccessTokenTTL.Seconds()),
		"scope": code.Scope,
	})
}

func (p *Provider) tokenClientCredentials(w http.ResponseWriter, r *http.Request, client *Client) {
	if !hasGrant(client, "client_credentials") {
		oauthError(w, 400, "unauthorized_client", "client may not use client_credentials")
		return
	}
	scope := r.Form.Get("scope")
	if scope == "" {
		scope = strings.Join(client.Scopes, " ")
	}
	if !scopeAllowed(client, scope) {
		// The agent client asking for records:write lands here: refused at
		// issuance, before any enforcement downstream is even needed.
		oauthError(w, 400, "invalid_scope", "requested scope exceeds client's allowed scopes")
		return
	}
	access, err := p.mintAccessToken("client:"+client.ID, client.Role, client.Tenant, scope)
	if err != nil {
		oauthError(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(AccessTokenTTL.Seconds()), "scope": scope,
	})
}

// VerifyAccessToken validates an access token against this provider's key
// and the records-api audience. Used by userinfo; the resource API does
// the same check against JWKS over HTTP.
func (p *Provider) VerifyAccessToken(token string) (map[string]any, error) {
	claims, err := jwtmini.VerifyRS256(&p.Key.PublicKey, token)
	if err != nil {
		return nil, err
	}
	if jwtmini.StringClaim(claims, "iss") != p.Issuer {
		return nil, fmt.Errorf("idp: wrong issuer")
	}
	if jwtmini.StringClaim(claims, "aud") != "records-api" {
		return nil, fmt.Errorf("idp: wrong audience")
	}
	if jwtmini.TimeClaim(claims, "exp") < p.now().Unix() {
		return nil, fmt.Errorf("idp: token expired")
	}
	return claims, nil
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		oauthError(w, 401, "invalid_token", "bearer access token required")
		return
	}
	claims, err := p.VerifyAccessToken(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		oauthError(w, 401, "invalid_token", err.Error())
		return
	}
	sub := jwtmini.StringClaim(claims, "sub")
	out := map[string]any{"sub": sub}
	for _, u := range p.Users {
		if u.Sub == sub {
			out["name"] = u.Name
			out["email"] = u.Email
			out["tenant"] = u.Tenant
		}
	}
	writeJSON(w, 200, out)
}

// SortedScope is a tiny helper for deterministic scope strings in tests.
func SortedScope(scope string) string {
	f := strings.Fields(scope)
	sort.Strings(f)
	return strings.Join(f, " ")
}
