package idp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cleanroom/internal/jwtmini"
)

func startProvider(t *testing.T) (*Provider, *httptest.Server) {
	t.Helper()
	p, err := New("http://placeholder.invalid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	p.Issuer = srv.URL
	t.Cleanup(srv.Close)
	return p, srv
}

const pkceVerifier = "test-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

func pkceChallenge() string {
	sum := sha256.Sum256([]byte(pkceVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// runAuthCodeFlow performs the full login + PKCE flow and returns the
// token endpoint response.
func runAuthCodeFlow(t *testing.T, srv *httptest.Server, verifier string) (int, map[string]any) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), "http://localhost:8402/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	q := url.Values{
		"response_type": {"code"}, "client_id": {"demo-client"},
		"redirect_uri":   {"http://localhost:8402/callback"},
		"scope":          {"openid records:read records:write"},
		"code_challenge": {pkceChallenge()}, "code_challenge_method": {"S256"},
		"state": {"s1"}, "nonce": {"n1"},
	}
	resp, err := client.Get(srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("authorize unauthenticated: status %d, want login form 200", resp.StatusCode)
	}
	resp2, err := client.PostForm(srv.URL+"/login", url.Values{
		"username": {"fixture-user"}, "password": {"fixture-password"},
		"return": {"/authorize?" + q.Encode()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	loc := resp2.Header.Get("Location")
	if resp2.StatusCode != 302 || !strings.Contains(loc, "code=") {
		t.Fatalf("post-login: status %d loc %q, want 302 with code", resp2.StatusCode, loc)
	}
	code := strings.SplitN(strings.SplitN(loc, "code=", 2)[1], "&", 2)[0]
	return postToken(t, srv, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri":  {"http://localhost:8402/callback"},
		"code_verifier": {verifier},
	}, "demo-client", "fixture-client-secret")
}

func postToken(t *testing.T, srv *httptest.Server, form url.Values, id, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

func TestDiscoveryAndJWKS(t *testing.T) {
	_, srv := startProvider(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != srv.URL {
		t.Fatalf("issuer = %v, want %v", doc["issuer"], srv.URL)
	}
	if doc["jwks_uri"] != srv.URL+"/jwks" {
		t.Fatalf("jwks_uri = %v", doc["jwks_uri"])
	}
	resp2, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var jwks map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&jwks)
	keys := jwtmini.PublicKeysFromJWKS(jwks)
	if len(keys) != 1 {
		t.Fatalf("jwks keys = %d, want 1", len(keys))
	}
}

func TestPKCEFlowEndToEnd(t *testing.T) {
	p, srv := startProvider(t)
	status, tok := runAuthCodeFlow(t, srv, pkceVerifier)
	if status != 200 {
		t.Fatalf("token exchange: status %d body %v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	idTok, _ := tok["id_token"].(string)
	if access == "" || idTok == "" {
		t.Fatalf("missing tokens: %v", tok)
	}
	claims, err := p.VerifyAccessToken(access)
	if err != nil {
		t.Fatalf("access token does not verify: %v", err)
	}
	if jwtmini.StringClaim(claims, "role") != "human" ||
		jwtmini.StringClaim(claims, "tenant") != "tenant-acme" {
		t.Fatalf("claims role/tenant wrong: %v", claims)
	}
	idClaims, err := jwtmini.VerifyRS256(&p.Key.PublicKey, idTok)
	if err != nil {
		t.Fatal(err)
	}
	if jwtmini.StringClaim(idClaims, "aud") != "demo-client" ||
		jwtmini.StringClaim(idClaims, "nonce") != "n1" {
		t.Fatalf("id_token claims wrong: %v", idClaims)
	}
	// userinfo
	req, _ := http.NewRequest("GET", srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if info["sub"] != "user-1001" || info["email"] != "fixture.user@example.invalid" {
		t.Fatalf("userinfo = %v", info)
	}
}

func TestWrongPKCEVerifierRejected(t *testing.T) {
	_, srv := startProvider(t)
	status, body := runAuthCodeFlow(t, srv, "the-wrong-verifier-value-0123456789")
	if status != 400 {
		t.Fatalf("wrong verifier: status %d body %v, want 400", status, body)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	_, srv := startProvider(t)
	// First exchange happens inside runAuthCodeFlow with a fresh code; to
	// test reuse we capture a code manually.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), "http://localhost:8402/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	q := url.Values{
		"response_type": {"code"}, "client_id": {"demo-client"},
		"redirect_uri":   {"http://localhost:8402/callback"},
		"scope":          {"openid records:read"},
		"code_challenge": {pkceChallenge()}, "code_challenge_method": {"S256"},
	}
	resp, _ := client.Get(srv.URL + "/authorize?" + q.Encode())
	resp.Body.Close()
	resp2, err := client.PostForm(srv.URL+"/login", url.Values{
		"username": {"fixture-user"}, "password": {"fixture-password"},
		"return": {"/authorize?" + q.Encode()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	code := strings.SplitN(strings.SplitN(resp2.Header.Get("Location"), "code=", 2)[1], "&", 2)[0]
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri":  {"http://localhost:8402/callback"},
		"code_verifier": {pkceVerifier},
	}
	if status, _ := postToken(t, srv, form, "demo-client", "fixture-client-secret"); status != 200 {
		t.Fatalf("first exchange: %d", status)
	}
	if status, _ := postToken(t, srv, form, "demo-client", "fixture-client-secret"); status != 400 {
		t.Fatalf("code reuse: status %d, want 400", status)
	}
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	_, srv := startProvider(t)
	resp, err := http.Get(srv.URL + "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {"demo-client"},
		"redirect_uri": {"http://localhost:8402/callback"}, "scope": {"openid"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("missing PKCE: status %d, want 400", resp.StatusCode)
	}
}

func TestAgentClientCredentials(t *testing.T) {
	p, srv := startProvider(t)
	status, tok := postToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "scope": {"records:read"},
	}, "agent-client", "fixture-agent-secret")
	if status != 200 {
		t.Fatalf("agent token: status %d %v", status, tok)
	}
	claims, err := p.VerifyAccessToken(tok["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if jwtmini.StringClaim(claims, "role") != "agent" {
		t.Fatalf("role = %q, want agent", jwtmini.StringClaim(claims, "role"))
	}
	// The agent client asking for write scope is refused at issuance.
	status, body := postToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "scope": {"records:write"},
	}, "agent-client", "fixture-agent-secret")
	if status != 400 || body["error"] != "invalid_scope" {
		t.Fatalf("agent write scope: status %d body %v, want 400 invalid_scope", status, body)
	}
	// The human client may not use client_credentials at all.
	status, _ = postToken(t, srv, url.Values{
		"grant_type": {"client_credentials"},
	}, "demo-client", "fixture-client-secret")
	if status != 400 {
		t.Fatalf("demo-client client_credentials: status %d, want 400", status)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	p, srv := startProvider(t)
	_, tok := postToken(t, srv, url.Values{
		"grant_type": {"client_credentials"}, "scope": {"records:read"},
	}, "agent-client", "fixture-agent-secret")
	access := tok["access_token"].(string)
	realNow := p.Now
	p.Now = func() time.Time { return realNow().Add(11 * time.Minute) }
	defer func() { p.Now = realNow }()
	if _, err := p.VerifyAccessToken(access); err == nil {
		t.Fatal("expired token verified successfully")
	}
	_ = srv
}
