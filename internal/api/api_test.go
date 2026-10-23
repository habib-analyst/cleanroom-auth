package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cleanroom/internal/idp"
	"cleanroom/internal/jwtmini"
	"cleanroom/internal/store"
)

type testStack struct {
	prov   *idp.Provider
	idpSrv *httptest.Server
	apiSrv *httptest.Server
	st     *store.Store
}

func buildStack(t *testing.T) *testStack {
	t.Helper()
	prov, err := idp.New("http://placeholder.invalid")
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := httptest.NewServer(prov.Handler())
	prov.Issuer = idpSrv.URL
	st, _ := store.Open("", true)
	human := store.Principal{Subject: "setup", Role: store.RoleHuman, Tenant: "tenant-acme"}
	_ = st.Insert(human, &store.Record{ID: "r1", Tenant: "tenant-acme",
		Fields: map[string]string{"title": "Hello"}})
	srv := &Server{
		Store:         st,
		Verifier:      &Verifier{Issuer: idpSrv.URL, Audience: "records-api", JWKSURL: idpSrv.URL + "/jwks"},
		EnforceScopes: true,
	}
	apiSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { idpSrv.Close(); apiSrv.Close() })
	return &testStack{prov: prov, idpSrv: idpSrv, apiSrv: apiSrv, st: st}
}

func agentToken(t *testing.T, ts *testStack) string {
	t.Helper()
	form := strings.NewReader("grant_type=client_credentials&scope=records:read")
	req, _ := http.NewRequest("POST", ts.idpSrv.URL+"/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("agent-client", "fixture-agent-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("no agent token: %v", out)
	}
	return tok
}

func call(t *testing.T, ts *testStack, method, path, token, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, ts.apiSrv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestNoTokenAndGarbageToken(t *testing.T) {
	ts := buildStack(t)
	if status, _ := call(t, ts, "GET", "/records/r1", "", ""); status != 401 {
		t.Fatalf("no token: %d, want 401", status)
	}
	if status, _ := call(t, ts, "GET", "/records/r1", "not.a.jwt", ""); status != 401 {
		t.Fatalf("garbage token: %d, want 401", status)
	}
}

func TestAgentCanReadCannotWrite(t *testing.T) {
	ts := buildStack(t)
	tok := agentToken(t, ts)
	if status, body := call(t, ts, "GET", "/records/r1", tok, ""); status != 200 || !strings.Contains(body, "Hello") {
		t.Fatalf("agent read: %d %s", status, body)
	}
	if status, _ := call(t, ts, "POST", "/records", tok, `{"id":"rX","fields":{}}`); status != 403 {
		t.Fatalf("agent POST: %d, want 403 (scope)", status)
	}
	if status, _ := call(t, ts, "DELETE", "/records/r1", tok, ""); status != 403 {
		t.Fatalf("agent DELETE: %d, want 403 (scope)", status)
	}
}

func TestExpiredAndWrongAudienceTokensRejected(t *testing.T) {
	ts := buildStack(t)
	now := time.Now()
	base := map[string]any{
		"iss": ts.idpSrv.URL, "sub": "client:agent-client", "aud": "records-api",
		"iat": now.Unix(), "role": "agent", "tenant": "tenant-acme", "scope": "records:read",
	}
	expired := map[string]any{}
	for k, v := range base {
		expired[k] = v
	}
	expired["exp"] = now.Add(-time.Minute).Unix()
	tokExp, err := jwtmini.Sign(ts.prov.Key, expired)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := call(t, ts, "GET", "/records/r1", tokExp, ""); status != 401 {
		t.Fatalf("expired token: %d, want 401", status)
	}
	wrongAud := map[string]any{}
	for k, v := range base {
		wrongAud[k] = v
	}
	wrongAud["exp"] = now.Add(time.Hour).Unix()
	wrongAud["aud"] = "some-other-api"
	tokAud, err := jwtmini.Sign(ts.prov.Key, wrongAud)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := call(t, ts, "GET", "/records/r1", tokAud, ""); status != 401 {
		t.Fatalf("wrong-audience token: %d, want 401", status)
	}
	wrongIss := map[string]any{}
	for k, v := range base {
		wrongIss[k] = v
	}
	wrongIss["exp"] = now.Add(time.Hour).Unix()
	wrongIss["iss"] = "http://evil.example"
	tokIss, err := jwtmini.Sign(ts.prov.Key, wrongIss)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := call(t, ts, "GET", "/records/r1", tokIss, ""); status != 401 {
		t.Fatalf("wrong-issuer token: %d, want 401", status)
	}
}

func TestHumanScopeTokenCanWrite(t *testing.T) {
	ts := buildStack(t)
	now := time.Now()
	tok, err := jwtmini.Sign(ts.prov.Key, map[string]any{
		"iss": ts.idpSrv.URL, "sub": "user-1001", "aud": "records-api",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"role": "human", "tenant": "tenant-acme", "scope": "records:read records:write",
	})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := call(t, ts, "POST", "/records", tok, `{"id":"r2","fields":{"title":"New"}}`); status != 201 {
		t.Fatalf("human POST: %d, want 201", status)
	}
}
