// Package api is cleanroom-auth's resource API: a demo records service
// guarded by access-token verification against the IdP's JWKS over HTTP —
// signature, issuer, audience, expiry, and per-endpoint scope. The store
// principal is built exclusively from verified claims.
//
// The EnforceScopes flag exists for one reason: the breach suite's baseline
// is this same API with scope checks off and the store unenforced, so the
// measured difference is the enforcement, not a different codebase.
package api

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cleanroom/internal/jwtmini"
	"cleanroom/internal/store"
)

// Verifier validates RS256 access tokens against a remote JWKS.
type Verifier struct {
	Issuer   string
	Audience string
	JWKSURL  string
	Now      func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) fetchKeys() (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(v.JWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return jwtmini.PublicKeysFromJWKS(doc), nil
}

// Verify checks signature, issuer, audience and expiry; returns claims.
func (v *Verifier) Verify(token string) (map[string]any, error) {
	header, _, err := jwtmini.ParseUnverified(token)
	if err != nil {
		return nil, err
	}
	kid, _ := header["kid"].(string)
	keys, err := v.fetchKeys()
	if err != nil {
		return nil, fmt.Errorf("api: jwks fetch: %w", err)
	}
	pub, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("api: unknown kid %q", kid)
	}
	claims, err := jwtmini.VerifyRS256(pub, token)
	if err != nil {
		return nil, err
	}
	if jwtmini.StringClaim(claims, "iss") != v.Issuer {
		return nil, fmt.Errorf("api: wrong issuer")
	}
	if jwtmini.StringClaim(claims, "aud") != v.Audience {
		return nil, fmt.Errorf("api: wrong audience")
	}
	if jwtmini.TimeClaim(claims, "exp") < v.now().Unix() {
		return nil, fmt.Errorf("api: token expired")
	}
	return claims, nil
}

// Server is the records API.
type Server struct {
	Store         *store.Store
	Verifier      *Verifier
	EnforceScopes bool // false only for the breach suite's baseline
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /records", s.auth("records:read", s.list))
	mux.HandleFunc("GET /records/{id}", s.auth("records:read", s.get))
	mux.HandleFunc("POST /records", s.auth("records:write", s.create))
	mux.HandleFunc("PUT /records/{id}", s.auth("records:write", s.update))
	mux.HandleFunc("DELETE /records/{id}", s.auth("records:write", s.del))
	return mux
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p store.Principal)

func (s *Server) auth(scope string, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			httpError(w, 401, "missing bearer token")
			return
		}
		claims, err := s.Verifier.Verify(strings.TrimPrefix(authz, "Bearer "))
		if err != nil {
			httpError(w, 401, "invalid token: "+err.Error())
			return
		}
		p := store.Principal{
			Subject: jwtmini.StringClaim(claims, "sub"),
			Role:    store.Role(jwtmini.StringClaim(claims, "role")),
			Tenant:  jwtmini.StringClaim(claims, "tenant"),
			Scopes:  strings.Fields(jwtmini.StringClaim(claims, "scope")),
		}
		if s.EnforceScopes && !p.HasScope(scope) {
			httpError(w, 403, "insufficient scope: need "+scope)
			return
		}
		h(w, r, p)
	}
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, p store.Principal) {
	recs, err := s.Store.List(p)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, recs)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, p store.Principal) {
	rec, err := s.Store.Get(p, r.PathValue("id"))
	if err != nil {
		httpError(w, 404, "record not found")
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var rec store.Record
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		httpError(w, 400, "bad record json")
		return
	}
	if err := s.Store.Insert(p, &rec); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, rec)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var fields map[string]string
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		httpError(w, 400, "bad fields json")
		return
	}
	if err := s.Store.Update(p, r.PathValue("id"), fields); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "updated"})
}

func (s *Server) del(w http.ResponseWriter, r *http.Request, p store.Principal) {
	if err := s.Store.Delete(p, r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// writeStoreError maps the store's typed errors to HTTP: a role-forbidden
// write is a 403 whose body names the enforcement layer that stopped it.
func writeStoreError(w http.ResponseWriter, err error) {
	var forb *store.ErrForbidden
	if errors.As(err, &forb) {
		httpError(w, 403, "blocked at data layer: "+forb.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		httpError(w, 404, "record not found")
		return
	}
	httpError(w, 400, err.Error())
}
