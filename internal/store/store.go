// Package store is cleanroom-auth's data layer: a tiny file-backed table
// store with ROLE ENFORCEMENT INSIDE the data layer.
//
// The security property lives here, not in any prompt and not only in the
// API: every operation takes a Principal, and when enforcement is on, an
// agent-role principal cannot execute a write verb at all — Insert, Update
// and Delete return a typed ErrForbidden before touching any data — and no
// principal can touch another tenant's records, whatever its role.
//
// The same store, constructed with enforce=false, is the breach suite's
// unenforced baseline: identical code, enforcement switch off, so the
// measured difference is the enforcement and nothing else.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

type Role string

const (
	RoleAgent Role = "agent"
	RoleHuman Role = "human"
)

// Principal is the authenticated identity a store operation runs as. Role
// and Tenant come from the verified access token; they are never taken
// from request payloads.
type Principal struct {
	Subject string
	Role    Role
	Tenant  string
	Scopes  []string
}

func (p Principal) HasScope(s string) bool {
	for _, sc := range p.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// Record is one row. Fields is free-form string data, the kind of content a
// records API serves and an agent reads — including, in the breach suite,
// poisoned fields carrying injected instructions.
type Record struct {
	ID     string            `json:"id"`
	Tenant string            `json:"tenant"`
	Owner  string            `json:"owner"`
	Fields map[string]string `json:"fields"`
}

// ErrForbidden is returned when a principal's role does not permit the verb.
type ErrForbidden struct {
	Role Role
	Verb string
}

func (e *ErrForbidden) Error() string {
	return fmt.Sprintf("store: role %q may not execute verb %s", e.Role, e.Verb)
}

// ErrNotFound is returned for missing records AND for records belonging to
// another tenant, so reads never leak cross-tenant existence.
var ErrNotFound = errors.New("store: record not found")

type diskFormat struct {
	Records map[string]*Record `json:"records"`
}

// Store is a mutex-guarded, JSON-file-backed set of records.
type Store struct {
	mu      sync.Mutex
	path    string // empty = in-memory only
	enforce bool
	records map[string]*Record
}

// Open loads (or creates) a store at path. enforce=true turns on role and
// tenant enforcement; the breach suite's baseline uses enforce=false.
func Open(path string, enforce bool) (*Store, error) {
	s := &Store{path: path, enforce: enforce, records: map[string]*Record{}}
	if path != "" {
		b, err := os.ReadFile(path)
		if err == nil {
			var df diskFormat
			if err := json.Unmarshal(b, &df); err != nil {
				return nil, fmt.Errorf("store: corrupt file %s: %w", path, err)
			}
			if df.Records != nil {
				s.records = df.Records
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(diskFormat{Records: s.records}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o600)
}

// checkWrite is the enforcement core: agent-role principals may not write,
// in any code path, however well-formed the request is.
func (s *Store) checkWrite(p Principal, verb string) error {
	if s.enforce && p.Role == RoleAgent {
		return &ErrForbidden{Role: p.Role, Verb: verb}
	}
	return nil
}

func (s *Store) visibleLocked(p Principal, r *Record) bool {
	if !s.enforce {
		return true
	}
	return r.Tenant == p.Tenant
}

// Insert adds a new record. The record's tenant is forced to the
// principal's tenant under enforcement (a caller cannot mint records into
// another tenant by asking).
func (s *Store) Insert(p Principal, r *Record) error {
	if err := s.checkWrite(p, "INSERT"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[r.ID]; exists {
		return fmt.Errorf("store: record %q already exists", r.ID)
	}
	cp := *r
	if s.enforce {
		cp.Tenant = p.Tenant
	}
	s.records[cp.ID] = &cp
	return s.saveLocked()
}

// Get returns one record by id, tenant-scoped under enforcement.
func (s *Store) Get(p Principal, id string) (*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || !s.visibleLocked(p, r) {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

// List returns the records visible to the principal: its own tenant's under
// enforcement, every tenant's without it (the baseline's exfil surface).
func (s *Store) List(p Principal) ([]*Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*Record{}
	for _, r := range s.records {
		if s.visibleLocked(p, r) {
			cp := *r
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Update merges fields into an existing record.
func (s *Store) Update(p Principal, id string, fields map[string]string) error {
	if err := s.checkWrite(p, "UPDATE"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || !s.visibleLocked(p, r) {
		return ErrNotFound
	}
	if r.Fields == nil {
		r.Fields = map[string]string{}
	}
	for k, v := range fields {
		r.Fields[k] = v
	}
	return s.saveLocked()
}

// Delete removes a record.
func (s *Store) Delete(p Principal, id string) error {
	if err := s.checkWrite(p, "DELETE"); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	if !ok || !s.visibleLocked(p, r) {
		return ErrNotFound
	}
	delete(s.records, id)
	return s.saveLocked()
}

// CountAll is a test/suite introspection helper: total records regardless
// of tenancy. It bypasses visibility by design and is not exposed via API.
func (s *Store) CountAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}
