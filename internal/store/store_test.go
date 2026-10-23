package store

import (
	"errors"
	"path/filepath"
	"testing"
)

var (
	agentAcme = Principal{Subject: "client:agent-client", Role: RoleAgent, Tenant: "tenant-acme", Scopes: []string{"records:read"}}
	humanAcme = Principal{Subject: "user-1001", Role: RoleHuman, Tenant: "tenant-acme", Scopes: []string{"records:read", "records:write"}}
)

func seedStore(t *testing.T, enforce bool) *Store {
	t.Helper()
	s, err := Open("", enforce)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(humanAcme, &Record{ID: "r1", Tenant: "tenant-acme", Fields: map[string]string{"status": "open"}}); err != nil {
		t.Fatal(err)
	}
	globex := Principal{Subject: "g", Role: RoleHuman, Tenant: "tenant-globex"}
	if err := s.Insert(globex, &Record{ID: "r2", Tenant: "tenant-globex", Fields: map[string]string{"secret": "x"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAgentWriteVerbsRejected(t *testing.T) {
	s := seedStore(t, true)
	verbs := map[string]func() error{
		"INSERT": func() error { return s.Insert(agentAcme, &Record{ID: "r3", Fields: map[string]string{}}) },
		"UPDATE": func() error { return s.Update(agentAcme, "r1", map[string]string{"status": "pwned"}) },
		"DELETE": func() error { return s.Delete(agentAcme, "r1") },
	}
	for name, fn := range verbs {
		err := fn()
		var forb *ErrForbidden
		if !errors.As(err, &forb) {
			t.Fatalf("%s by agent: err = %v, want ErrForbidden", name, err)
		}
		if forb.Verb != name {
			t.Fatalf("ErrForbidden.Verb = %q, want %q", forb.Verb, name)
		}
	}
	// Nothing changed.
	if got, _ := s.Get(humanAcme, "r1"); got.Fields["status"] != "open" {
		t.Fatal("record mutated despite forbidden writes")
	}
	if s.CountAll() != 2 {
		t.Fatalf("count = %d, want 2", s.CountAll())
	}
}

func TestAgentReadsAllowed(t *testing.T) {
	s := seedStore(t, true)
	if _, err := s.Get(agentAcme, "r1"); err != nil {
		t.Fatalf("agent read own tenant: %v", err)
	}
	recs, err := s.List(agentAcme)
	if err != nil || len(recs) != 1 {
		t.Fatalf("agent list: %d records, err %v; want exactly its own tenant's 1", len(recs), err)
	}
}

func TestCrossTenantInvisible(t *testing.T) {
	s := seedStore(t, true)
	if _, err := s.Get(agentAcme, "r2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant get: err = %v, want ErrNotFound", err)
	}
	if err := s.Update(humanAcme, "r2", map[string]string{"secret": "y"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant update by human: err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(humanAcme, "r2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant delete by human: err = %v, want ErrNotFound", err)
	}
}

func TestHumanWritesAllowed(t *testing.T) {
	s := seedStore(t, true)
	if err := s.Update(humanAcme, "r1", map[string]string{"status": "closed"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(humanAcme, "r1"); err != nil {
		t.Fatal(err)
	}
	if s.CountAll() != 1 {
		t.Fatalf("count = %d, want 1", s.CountAll())
	}
}

func TestUnenforcedBaselineAllowsEverything(t *testing.T) {
	// Documents the ablation: with enforcement off, the same code lets an
	// agent write and read across tenants. This is what the breach suite's
	// baseline measures.
	s := seedStore(t, false)
	if err := s.Delete(agentAcme, "r1"); err != nil {
		t.Fatalf("baseline agent delete: %v", err)
	}
	recs, _ := s.List(agentAcme)
	if len(recs) != 1 || recs[0].ID != "r2" {
		t.Fatalf("baseline list should expose the other tenant's record, got %v", recs)
	}
}

func TestPersistenceRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	s, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Insert(humanAcme, &Record{ID: "keep", Fields: map[string]string{"a": "b"}}); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path, true)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s2.Get(humanAcme, "keep")
	if err != nil || rec.Fields["a"] != "b" {
		t.Fatalf("reloaded record: %v %v", rec, err)
	}
}
