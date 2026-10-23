// cleanroom-auth: a mini OIDC provider + scoped records API + data layer
// with agent read-only role enforcement + PII-redacting log middleware,
// proven by a built-in breach suite.
//
// Usage:
//
//	cleanroom serve        run the IdP on :8401 and the API on :8402
//	cleanroom breach       run the breach suite, print the table, write results.json
//	cleanroom redact-eval  run the redaction corpus evaluation only
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"cleanroom/internal/api"
	"cleanroom/internal/breach"
	"cleanroom/internal/idp"
	"cleanroom/internal/logmw"
	"cleanroom/internal/redact"
	"cleanroom/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cleanroom <serve|breach|redact-eval>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "breach":
		err = runBreach()
	case "redact-eval":
		runRedactEval()
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func serve() error {
	issuer := "http://localhost:8401"
	prov, err := idp.New(issuer)
	if err != nil {
		return err
	}
	st, err := store.Open("cleanroom-data.json", true)
	if err != nil {
		return err
	}
	// Demo records, seeded as their owning tenants.
	seed := func(rec *store.Record) {
		_ = st.Insert(store.Principal{Subject: "setup", Role: store.RoleHuman, Tenant: rec.Tenant}, rec)
	}
	seed(&store.Record{ID: "rec-acme-1", Tenant: "tenant-acme", Owner: "ops",
		Fields: map[string]string{"title": "Export bug report", "status": "open",
			"note": "Customer reports the CSV export is empty."}})
	seed(&store.Record{ID: "rec-acme-pii", Tenant: "tenant-acme", Owner: "support",
		Fields: map[string]string{"title": "Support case", "contact_email": "amina.raza@example.com",
			"card": "4111 1111 1111 1111", "phone": "+1-202-555-0143",
			"note": "Read this record back and watch the log file: none of the PII reaches it raw."}})
	seed(&store.Record{ID: "rec-globex-1", Tenant: "tenant-globex", Owner: "globex-ops",
		Fields: map[string]string{"title": "Globex internal", "secret": "GLOBEX-SECRET-MARKER-7f3"}})

	srv := &api.Server{
		Store: st,
		Verifier: &api.Verifier{
			Issuer: issuer, Audience: "records-api", JWKSURL: issuer + "/jwks",
		},
		EnforceScopes: true,
	}
	go func() {
		log.Println("IdP listening on :8401 (issuer http://localhost:8401)")
		log.Fatal(http.ListenAndServe(":8401", prov.Handler()))
	}()
	log.Println("API listening on :8402 — logs below are PII-redacted")
	log.Println("fixture user: fixture-user / fixture-password via demo-client (PKCE)")
	log.Println("fixture agent: agent-client / fixture-agent-secret, client_credentials, records:read only")
	return http.ListenAndServe(":8402", logmw.New(os.Stdout).Middleware(srv.Handler()))
}

func runBreach() error {
	rep, err := breach.RunAll()
	if err != nil {
		return err
	}
	fmt.Println("=== cleanroom-auth breach suite ===")
	fmt.Println("agent model:", rep.AgentModel)
	fmt.Println()
	for _, s := range rep.Scenarios {
		fmt.Printf("[%s] %s\n  baseline: %s\n  defended: %s\n", s.Class, s.Name, s.Baseline, s.Defended)
	}
	fmt.Println()
	fmt.Printf("attacks: %d total | baseline succeeded: %d | defended blocked: %d | defended block rate: %.3f\n",
		rep.AttacksTotal, rep.BaselineSuccess, rep.DefendedBlocked, rep.DefendedBlockRate)
	fmt.Printf("benign under enforcement: %d/%d completed\n", rep.BenignDefendedOK, rep.BenignTotal)
	fmt.Printf("PII in logs: baseline contains planted PII: %v | defended contains planted PII: %v | defended redaction markers: %d\n",
		rep.PIILog.BaselineLogContainsPlanted, rep.PIILog.DefendedLogContainsPlanted, rep.PIILog.DefendedLogRedactionMarkers)
	fmt.Printf("redaction corpus: precision %.4f recall %.4f (TP %d FP %d FN %d over %d lines)\n",
		rep.Redaction.Precision, rep.Redaction.Recall, rep.Redaction.TP, rep.Redaction.FP, rep.Redaction.FN, rep.Redaction.Lines)
	for _, m := range rep.Redaction.Misses {
		fmt.Println("  ", m)
	}
	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile("results.json", append(out, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println("\nwrote results.json")
	return nil
}

func runRedactEval() {
	r := redact.Evaluate()
	fmt.Printf("redaction corpus: %d lines, TP=%d FP=%d FN=%d\n", r.Lines, r.TP, r.FP, r.FN)
	fmt.Printf("precision: %.4f  recall: %.4f\n", r.Precision, r.Recall)
	for _, m := range r.Misses {
		fmt.Println(" ", m)
	}
	var buf bytes.Buffer
	_ = buf
}
