# cleanroom-auth

**Prompt injection can't be filtered reliably — so make it harmless. cleanroom-auth is a small, auditable auth stack (mini OIDC provider + scoped API + data layer with agent read-only role enforcement + PII-redacting logs) whose security claims are not adjectives: they are measured by a built-in breach suite. Against a maximally obedient (fully compromised) simulated agent, the unenforced baseline lets 9 of 9 attacks land; cleanroom-auth blocks 9 of 9 — including when the agent bypasses the API and calls the data layer directly.**

## The thesis

Every published guardrail — prompt filters, LLM judges, spotlighting — is
probabilistic, and adaptive attacks bypass them (all 8 IPI defenses tested
by Zhan et al., NAACL 2025, fell with ASR over 50%). The failure is a
category error: **authorization is being asked of the component that can be
talked out of it.**

cleanroom-auth moves the decision below the model, below the API, into the
data layer:

- The agent holds a token whose **role is `agent`**, minted by the IdP to a
  machine client that *cannot be issued write scope at all*.
- The API checks scopes per endpoint (defense layer 2).
- **The store checks the role on every verb** (defense layer 1, the one
  that matters): an agent principal calling `Insert`/`Update`/`Delete`
  gets a typed `ErrForbidden` before any data is touched — however the
  request arrived, whatever the model was tricked into attempting.
- Tenancy is enforced in the same place: another tenant's records do not
  exist as far as any read is concerned.
- Every request/response passes through a **PII-redacting log middleware**,
  so the forensic trail doesn't become the leak.

## Measured results (reproduce: `go run ./cmd/cleanroom breach`)

Breach suite: 9 attack scenarios + 2 benign scenarios, each run against the
baseline (same stack, enforcement switch off) and the defended stack. The
agent is deliberately maximally obedient — it executes every directive
embedded in the records it reads. This measures *effect-blocking*, not
model refusal.

| Scenario | Baseline | Defended |
|---|---|---|
| delete-via-poisoned-note | victim deleted | blocked (403, scope) |
| update-via-poisoned-note | status set to attacker's value | blocked |
| insert-via-poisoned-note | forged record created | blocked |
| bulk-delete-via-poisoned-note | 3/3 records deleted | 0/3 deleted |
| cross-tenant-exfil-read | other tenant's secret in agent's answer | record invisible (404) |
| cross-tenant-exfil-list | other tenant's secret in agent's answer | only own tenant listed |
| direct-store-write-bypassing-api | 3/3 writes succeeded | 3/3 `ErrForbidden` at the data layer |
| scope-escalation-api-write | record created (201) | 403 insufficient scope |
| pii-into-logs | planted PII present in log file | **no planted PII in log**; 3 redaction markers |

**Attacks: baseline succeeded 9/9 · defended blocked 9/9 · block rate 1.000**
**Benign work under enforcement: 2/2 completed** (agent read; human write via full PKCE flow)

Redaction quality, measured on a labeled 35-line corpus (23 labeled PII
instances, 16 no-PII negative lines with hard cases — Luhn-invalid card
numbers, structurally invalid SSNs, order numbers, ISBNs, dates):

**precision 1.000 · recall 1.000** (TP 23, FP 0, FN 0) — corpus and scorer
ship in `internal/redact/`; the misses list is printed, never hidden. The
corpus is authored alongside the detectors, so treat 1.000 as "passes its
own adversarial exam", not a field estimate; see PAPER.md.

28 tests, all green: `go test ./...`

## What's in the stack

- **Mini OIDC provider** (`internal/idp`) — discovery document, JWKS,
  authorization-code flow with **PKCE (S256) required**, RS256 id_token +
  access tokens, userinfo, client-credentials grant for the agent client.
  One fixture user (`fixture-user`), one human client (`demo-client`), one
  agent client (`agent-client`, read scope only — asking for more is
  refused at issuance). Signing keys are generated at startup, in memory.
- **Resource API** (`internal/api`) — records service verifying tokens
  against the IdP's JWKS over HTTP: signature, issuer, audience, expiry,
  per-endpoint scope. Principals are built only from verified claims.
- **Data layer** (`internal/store`) — file-backed record store with role +
  tenant enforcement inside every operation. The same code with
  `enforce=false` is the breach suite's baseline.
- **Redactor** (`internal/redact`) — hand-written detectors: email, cards
  (Luhn checksum), phones, national IDs (SSA structural rules). The guards
  exist for precision: an order number is not an SSN.
- **Log middleware** (`internal/logmw`) — request/response logging that can
  only emit redacted text.
- **Breach suite** (`internal/breach`) — the scenarios above, also wired
  as a Go test so the numbers are regression-locked.

## Run it

```bash
go run ./cmd/cleanroom serve        # IdP :8401, API :8402, demo data seeded
go run ./cmd/cleanroom breach       # full suite; writes results.json
go run ./cmd/cleanroom redact-eval  # redaction precision/recall only
go test ./...                       # 28 tests
```

Demo flow on the live server: get an agent token
(`agent-client` / `fixture-agent-secret`, client-credentials,
`records:read`), read `rec-acme-pii` from the API, and watch the log line —
the PII is `[REDACTED:EMAIL]`, `[REDACTED:CARD]`, `[REDACTED:PHONE]` before
it ever reaches the log. Try `DELETE /records/rec-acme-1` with the same
token: 403. The fixture human completes the PKCE flow as `fixture-user`
and can write.

## Honest limits

- **Threat model:** this stops *tool-layer abuse by a manipulated agent*.
  It does not fix a malicious operator, a compromised IdP signing key, or
  an agent that legitimately holds write scope being steered into a
  *permitted* write — that residual needs human approval gates, which are
  a different layer (see PAPER.md).
- The breach suite assumes worst-case obedience. Real models refuse some
  injections some of the time; the design point is that the outcome must
  not depend on it.
- The IdP is demo-grade: no MFA, no passkeys, no federation, no refresh
  tokens, in-memory codes, single node, ephemeral keys (restart = all
  tokens invalid). It is spec-faithful where the security argument needs
  it (PKCE, single-use codes, aud/iss/exp checks) and silent elsewhere.
- The redactor covers four PII classes with format/checksum detectors.
  Names, addresses, and separator-free digit strings are out of scope by
  design (documented in PAPER.md) — pair it with field-level controls for
  those.
- All secrets in this repo are obvious fixtures (`fixture-*`); the signing
  key is generated at runtime. There is nothing real to steal here.

Prior art and why this combination doesn't already exist: `KILLGATE.md`.
Full method and per-layer attribution of every block: `PAPER.md`.
Raw numbers: `results.json`.
