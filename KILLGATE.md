# KILL-GATE — cleanroom-auth

**Verdict: PROCEED.** No available tool ships this combination with measured
security claims. The components exist separately; the packaged, auditable
stack whose headline numbers come from an adversarial breach suite does not.

## Prior art, and what each piece does NOT do

### Identity providers (the auth half exists, alone)
- **Keycloak** (Apache-2.0, CNCF): complete OIDC/SAML IdP, orgs, brokering.
  Needs a production DB and multi-instance cache to run properly. It issues
  tokens; it knows nothing about your agent's tool calls, your data layer's
  roles, or your logs. No breach suite, no measured enforcement claims.
- **Authentik**, **ZITADEL**, **Logto**, **Hanko**, **Pocket ID**: same shape,
  varying weight. All stop at the token.
- **Ory Hydra/Kratos** (Apache-2.0): headless OAuth2/OIDC server, deliberately
  *only* the protocol — you bring users, UI, and everything downstream.
  Some features are commercial-license only when self-hosted.

None of these enforces anything at a data layer, redacts a log, or measures
what happens when a manipulated agent uses the tokens they issue.

### PII redaction (the log half exists, alone)
- **Microsoft Presidio** (MIT, now community-led under Data Privacy Stack):
  analyzer + anonymizer SDK, regex + NER + checksums, Python. It is a
  library for pipelines — no IdP, no API authorization, no agent story.
  Presidio's own docs state there is "no guarantee that Presidio will find
  all sensitive information": detection quality is the user's problem to
  measure. Nobody ships Presidio-style redaction *with* a labeled-corpus
  precision/recall number attached to a specific deployment's middleware.

### Agent guardrails (prompt-level, probabilistic)
- **NeMo Guardrails / Guardrails AI / Rebuff-style filters**: operate on
  prompts and outputs — classifiers and LLM judges. They reduce injection
  success; they do not make a write *impossible*. Published adaptive-attack
  results (Zhan et al., NAACL 2025) bypassed all 8 tested IPI defenses with
  ASR consistently over 50%. A filter that usually says no is not an
  authorization boundary.

### Benchmarks (they measure models, not stacks)
- **InjecAgent** (ACL 2024), **AgentDojo**, **Agent Security Bench**,
  **AgentHarm**: measure whether a *model* complies with injected
  instructions (ReAct GPT-4: 24% vulnerable on InjecAgent; ASB: 84.3%
  average attack success across defenses). Essential research — but they
  grade the model's obedience, not whether a deployed system's data layer
  blocks the *effect* when obedience happens. They ship no IdP, no API,
  no store, no redactor.

### Practitioner guidance (agrees with the thesis, ships nothing)
- OWASP LLM01/LLM06 guidance and multiple 2025–2026 write-ups converge on:
  give the agent its own read-only DB role, least-privilege tools, log every
  tool call, "design for the case where the model obeys the attacker."
  This is published as checklists and blog architecture — advice, not a
  small runnable stack with numbers.

## The differentiation (the claim this build must prove)

1. **One small auditable stack** (stdlib-only Go, ~one sitting to read):
   mini OIDC provider (auth-code + PKCE, RS256, JWKS) → scoped resource
   API → data layer with role enforcement *inside* it → PII-redacting log
   middleware on every request.
2. **Enforcement at the database layer, not the prompt layer.** The agent's
   role is bound to its token and checked inside the store on every verb.
   A fully obedient (fully compromised) agent still cannot write, because
   the write is rejected below the model, below the API — in the data layer.
3. **The claims are measured, by a shipped breach suite.** Scripted
   maximally-obedient-agent scenarios (poisoned record fields directing
   DELETE / UPDATE / INSERT / cross-tenant exfiltration / PII-to-logs) run
   against the unenforced baseline and against cleanroom-auth; the report
   is per-scenario outcomes and block rates, not adjectives. Redaction
   quality is likewise a number: precision/recall on a labeled corpus with
   hard cases, misses printed.

## What would have killed it
- A single available product combining a mini IdP + DB-layer agent role
  enforcement + log redaction *with published block-rate measurements*
  from an adversarial suite. **Not found** (searched IdPs, Presidio,
  guardrail frameworks, agent-security benchmarks, practitioner write-ups,
  2026-10-23).
- Evidence that DB-layer enforcement does not in fact block well-formed
  tool-layer writes. Contradicted by construction: a rejected verb cannot
  partially execute. The suite verifies this empirically anyway.

## Honest scope limits (stated up front, repeated in README/PAPER)
- This stops **tool-layer abuse by a manipulated agent**. It does not fix
  a malicious operator, a compromised IdP signing key, or an agent that
  legitimately holds write scope and is steered into a *permitted* write.
- The breach suite assumes a maximally obedient agent (worst case). It
  measures effect-blocking, not model obedience — obedience rates are
  InjecAgent/AgentDojo's question, already answered (badly).
- Mini provider: no MFA, no passkeys, no federation, single node,
  ephemeral in-memory codes. Demo-grade IdP, production-grade argument.
