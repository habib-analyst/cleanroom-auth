# cleanroom-auth: enforcement at the data layer, measured by a breach suite

## 1. Problem

Tool-using LLM agents read untrusted content — records, notes, retrieved
documents — in the same context window that decides their tool calls. An
attacker who can write into that content (a poisoned record field is
enough) can direct the agent's tools. The benchmark literature measures
how often models comply: InjecAgent found a ReAct-prompted GPT-4
vulnerable 24% of the time; the Agent Security Bench reports an 84.3%
average attack success rate across defenses; adaptive attacks bypassed
all 8 published IPI defenses tested by Zhan et al. (NAACL 2025) with ASR
consistently over 50%.

The deployed defenses are mostly more prompts: system-prompt constraints,
input/output filters, LLM supervisors. Each is a probability, and the
probabilities are not good. Meanwhile the classical answer sits unused in
most agent stacks: **the agent's database identity should not be able to
write at all**, so a fully successful injection has no effect to land.

cleanroom-auth is that answer, built as one small stdlib-only Go stack and
— the part the category is missing — **shipped with the measurement**: a
breach suite that runs scripted attacks against an unenforced baseline
and the defended stack and reports per-scenario outcomes.

## 2. Architecture and where each guarantee lives

Four components, three enforcement layers:

1. **IdP** (`internal/idp`): mini OIDC provider. Authorization-code flow
   with PKCE S256 *required*; codes are single-use, 5-minute-lived, and
   bound to client + redirect URI. RS256 tokens; JWKS published. The agent
   is a client-credentials client whose registered scope ceiling is
   `records:read` — a request for `records:write` fails with
   `invalid_scope` **at issuance**. Role (`agent`/`human`) and tenant are
   claims minted by the IdP, never accepted from request payloads.
2. **API** (`internal/api`): verifies signature/issuer/audience/expiry
   against JWKS fetched over HTTP, then checks the endpoint's scope —
   writes require `records:write`. Builds the store principal solely from
   verified claims.
3. **Store** (`internal/store`): the load-bearing layer. Every operation
   takes a principal. With enforcement on:
   - agent-role principals get `*store.ErrForbidden` (a typed error
     naming the verb) from `Insert`/`Update`/`Delete` before any data is
     touched;
   - records outside the principal's tenant are invisible — `Get` returns
     `ErrNotFound` (existence is not leaked), `List` filters, writes to
     foreign records are `ErrNotFound`, and `Insert` forces the record's
     tenant to the principal's;
   - persistence is a JSON file written on each mutation.
4. **Log middleware** (`internal/logmw` + `internal/redact`): all request
   and response bodies are logged through the redactor. Detectors:
   email (regex), payment cards (shape + **Luhn checksum**), phones
   (separated/grouped shapes only), national IDs (SSN shape + **SSA
   structural validity**: area 000/666/9xx, group 00, serial 0000 are
   rejected). The checksum/validity guards are precision machinery:
   without them, order numbers and ISBNs become false positives.

The baseline in every experiment is *the same code* with the enforcement
switch off (`store.Open(path, false)`, API scope checks disabled, raw
logger). The ablation is the argument: one switch, opposite outcomes.

## 3. Method: the breach suite

The simulated agent is a deterministic, **maximally obedient** tool
executor: it reads a record through the real API with a real agent token,
scans the content for embedded directives (a bracketed syntax stands in
for natural-language instructions, for reproducibility), executes each
one through the API, and appends read/list results to its answer — the
exfiltration channel. Obedience is assumed, not measured: models'
obedience rates are InjecAgent/AgentDojo's question, and designing for
anything less than 100% obedience is designing for the attacker's bad
days.

Nine attack scenarios: poisoned-note DELETE / UPDATE / INSERT,
bulk DELETE (3 records from one note), cross-tenant exfiltration via
READ and via LIST, a direct data-layer write attempt bypassing the API
entirely, a scope-escalation write through the API, and PII-into-logs
(the agent reads a PII-laden record; the effect is assessed by grepping
the actual log sink for the three planted values). Two benign scenarios
(agent read; human write through the full PKCE flow) verify the stack
still works for legitimate work.

## 4. Results

All numbers from `go run ./cmd/cleanroom breach` (also `results.json`),
reproduced identically across runs; the suite also runs as a Go test
(`internal/breach`), so regressions fail CI-style.

**Attacks: baseline 9/9 succeeded; defended 9/9 blocked; block rate 1.000.**
**Benign: 2/2 completed under enforcement.**

Per-layer attribution — which layer actually stopped each attack in the
defended stack (this is the honest detail a single "block rate" hides):

- Note-embedded writes (delete/update/insert/bulk) and the
  scope-escalation write were stopped at the **API scope layer** (403):
  the agent token simply has no write scope. The data layer never saw
  them.
- The **direct-store scenario isolates the data layer**: with no API in
  the path, all three verbs returned `ErrForbidden`, zero effects. This is
  the guarantee that survives an API bug, a second API, or a future tool
  that talks to the store directly.
- Both exfiltration scenarios were stopped by **store tenant isolation**
  (the API passed the reads through with a valid read scope; the store
  returned nothing foreign). The agent's answers contained no trace of
  the other tenant's marker value.
- PII-into-logs: the baseline log contains all three planted values raw;
  the defended log contains **none**, with 3 `[REDACTED:*]` markers where
  they would have been. Verified by string search over the real log
  sinks, not by inspecting the middleware.

**Redaction evaluation** (labeled corpus, 35 lines, span-exact scoring):
23 labeled PII instances — TP 23, FP 0, FN 0; **precision 1.000, recall
1.000**. Negatives included a Luhn-invalid card-shaped number, a
structurally invalid SSN (area 000), an ISBN, order/invoice numbers,
dates, a hash, coordinates, and short phone fragments; none were flagged.

**A bug the tests caught in this build:** the first version of the token
endpoint consumed authorization codes without rejecting replays — the
single-use test failed (second exchange returned 200), the check was
fixed, and the suite now regression-locks it. An auth stack whose own
tests catch an auth bug before anyone else does is the process working
as intended; it is reported here because a measurement-first project
reports its misses.

## 5. Threat model — what is and is not defended

**Defended:** a manipulated agent (indirect prompt injection through data
it reads) attempting writes, cross-tenant reads, or PII leakage into logs
through its tools. The defense does not depend on detecting the
injection, on the model's behaviour, or on the API being the only path
to the data.

**Not defended, stated plainly:**
- An agent that *legitimately holds write scope* being steered into a
  permitted-but-harmful write. Least privilege shrinks this surface; the
  remaining control is human approval for sensitive writes (out of scope
  here, and incompatible with pretending the problem is solved).
- A malicious operator or insider with human credentials.
- A compromised IdP (signing-key theft mints arbitrary tokens; key
  custody is an operational problem this demo does not address —
  keys here are ephemeral and in-memory).
- PII classes outside the four detectors — notably person names,
  addresses, and separator-free digit strings (excluded deliberately:
  bare digit runs are too ambiguous to redact on without destroying log
  utility; field-level masking is the right control there).
- Exfiltration through channels the agent legitimately has (e.g. encoding
  its own tenant's data into an answer a human then forwards). Tenant
  isolation bounds *whose* data; it cannot judge intent within scope.

## 6. Limitations of the measurement

- The corpus and the detectors share an author. The corpus was written
  adversarially (hard negatives first), but an independent corpus would
  likely score below 1.000 — the honest reading of the number is "the
  guards behave as specified on the specified hard cases", and the
  scorer prints every miss so the claim is checkable line by line.
- Directive syntax is a stand-in for natural language. A real LLM follows
  natural-language injections stochastically; the suite's assumption
  (always follows) is the conservative direction for an enforcement
  claim, and the wrong direction for estimating real-world attack
  frequency — which this paper does not estimate.
- Single node, in-memory sessions/codes, JSON-file store, no rate
  limiting, no refresh tokens, no MFA. This is a proof of an enforcement
  architecture and its measurement, not a production IdP.
- Latency/throughput are not reported: at this scale they measure the
  test VM, not the design, and no number is better than a meaningless
  one.

## 7. Relation to prior art

Keycloak/Authentik/Ory provide the IdP half at production weight, with no
agent data-layer story. Presidio provides detection as a library, with
quality left to the deployer to measure. NeMo Guardrails and filter
vendors provide probabilistic prompt/output controls. InjecAgent,
AgentDojo, ASB, and AgentHarm measure model obedience. OWASP's LLM01/LLM06
guidance recommends exactly this shape (own DB role for the agent,
read-only by default, least privilege, log tool calls) as prose.
cleanroom-auth's contribution is the combination as one small auditable
stack whose claims — block rate, per-layer attribution, redaction
precision/recall, log cleanliness — are numbers produced by a shipped,
runnable suite. Full survey: `KILLGATE.md`.
