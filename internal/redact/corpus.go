package redact

// Label is one human-labeled PII occurrence in a corpus line: the exact
// value, and the type a correct redactor must report for it.
type Label struct {
	Type  string
	Value string
}

// CorpusLine is one labeled log line. An empty PII slice means the line
// contains NO PII and a correct redactor must leave it untouched — the
// negatives are what precision is measured against.
type CorpusLine struct {
	Text string
	PII  []Label
}

// Corpus is the labeled evaluation set. All values are fixtures: reserved
// domains (example.com / example.invalid), the 555 fictional phone range,
// Ofcom's reserved 020 7946 fictional range, published SSA example SSNs,
// and the card industry's well-known test numbers.
var Corpus = []CorpusLine{
	// ---- emails ----
	{Text: `2026-10-23T10:15:01Z INFO user login ok email=amina.raza@example.com session=9f2`,
		PII: []Label{{"EMAIL", "amina.raza@example.com"}}},
	{Text: `From: Bilal Ahmed <bilal.ahmed+alerts@mail.example.org>`,
		PII: []Label{{"EMAIL", "bilal.ahmed+alerts@mail.example.org"}}},
	{Text: `{"event":"invite_sent","to":"chen.wei@example.invalid","by":"ops@example.com"}`,
		PII: []Label{{"EMAIL", "chen.wei@example.invalid"}, {"EMAIL", "ops@example.com"}}},
	{Text: `WARN bounce for recipient fatima.khan@sub.domain.example.co.uk code=550`,
		PII: []Label{{"EMAIL", "fatima.khan@sub.domain.example.co.uk"}}},
	{Text: `contact "d.osei@example.com" regarding ticket 4471`,
		PII: []Label{{"EMAIL", "d.osei@example.com"}}},
	// ---- cards ----
	{Text: `payment authorized card 4111111111111111 amount=59.99`,
		PII: []Label{{"CARD", "4111111111111111"}}},
	{Text: `payment authorized card 4111 1111 1111 1111 amount=12.50`,
		PII: []Label{{"CARD", "4111 1111 1111 1111"}}},
	{Text: `refund issued to 5500-0055-5555-5559 ref=rf_991`,
		PII: []Label{{"CARD", "5500-0055-5555-5559"}}},
	{Text: `amex on file: 378282246310005 exp 11/29`,
		PII: []Label{{"CARD", "378282246310005"}}},
	{Text: `card=6011 1111 1111 1117 charged`,
		PII: []Label{{"CARD", "6011 1111 1111 1117"}}},
	// ---- phones ----
	{Text: `sms sent to +1-202-555-0143 body="your code is ready"`,
		PII: []Label{{"PHONE", "+1-202-555-0143"}}},
	{Text: `callback requested at (415) 555-0132 after 5pm`,
		PII: []Label{{"PHONE", "(415) 555-0132"}}},
	{Text: `phone: 212.555.0176 verified`,
		PII: []Label{{"PHONE", "212.555.0176"}}},
	{Text: `intl contact +44 20 7946 0958 (london office)`,
		PII: []Label{{"PHONE", "+44 20 7946 0958"}}},
	{Text: `reach me at 305 555 0119 please`,
		PII: []Label{{"PHONE", "305 555 0119"}}},
	// ---- national IDs ----
	{Text: `kyc check ssn=078-05-1120 result=pass`,
		PII: []Label{{"NATIONAL_ID", "078-05-1120"}}},
	{Text: `applicant id 219-09-9999 on form W-9 line 1`,
		PII: []Label{{"NATIONAL_ID", "219-09-9999"}}},
	// ---- multi-PII lines ----
	{Text: `user ivan.petrov@example.com called from +1-650-555-0120 about card 4242424242424242`,
		PII: []Label{{"EMAIL", "ivan.petrov@example.com"}, {"PHONE", "+1-650-555-0120"}, {"CARD", "4242424242424242"}}},
	{Text: `ssn 078-05-1120 and backup phone (212) 555-0147 on file`,
		PII: []Label{{"NATIONAL_ID", "078-05-1120"}, {"PHONE", "(212) 555-0147"}}},
	// ---- negatives: no PII, must stay untouched ----
	{Text: `order ORD-88412 shipped tracking=1Z8845W90300112233`},
	{Text: `invoice INV-2026-0451 total=1204.00 due 2026-11-01`},
	{Text: `2026-10-23T22:14:55Z GET /records/rec-1007 200 3ms`},
	{Text: `version v1.23.4 deployed to prod, build 20261023.7`},
	{Text: `zip=90210 addr verified score=98.6`},
	{Text: `card probe 4111 1111 1111 1112 declined (checksum)`}, // Luhn-invalid: not a card number
	{Text: `short phone fragment 555-0132 noted`},
	{Text: `form field 000-12-3456 rejected as invalid id`}, // area 000: structurally invalid SSN
	{Text: `sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 ok`},
	{Text: `metric latency_p99=184 window=300s samples=1048576`},
	{Text: `session token id tok_9f2ka81mz (not a credential, an identifier)`},
	{Text: `isbn 978-0-13-468599-1 catalogued`},
	{Text: `ticket #40217 priority=high queue=support`},
	{Text: `coords 40.7128,-74.0060 stored for venue`},
	{Text: `refund window 30 days, policy POL-2026-7781`},
	{Text: `phone extension 4421 at front desk`},
}

// EvalResult is the measured quality of the redactor on the corpus.
type EvalResult struct {
	Lines     int               `json:"lines"`
	TP        int               `json:"true_positives"`
	FP        int               `json:"false_positives"`
	FN        int               `json:"false_negatives"`
	Precision float64           `json:"precision"`
	Recall    float64           `json:"recall"`
	PerType   map[string][3]int `json:"per_type_tp_fp_fn"`
	Misses    []string          `json:"misses"` // human-readable, printed not hidden
}

// Evaluate runs Find over the corpus and scores it span-exact per label: a
// finding counts as a true positive only if type AND exact value match a
// label; any other finding is a false positive; any unmatched label is a
// false negative (a miss).
func Evaluate() EvalResult {
	res := EvalResult{PerType: map[string][3]int{}}
	for _, line := range Corpus {
		res.Lines++
		findings := Find(line.Text)
		used := make([]bool, len(findings))
		for _, lab := range line.PII {
			hit := -1
			for i, f := range findings {
				if !used[i] && f.Type == lab.Type && f.Value == lab.Value {
					hit = i
					break
				}
			}
			pt := res.PerType[lab.Type]
			if hit >= 0 {
				used[hit] = true
				res.TP++
				pt[0]++
			} else {
				res.FN++
				pt[2]++
				res.Misses = append(res.Misses, "MISS "+lab.Type+" "+lab.Value+" in: "+line.Text)
			}
			res.PerType[lab.Type] = pt
		}
		for i, f := range findings {
			if !used[i] {
				res.FP++
				pt := res.PerType[f.Type]
				pt[1]++
				res.PerType[f.Type] = pt
				res.Misses = append(res.Misses, "FALSE-POSITIVE "+f.Type+" "+f.Value+" in: "+line.Text)
			}
		}
	}
	if res.TP+res.FP > 0 {
		res.Precision = float64(res.TP) / float64(res.TP+res.FP)
	}
	if res.TP+res.FN > 0 {
		res.Recall = float64(res.TP) / float64(res.TP+res.FN)
	}
	return res
}
