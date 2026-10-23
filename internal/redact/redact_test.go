package redact

import "testing"

func TestLuhn(t *testing.T) {
	if !LuhnValid("4111111111111111") {
		t.Fatal("visa test number should be Luhn-valid")
	}
	if LuhnValid("4111111111111112") {
		t.Fatal("checksum-off number must not be Luhn-valid")
	}
	if LuhnValid("12345") {
		t.Fatal("short string must not be Luhn-valid")
	}
}

func TestDetectors(t *testing.T) {
	cases := []struct {
		text string
		want []Finding
	}{
		{"mail me at a.b@example.com now", []Finding{{Type: "EMAIL", Value: "a.b@example.com"}}},
		{"card 4111 1111 1111 1111 ok", []Finding{{Type: "CARD", Value: "4111 1111 1111 1111"}}},
		{"card 4111 1111 1111 1112 nope", nil}, // Luhn-invalid
		{"ssn 078-05-1120 on file", []Finding{{Type: "NATIONAL_ID", Value: "078-05-1120"}}},
		{"field 000-12-3456 rejected", nil}, // structurally invalid SSN area
		{"call (415) 555-0132 today", []Finding{{Type: "PHONE", Value: "(415) 555-0132"}}},
		{"call +44 20 7946 0958 today", []Finding{{Type: "PHONE", Value: "+44 20 7946 0958"}}},
		{"order ORD-88412 shipped", nil},
		{"date 2026-10-23 logged", nil},
		{"isbn 978-0-13-468599-1 here", nil},
	}
	for _, c := range cases {
		got := Find(c.text)
		if len(got) != len(c.want) {
			t.Fatalf("Find(%q) = %v, want %v", c.text, got, c.want)
		}
		for i := range got {
			if got[i].Type != c.want[i].Type || got[i].Value != c.want[i].Value {
				t.Fatalf("Find(%q)[%d] = %v, want %v", c.text, i, got[i], c.want[i])
			}
		}
	}
}

func TestCardNotDoubleReportedAsPhone(t *testing.T) {
	got := Find("card 4111 1111 1111 1111 charged")
	if len(got) != 1 || got[0].Type != "CARD" {
		t.Fatalf("findings = %v, want exactly one CARD", got)
	}
}

func TestRedactReplacesValues(t *testing.T) {
	out, fs := Redact("email a.b@example.com card 4111111111111111")
	if len(fs) != 2 {
		t.Fatalf("findings = %v", fs)
	}
	want := "email [REDACTED:EMAIL] card [REDACTED:CARD]"
	if out != want {
		t.Fatalf("redacted = %q, want %q", out, want)
	}
}

func TestCorpusEvaluation(t *testing.T) {
	r := Evaluate()
	if r.TP != 23 || r.FP != 0 || r.FN != 0 {
		t.Fatalf("corpus eval drifted: TP=%d FP=%d FN=%d misses=%v", r.TP, r.FP, r.FN, r.Misses)
	}
	if r.Precision != 1 || r.Recall != 1 {
		t.Fatalf("precision=%v recall=%v", r.Precision, r.Recall)
	}
}
