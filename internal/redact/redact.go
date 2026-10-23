// Package redact is cleanroom-auth's PII redactor: hand-written detectors
// for emails, payment-card numbers (Luhn-validated), phone numbers, and
// US national-ID (SSN) shaped numbers, with checksum/format guards whose
// entire purpose is precision — the labeled-corpus evaluation in corpus.go
// measures whether they earn it, and prints the misses.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Finding is one detected PII span in the input text.
type Finding struct {
	Type  string // EMAIL, CARD, PHONE, NATIONAL_ID
	Start int
	End   int
	Value string
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	// Card candidates: 13-19 digits, optionally separated by single spaces
	// or dashes in groups. The candidate is Luhn-checked before it counts.
	cardRe = regexp.MustCompile(`\b(?:\d[ \-]?){12,18}\d\b`)
	ssnRe  = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// Phone shapes: optional country code, then 3-3-4 grouping with
	// parentheses / spaces / dashes / dots, or an international +CC form
	// with 2-4 digit groups. Bare digit runs are deliberately NOT phones:
	// a separator-free 10-digit string is too ambiguous to redact on.
	phoneRe = regexp.MustCompile(`(?:\+\d{1,3}[\s\-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.\-])\d{3}[\s.\-]\d{4}\b|\+[1-9]\d{0,2}(?:[\s\-]\d{2,4}){2,3}\b`)
)

// LuhnValid reports whether a digit string passes the Luhn checksum.
func LuhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validSSN applies the SSA's structural rules so order-number-shaped
// strings (area 000, 666, or 9xx) are not flagged as national IDs.
func validSSN(s string) bool {
	area := s[0:3]
	group := s[4:6]
	serial := s[7:11]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

// Find returns all PII findings in text, sorted by position, with overlaps
// resolved in favour of the longer span (a card number is not also a
// phone number).
func Find(text string) []Finding {
	var cands []Finding
	add := func(t string, loc []int) {
		if loc != nil {
			cands = append(cands, Finding{Type: t, Start: loc[0], End: loc[1], Value: text[loc[0]:loc[1]]})
		}
	}
	for _, loc := range cardRe.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		if LuhnValid(digitsOnly(raw)) {
			add("CARD", loc)
		}
	}
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		add("EMAIL", loc)
	}
	for _, loc := range ssnRe.FindAllStringIndex(text, -1) {
		if validSSN(text[loc[0]:loc[1]]) {
			add("NATIONAL_ID", loc)
		}
	}
	for _, loc := range phoneRe.FindAllStringIndex(text, -1) {
		d := digitsOnly(text[loc[0]:loc[1]])
		if len(d) >= 10 && len(d) <= 15 {
			add("PHONE", loc)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Start != cands[j].Start {
			return cands[i].Start < cands[j].Start
		}
		return (cands[i].End - cands[i].Start) > (cands[j].End - cands[j].Start)
	})
	var out []Finding
	lastEnd := -1
	for _, c := range cands {
		if c.Start >= lastEnd {
			out = append(out, c)
			lastEnd = c.End
		}
	}
	return out
}

// Redact replaces every finding with a typed marker and returns the cleaned
// text plus the findings it acted on.
func Redact(text string) (string, []Finding) {
	fs := Find(text)
	if len(fs) == 0 {
		return text, fs
	}
	var b strings.Builder
	pos := 0
	for _, f := range fs {
		b.WriteString(text[pos:f.Start])
		b.WriteString("[REDACTED:" + f.Type + "]")
		pos = f.End
	}
	b.WriteString(text[pos:])
	return b.String(), fs
}
