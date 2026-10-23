package breach

import "testing"

// TestBreachSuite is the regression form of the headline measurement: the
// suite must keep proving baseline 9/9 success and defended 9/9 blocked,
// with benign work intact and no planted PII in the defended log.
func TestBreachSuite(t *testing.T) {
	rep, err := RunAll()
	if err != nil {
		t.Fatal(err)
	}
	if rep.AttacksTotal != 9 {
		t.Fatalf("attacks total = %d, want 9", rep.AttacksTotal)
	}
	if rep.BaselineSuccess != 9 {
		t.Fatalf("baseline successes = %d, want 9 (baseline must be genuinely vulnerable)", rep.BaselineSuccess)
	}
	if rep.DefendedBlocked != 9 || rep.DefendedBlockRate != 1.0 {
		t.Fatalf("defended blocked = %d rate = %v, want 9 / 1.0", rep.DefendedBlocked, rep.DefendedBlockRate)
	}
	if rep.BenignDefendedOK != rep.BenignTotal || rep.BenignTotal != 2 {
		t.Fatalf("benign defended = %d/%d, want 2/2", rep.BenignDefendedOK, rep.BenignTotal)
	}
	if !rep.PIILog.BaselineLogContainsPlanted {
		t.Fatal("baseline log should contain planted PII (the vulnerability must be real)")
	}
	if rep.PIILog.DefendedLogContainsPlanted {
		t.Fatal("defended log contains planted PII")
	}
	if rep.PIILog.DefendedLogRedactionMarkers < 3 {
		t.Fatalf("defended redaction markers = %d, want >= 3", rep.PIILog.DefendedLogRedactionMarkers)
	}
	if rep.Redaction.Precision != 1 || rep.Redaction.Recall != 1 {
		t.Fatalf("redaction P=%v R=%v, want 1/1", rep.Redaction.Precision, rep.Redaction.Recall)
	}
}
