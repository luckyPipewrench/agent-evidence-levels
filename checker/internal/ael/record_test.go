package ael

import "testing"

func TestDecodeCompactBase64RejectsNonCanonicalTrailingBits(t *testing.T) {
	if _, err := decodeCompactBase64("AA"); err != nil {
		t.Fatalf("canonical segment rejected: %v", err)
	}
	if _, err := decodeCompactBase64("AB"); err == nil {
		t.Fatal("non-canonical segment with non-zero trailing bits was accepted")
	}
}

func TestParseRecordLineRejectsPadding(t *testing.T) {
	rec, err := ParseRecordLine("AA==.AA", "recorders/r1.jsonl", 1)
	if err != nil {
		t.Fatal(err)
	}
	if rec.LineErr == nil {
		t.Fatal("padded compact line was accepted")
	}
}
