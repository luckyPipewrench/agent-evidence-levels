// SPDX-License-Identifier: Apache-2.0

package ael

import "testing"

func TestAEL0OrderChecksAreUVWithoutRecorderLogs(t *testing.T) {
	art := &Artifact{}
	tests := []struct {
		name  string
		check func(*Artifact) Outcome
	}{
		{name: "sequence order", check: checkSequenceOrder},
		{name: "predecessor links", check: checkPredecessorLinks},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.check(art); got.Status != UV {
				t.Fatalf("status = %s, want UV", got.Status)
			}
		})
	}
}

func TestAEL0OrderChecksAcceptSingleRootRecord(t *testing.T) {
	art := &Artifact{RecorderLogs: []*RecorderLog{{
		ID:  "r1",
		Run: "run-one",
		Records: []*Record{{Payload: Payload{
			V:        1,
			Run:      "run-one",
			Recorder: "r1",
			Seq:      0,
			Prev:     zeroPrev,
		}}},
	}}}
	if got := checkSequenceOrder(art); got.Status != Pass {
		t.Fatalf("sequence-order status = %s, want PASS: %s", got.Status, got.Message)
	}
	if got := checkPredecessorLinks(art); got.Status != Pass {
		t.Fatalf("predecessor-link status = %s, want PASS: %s", got.Status, got.Message)
	}
}
