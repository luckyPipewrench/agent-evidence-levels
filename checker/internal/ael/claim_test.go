// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestClaimedRungDoesNotAffectGrade(t *testing.T) {
	artifactDir := filepath.Join("..", "..", "..", "fixtures", "ael1", "valid")
	art, err := LoadArtifact(artifactDir, filepath.Join(artifactDir, "keys"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	art.Manifest.ClaimedRung = 0
	lowClaim := Evaluate(art)
	art.Manifest.ClaimedRung = 4
	highClaim := Evaluate(art)

	if !reflect.DeepEqual(lowClaim, highClaim) {
		t.Fatalf("producer claimed_rung changed checker result:\nlow:  %#v\nhigh: %#v", lowClaim, highClaim)
	}
	if len(highClaim.Runs) != 1 || highClaim.Runs[0].Ungraded || highClaim.Runs[0].Grade != 1 {
		t.Fatalf("fixture grade = %#v, want one independently computed AEL-1 result", highClaim.Runs)
	}
}
