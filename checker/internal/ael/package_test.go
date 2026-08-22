// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackageSchemaRejectsEvaluationGrades(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean("../../../fixtures/packages/evaluation_carries_grade/package/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = validatePackageManifestSchema(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown top-level key \"grades\"") {
		t.Fatalf("schema diagnostic = %v, want rejected evaluation grades", err)
	}
}

func TestValidatePackagePathRejectsEscape(t *testing.T) {
	if err := validatePackagePath("../escape"); err == nil {
		t.Fatal("path escape was accepted")
	}
}

func TestVerificationStatusSchemaRejectsRequiredFreshnessFields(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "unsupported status format",
			raw:  `{"authority":"placeholder-status-authority","issued_at":"2026-01-03T00:00:00Z","next_update":"2026-01-04T00:00:00Z","record_id":"fixture-record","state":"current","status_format":2}`,
			want: "status_format must be 1",
		},
		{
			name: "missing status format",
			raw:  `{"authority":"placeholder-status-authority","issued_at":"2026-01-03T00:00:00Z","next_update":"2026-01-04T00:00:00Z","record_id":"fixture-record","state":"current"}`,
			want: "missing required top-level key \"status_format\"",
		},
		{
			name: "missing issued at",
			raw:  `{"authority":"placeholder-status-authority","next_update":"2026-01-04T00:00:00Z","record_id":"fixture-record","state":"current","status_format":1}`,
			want: "missing required top-level key \"issued_at\"",
		},
		{
			name: "missing next update",
			raw:  `{"authority":"placeholder-status-authority","issued_at":"2026-01-03T00:00:00Z","record_id":"fixture-record","state":"current","status_format":1}`,
			want: "current status requires next_update",
		},
		{
			name: "next update equals issued at",
			raw:  `{"authority":"placeholder-status-authority","issued_at":"2026-01-03T00:00:00Z","next_update":"2026-01-03T00:00:00Z","record_id":"fixture-record","state":"current","status_format":1}`,
			want: "current status next_update must be later than issued_at",
		},
		{
			name: "next update before issued at",
			raw:  `{"authority":"placeholder-status-authority","issued_at":"2026-01-03T00:00:00Z","next_update":"2026-01-02T23:59:59Z","record_id":"fixture-record","state":"current","status_format":1}`,
			want: "current status next_update must be later than issued_at",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVerificationStatusSchema([]byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestVerificationRecordWithoutStatusIsUnknown(t *testing.T) {
	fixtureRoot := filepath.Clean("../../../fixtures/packages/valid_verification_record")
	result, err := ValidatePackage(filepath.Join(fixtureRoot, "package"), filepath.Join(fixtureRoot, "trust"), packageFixtureValidationOptions(t, "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestVerificationRecordWithoutEvaluationTimeIsUnknown(t *testing.T) {
	fixtureRoot := filepath.Clean("../../../fixtures/packages/valid_verification_record")
	result, err := ValidatePackage(filepath.Join(fixtureRoot, "package"), filepath.Join(fixtureRoot, "trust"), PackageValidationOptions{
		StatusPath:          filepath.Join(fixtureRoot, "status.json"),
		StatusSignaturePath: filepath.Join(fixtureRoot, "status.sig"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestConsumerEvaluationTimeIsRequired(t *testing.T) {
	if hasConsumerEvaluationTime(time.Time{}) {
		t.Fatal("zero evaluation time was accepted")
	}
	if !hasConsumerEvaluationTime(time.Date(2026, time.January, 3, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("explicit evaluation time was rejected")
	}
}

func TestVerificationRecordHonorsShorterStatusAge(t *testing.T) {
	fixtureRoot := filepath.Clean("../../../fixtures/packages/valid_verification_record")
	options := packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig"))
	options.MaxStatusAge = 6 * time.Hour
	result, err := ValidatePackage(filepath.Join(fixtureRoot, "package"), filepath.Join(fixtureRoot, "trust"), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestVerificationRecordWithUnvalidatedStatusIsUnknown(t *testing.T) {
	fixtureRoot := filepath.Clean("../../../fixtures/packages/status_signature_tampered")
	result, err := ValidatePackage(
		filepath.Join(fixtureRoot, "package"),
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestVerificationRecordWithIncompleteStatusIsUnknown(t *testing.T) {
	fixtureRoot := filepath.Clean("../../../fixtures/packages/valid_verification_record")
	result, err := ValidatePackage(
		filepath.Join(fixtureRoot, "package"),
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), ""),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestVerificationRecordWithUntrustedStatusKeyIsUnknown(t *testing.T) {
	fixtureRoot := copyPackageFixture(t, "valid_verification_record")
	if err := os.RemoveAll(filepath.Join(fixtureRoot, "trust", "status")); err != nil {
		t.Fatal(err)
	}
	result, err := ValidatePackage(
		filepath.Join(fixtureRoot, "package"),
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "STATUS-UNKNOWN" {
		t.Fatalf("display state = %q, want STATUS-UNKNOWN", result.DisplayState)
	}
}

func TestVerificationRecordRejectsOperatorKeyTrustedAsVerifier(t *testing.T) {
	fixtureRoot := copyPackageFixture(t, "evaluation_rewrapped_by_operator")
	operatorKey := onlyPublicKeyName(t, filepath.Join(fixtureRoot, "trust", "operators"))
	operatorRaw, err := os.ReadFile(filepath.Join(fixtureRoot, "trust", "operators", operatorKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "trust", "verifiers", operatorKey), operatorRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ValidatePackage(
		filepath.Join(fixtureRoot, "package"),
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
	)
	if err == nil || !strings.Contains(err.Error(), "also trusted as an operator key") {
		t.Fatalf("validation error = %v, want duplicated operator/verifier key rejection", err)
	}
}

func TestVerificationRecordRejectsVerifierRoleSymlink(t *testing.T) {
	fixtureRoot := copyPackageFixture(t, "evaluation_rewrapped_by_operator")
	operatorKey := onlyPublicKeyName(t, filepath.Join(fixtureRoot, "trust", "operators"))
	if err := os.Symlink(filepath.Join("..", "operators", operatorKey), filepath.Join(fixtureRoot, "trust", "verifiers", operatorKey)); err != nil {
		t.Skipf("create verifier role symlink: %v", err)
	}
	_, err := ValidatePackage(
		filepath.Join(fixtureRoot, "package"),
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
	)
	if err == nil || !strings.Contains(err.Error(), "contains symlink") {
		t.Fatalf("validation error = %v, want verifier role symlink rejection", err)
	}
}

func TestVerificationRecordRejectsSchemaValueGaps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "empty verifier relationship",
			mutate: func(manifest map[string]any) {
				manifest["verifier"].(map[string]any)["relationship_to_operator"] = ""
			},
			want: "verifier relationships must be present",
		},
		{
			name: "empty custody field",
			mutate: func(manifest map[string]any) {
				manifest["verification_custody"].(map[string]any)["review"] = ""
			},
			want: "verification custody fields must be present",
		},
		{
			name: "empty evidence coverage field",
			mutate: func(manifest map[string]any) {
				manifest["evidence_coverage"].(map[string]any)["disclosure"] = ""
			},
			want: "evidence coverage fields must be present",
		},
		{
			name: "blank evidence coverage field",
			mutate: func(manifest map[string]any) {
				manifest["evidence_coverage"].(map[string]any)["disclosure"] = " \t "
			},
			want: "evidence coverage fields must be present",
		},
		{
			name: "blank verifier relationship",
			mutate: func(manifest map[string]any) {
				manifest["verifier"].(map[string]any)["relationship_to_operator"] = " \t "
			},
			want: "verifier relationships must be present",
		},
		{
			name: "blank custody field",
			mutate: func(manifest map[string]any) {
				manifest["verification_custody"].(map[string]any)["review"] = " \t "
			},
			want: "verification custody fields must be present",
		},
		{
			name: "blank grade annotation",
			mutate: func(manifest map[string]any) {
				manifest["grades"].([]any)[0].(map[string]any)["annotations"].(map[string]any)["coverage"] = " \t "
			},
			want: "grade \"run-ael1-valid\" is missing required annotations",
		},
		{
			name: "missing artifact evaluation arguments array",
			mutate: func(manifest map[string]any) {
				manifest["artifact_evaluation"].(map[string]any)["arguments"] = nil
			},
			want: "artifact_evaluation.arguments must be an array",
		},
		{
			name: "invalid artifact evaluation argument item",
			mutate: func(manifest map[string]any) {
				manifest["artifact_evaluation"].(map[string]any)["arguments"] = []any{nil}
			},
			want: "artifact_evaluation.arguments[0] must be a string",
		},
		{
			name: "negative artifact evaluation exit status",
			mutate: func(manifest map[string]any) {
				manifest["artifact_evaluation"].(map[string]any)["exit_status"] = -1
			},
			want: "artifact_evaluation.exit_status must be a non-negative integer",
		},
		{
			name: "missing conformance command array",
			mutate: func(manifest map[string]any) {
				manifest["conformance"].(map[string]any)["command"] = nil
			},
			want: "conformance.command must be an array",
		},
		{
			name: "invalid conformance command item",
			mutate: func(manifest map[string]any) {
				manifest["conformance"].(map[string]any)["command"] = []any{nil}
			},
			want: "conformance.command[0] must be a string",
		},
		{
			name: "negative conformance exit status",
			mutate: func(manifest map[string]any) {
				manifest["conformance"].(map[string]any)["exit_status"] = -1
			},
			want: "conformance.exit_status must be a non-negative integer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureRoot := copyPackageFixture(t, "valid_verification_record")
			rewritePackageFixtureManifest(t, fixtureRoot, tt.mutate)
			_, err := ValidatePackage(
				filepath.Join(fixtureRoot, "package"),
				filepath.Join(fixtureRoot, "trust"),
				packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
			)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestVerificationRecordRejectsNullRequiredIntegers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "artifact evaluation exit status",
			mutate: func(manifest map[string]any) {
				manifest["artifact_evaluation"].(map[string]any)["exit_status"] = nil
			},
			want: "artifact_evaluation.exit_status must be a non-negative integer",
		},
		{
			name: "conformance exit status",
			mutate: func(manifest map[string]any) {
				manifest["conformance"].(map[string]any)["exit_status"] = nil
			},
			want: "conformance.exit_status must be a non-negative integer",
		},
		{
			name: "zero-byte file manifest size",
			mutate: func(manifest map[string]any) {
				for _, value := range manifest["files"].([]any) {
					blob := value.(map[string]any)
					if blob["path"] == "results/stderr.txt" {
						blob["size"] = nil
						return
					}
				}
				panic("results/stderr.txt is absent from fixture")
			},
			want: "size must be a non-negative integer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureRoot := copyPackageFixture(t, "valid_verification_record")
			rewritePackageFixtureManifest(t, fixtureRoot, tt.mutate)
			_, err := ValidatePackage(
				filepath.Join(fixtureRoot, "package"),
				filepath.Join(fixtureRoot, "trust"),
				packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
			)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPackageSnapshotIsolatesValidationFromSourceChanges(t *testing.T) {
	fixtureRoot := copyPackageFixture(t, "valid_verification_record")
	snapshot, cleanup, err := snapshotPackageDir(filepath.Join(fixtureRoot, "package"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	recordPath := filepath.Join(fixtureRoot, "package", "artifact", "recorders", "r1.jsonl")
	if err := os.WriteFile(recordPath, []byte("not a record\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := validatePackageDir(
		snapshot,
		filepath.Join(fixtureRoot, "trust"),
		packageFixtureValidationOptions(t, filepath.Join(fixtureRoot, "status.json"), filepath.Join(fixtureRoot, "status.sig")),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.DisplayState != "VERIFIED" {
		t.Fatalf("display state = %q, want VERIFIED", result.DisplayState)
	}
}

func copyPackageFixture(t *testing.T, name string) string {
	t.Helper()
	source := filepath.Clean(filepath.Join("../../../fixtures/packages", name))
	target := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		return os.WriteFile(destination, raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func onlyPublicKeyName(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".pub") {
			return entry.Name()
		}
	}
	t.Fatalf("no public key in %s", dir)
	return ""
}

func packageFixtureValidationOptions(t *testing.T, statusPath, statusSignaturePath string) PackageValidationOptions {
	t.Helper()
	evaluationTime, err := time.Parse(time.RFC3339, "2026-01-03T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return PackageValidationOptions{
		StatusPath:          statusPath,
		StatusSignaturePath: statusSignaturePath,
		EvaluationTime:      evaluationTime,
	}
}

func rewritePackageFixtureManifest(t *testing.T, fixtureRoot string, mutate func(map[string]any)) {
	t.Helper()
	manifestPath := filepath.Join(fixtureRoot, "package", "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(manifest)
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("AEL-FIXTURE-TEST-SEED-v1:package-verifier"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, raw))
	if err := os.WriteFile(filepath.Join(fixtureRoot, "package", "manifest.sig"), []byte(signature+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
