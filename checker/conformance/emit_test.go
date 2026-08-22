// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// buildChecker compiles the real aelcheck binary. The emitter runs and digests
// whatever executable it is handed, so a stub here would prove nothing about
// the thing an operator actually ships.
func buildChecker(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "aelcheck")
	cmd := exec.Command("go", "build", "-o", binary, "../cmd/aelcheck")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build aelcheck: %v\n%s", err, out)
	}
	return binary
}

func writePublicKey(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	sum := sha256.Sum256(pub)
	fingerprint := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(filepath.Join(dir, fingerprint+".pub"), []byte(encoded), 0o644); err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

type emitHarness struct {
	options   ael.EmitOptions
	trustRoot string
}

// newEmitHarness assembles a complete, honest emit for one artifact fixture.
func newEmitHarness(t *testing.T, artifactCase string) emitHarness {
	t.Helper()
	root := t.TempDir()

	operatorPub, operatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	statusPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	trustRoot := filepath.Join(root, "trust")
	writePublicKey(t, filepath.Join(trustRoot, "operators"), operatorPub)
	writePublicKey(t, filepath.Join(trustRoot, "status"), statusPub)
	if err := os.MkdirAll(filepath.Join(trustRoot, "verifiers"), 0o755); err != nil {
		t.Fatal(err)
	}

	specPath := filepath.Join(root, "specification.txt")
	if err := os.WriteFile(specPath, []byte("AEL specification under test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(root, "corpus-digest-source.txt")
	if err := os.WriteFile(corpusPath, []byte("corpus identity\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conformancePath := filepath.Join(root, "conformance.json")
	if err := os.WriteFile(conformancePath, []byte("{\"result\":\"pass\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	artifact := filepath.Join("..", "..", "fixtures", artifactCase)
	issued, err := time.Parse(time.RFC3339, "2026-01-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	return emitHarness{
		trustRoot: trustRoot,
		options: ael.EmitOptions{
			ArtifactDir:           artifact,
			ArtifactKeysDir:       filepath.Join(artifact, "keys"),
			CheckerPath:           buildChecker(t),
			CheckerName:           "aelcheck",
			SourceRevision:        "test-revision",
			PackageID:             "emitted-" + filepath.Base(artifactCase),
			ProducerID:            "test-producer",
			OperatorID:            "test-operator",
			OperatorKey:           operatorPriv,
			StatusAuthorityID:     "test-status-authority",
			StatusPublicKey:       statusPub,
			Custody:               ael.PackageCustody{Acquisition: "declared", Replay: "available", Review: "declared", Issuance: "signed"},
			Coverage:              ael.PackageCoverage{Scope: "declared", Disclosure: "complete-package"},
			SpecVersion:           "0.1",
			SpecPath:              specPath,
			CorpusVersion:         "test-corpus",
			CorpusDigestPath:      corpusPath,
			ConformanceCommand:    []string{"make", "check"},
			ConformanceResultPath: conformancePath,
			ConformanceExitStatus: 0,
			IssuedAt:              issued,
			OutDir:                filepath.Join(root, "package"),
		},
	}
}

// TestEmittedPackageValidates is the end-to-end proof the emitter exists for:
// a package built from a real checker run must satisfy the validator, which was
// written separately and does not trust the emitter.
func TestEmittedPackageValidates(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	result, err := ael.EmitEvaluationPackage(harness.options)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if result.ExitStatus != 0 {
		t.Fatalf("checker exit status = %d, want 0", result.ExitStatus)
	}

	validation, err := ael.ValidatePackage(harness.options.OutDir, harness.trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatalf("validate emitted package: %v", err)
	}
	if validation.Kind != "evaluation-package" {
		t.Errorf("kind = %q, want evaluation-package", validation.Kind)
	}
	if validation.DisplayState != "EVALUATED" {
		t.Errorf("display state = %q, want EVALUATED", validation.DisplayState)
	}
}

// TestEmittedPackageCarriesNoGrade holds the structural property the format
// exists to enforce: a self-run evaluation cannot present a grade.
func TestEmittedPackageCarriesNoGrade(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"grades\"", "\"grade\"", "\"verified\"", "\"claimed_rung\""} {
		if containsToken(raw, forbidden) {
			t.Errorf("emitted evaluation package manifest contains %s", forbidden)
		}
	}
}

// TestEmitRecordsNonconformingRun is the fail-direction case. A checker run
// that does not conform must still produce a package, and that package must
// report the failure rather than omit it or present as clean.
func TestEmitRecordsNonconformingRun(t *testing.T) {
	harness := newEmitHarness(t, "ael0/byteflip")
	result, err := ael.EmitEvaluationPackage(harness.options)
	if err != nil {
		t.Fatalf("emit must still produce a package for a nonconforming run: %v", err)
	}
	if result.ExitStatus == 0 {
		t.Fatalf("checker exit status = 0, want nonzero for a nonconforming artifact")
	}

	validation, err := ael.ValidatePackage(harness.options.OutDir, harness.trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatalf("validate emitted package: %v", err)
	}
	if validation.DisplayState != "EVALUATION-FAILED" {
		t.Errorf("display state = %q, want EVALUATION-FAILED", validation.DisplayState)
	}
}

func containsToken(raw []byte, token string) bool {
	return len(raw) > 0 && len(token) > 0 && indexOf(string(raw), token) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestEmitRefusesOutputInsideArtifact covers a real defect found by probing:
// nesting the package inside the artifact made copyTree its own source, so it
// recursed until the filesystem refused a path, after writing hundreds of
// files. An operator reaches this by running --out ./package from inside the
// artifact directory.
func TestEmitRefusesOutputInsideArtifact(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	artifactCopy := filepath.Join(t.TempDir(), "artifact")
	if err := os.MkdirAll(artifactCopy, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(harness.options.ArtifactDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		source := filepath.Join(harness.options.ArtifactDir, entry.Name())
		if entry.IsDir() {
			nested := filepath.Join(artifactCopy, entry.Name())
			if err := os.MkdirAll(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			inner, err := os.ReadDir(source)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range inner {
				raw, err := os.ReadFile(filepath.Join(source, file.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(nested, file.Name()), raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(artifactCopy, entry.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	harness.options.ArtifactDir = artifactCopy
	harness.options.ArtifactKeysDir = filepath.Join(artifactCopy, "keys")
	harness.options.OutDir = filepath.Join(artifactCopy, "package")

	if _, err := ael.EmitEvaluationPackage(harness.options); err == nil {
		t.Fatal("emit accepted an output directory inside the artifact")
	}
	// The refusal must happen before any copying, so nothing is left behind.
	if _, err := os.Stat(harness.options.OutDir); !os.IsNotExist(err) {
		t.Errorf("emit created the output directory before refusing: %v", err)
	}
}

// TestEmitRemovesPartialPackageOnFailure covers debris found by probing: a
// refused copy used to leave a half-written package behind, so the operator's
// retry failed a second time on a directory that was no longer empty.
func TestEmitRemovesPartialPackageOnFailure(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	// A missing specification fails after the artifact has been copied, which
	// is the point in the sequence where debris used to accumulate.
	harness.options.SpecPath = filepath.Join(t.TempDir(), "absent.txt")

	if _, err := ael.EmitEvaluationPackage(harness.options); err == nil {
		t.Fatal("emit accepted a missing specification")
	}
	if _, err := os.Stat(harness.options.OutDir); !os.IsNotExist(err) {
		t.Errorf("failed emit left a partial package behind: %v", err)
	}
}

// TestEmitReportsCheckerDiagnosis covers a diagnosability gap found by probing:
// an artifact the checker cannot load produced only a JSON parse error, hiding
// the checker's own explanation of what was actually wrong.
func TestEmitReportsCheckerDiagnosis(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	unloadable := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unloadable, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.ArtifactDir = unloadable
	harness.options.ArtifactKeysDir = filepath.Join(unloadable, "keys")

	_, err := ael.EmitEvaluationPackage(harness.options)
	if err == nil {
		t.Fatal("emit accepted an artifact the checker cannot load")
	}
	if indexOf(err.Error(), "manifest.json") < 0 {
		t.Errorf("error does not carry the checker's diagnosis: %v", err)
	}
}
