// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	// The conformance command is run now, so the harness supplies a real one.
	conformancePath := filepath.Join(root, "conformance.sh")
	if err := os.WriteFile(conformancePath, []byte("#!/bin/sh\nprintf '{\"result\":\"pass\"}\\n'\n"), 0o755); err != nil {
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
			ArtifactDir:        artifact,
			ArtifactKeysDir:    filepath.Join(artifact, "keys"),
			CheckerPath:        buildChecker(t),
			CheckerName:        "aelcheck",
			SourceRevision:     "test-revision",
			PackageID:          "emitted-" + filepath.Base(artifactCase),
			ProducerID:         "test-producer",
			OperatorID:         "test-operator",
			OperatorKey:        operatorPriv,
			StatusAuthorityID:  "test-status-authority",
			StatusPublicKey:    statusPub,
			Custody:            ael.PackageCustody{Acquisition: "declared", Replay: "available", Review: "declared", Issuance: "signed"},
			Coverage:           ael.PackageCoverage{Scope: "declared", Disclosure: "complete-package"},
			SpecVersion:        "0.1",
			SpecPath:           specPath,
			CorpusVersion:      "test-corpus",
			CorpusDigestPath:   corpusPath,
			ConformanceCommand: []string{conformancePath},
			IssuedAt:           issued,
			OutDir:             filepath.Join(root, "package"),
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

// TestEmitSelectedRunStillBindsAllDiscoveredRuns makes the favorable run in a
// mixed artifact the selected one. The package remains bound to both it and
// the degraded run, so selection cannot omit the unfavorable evidence.
func TestEmitSelectedRunStillBindsAllDiscoveredRuns(t *testing.T) {
	harness := newEmitHarness(t, "multi_run/mixed")
	harness.options.Run = "run-mixed-a"
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	validation, err := ael.ValidatePackage(harness.options.OutDir, harness.trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatalf("validate emitted package: %v", err)
	}
	if validation.DisplayState != "EVALUATED" {
		t.Errorf("display state = %q, want EVALUATED", validation.DisplayState)
	}
	raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ael.PackageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Run != "run-mixed-a" {
		t.Errorf("selected run = %q, want run-mixed-a", manifest.Run)
	}
	wantRuns := []string{"run-mixed-a", "run-mixed-b"}
	if len(manifest.ArtifactBinding.DiscoveredRuns) != len(wantRuns) {
		t.Fatalf("discovered runs = %v, want %v", manifest.ArtifactBinding.DiscoveredRuns, wantRuns)
	}
	for index, want := range wantRuns {
		if manifest.ArtifactBinding.DiscoveredRuns[index] != want {
			t.Errorf("discovered run %d = %q, want %q", index, manifest.ArtifactBinding.DiscoveredRuns[index], want)
		}
	}
}

// TestEmitRefusesCheckerExitDisagreement confirms that the JSON and human
// TestEmitRecordsOneInvocation holds the property that replaced a second
// checker run. The manifest carries a single arguments field, so it can only
// honestly describe one execution. The emitter previously ran the checker twice
// and recorded the machine run's arguments and stderr beside the OTHER run's
// stdout, so the signed evidence described no single execution and the
// documented byte-for-byte replay did not hold for the stdout it bundled.
func TestEmitRecordsOneInvocation(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ArtifactEvaluation struct {
			Arguments     []string `json:"arguments"`
			MachineOutput struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"machine_output"`
			Stdout struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"stdout"`
		} `json:"artifact_evaluation"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	evaluation := manifest.ArtifactEvaluation
	if evaluation.Stdout.Path != evaluation.MachineOutput.Path {
		t.Errorf("stdout %q and machine output %q come from different files, so the manifest describes more than one run",
			evaluation.Stdout.Path, evaluation.MachineOutput.Path)
	}
	if evaluation.Stdout.Digest != evaluation.MachineOutput.Digest {
		t.Errorf("stdout and machine output digests differ: %s vs %s",
			evaluation.Stdout.Digest, evaluation.MachineOutput.Digest)
	}

	// The recorded arguments must reproduce the recorded bytes.
	command := exec.Command("./"+filepath.Join("checker", "aelcheck"), evaluation.Arguments...)
	command.Dir = harness.options.OutDir
	replayed, replayErr := command.Output()
	if replayErr != nil {
		// Discarding this let a replay that exited nonzero pass whenever its
		// partial stdout happened to match, which is the opposite of what a
		// replay claim asserts.
		t.Fatalf("replaying the recorded arguments failed: %v", replayErr)
	}
	recorded, err := os.ReadFile(filepath.Join(harness.options.OutDir, filepath.FromSlash(evaluation.MachineOutput.Path)))
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed) != string(recorded) {
		t.Error("replaying the recorded arguments did not reproduce the recorded machine output")
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

	_, err = ael.EmitEvaluationPackage(harness.options)
	if err == nil {
		t.Fatal("emit accepted an output directory inside the artifact")
	}
	// Assert the OVERLAP refusal specifically. Asserting only that OutDir is
	// absent passes for any failure, because staged assembly never creates it,
	// so the test stayed green with this guard disabled.
	if indexOf(err.Error(), "is inside the") < 0 {
		t.Errorf("error does not name the overlap refusal: %v", err)
	}
	// The refusal must precede any copying, so no staging directory exists
	// inside the artifact either.
	assertNoStagingResidue(t, artifactCopy)
}

// assertNoStagingResidue fails when a staging directory was left behind. The
// emitter stages into a sibling named after the output directory, so residue
// there is the evidence that assembly began.
func assertNoStagingResidue(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".aelpackage-") {
			t.Errorf("staging residue left behind: %s", filepath.Join(parent, entry.Name()))
		}
	}
}

// TestEmitRefusesSymlinkedOutputInsideArtifact attacks the overlap guard with
// a lexical path outside the artifact whose parent symlink resolves inside it.
// Checking only filepath.Abs leaves this form of the recursive-copy bug open.
func TestEmitRefusesSymlinkedOutputInsideArtifact(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	artifactCopy := filepath.Join(t.TempDir(), "artifact")
	copyEmitArtifact(t, harness.options.ArtifactDir, artifactCopy)

	link := filepath.Join(t.TempDir(), "artifact-link")
	if err := os.Symlink(artifactCopy, link); err != nil {
		t.Fatal(err)
	}
	harness.options.ArtifactDir = artifactCopy
	harness.options.ArtifactKeysDir = filepath.Join(artifactCopy, "keys")
	harness.options.OutDir = filepath.Join(link, "package")

	if _, err := ael.EmitEvaluationPackage(harness.options); err == nil {
		t.Fatal("emit accepted an output directory symlinked inside the artifact")
	} else if indexOf(err.Error(), "output directory") < 0 {
		t.Errorf("emit did not reject the symlinked overlap before copying: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifactCopy, "package")); !os.IsNotExist(err) {
		t.Errorf("emit created the output directory before refusing: %v", err)
	}
}

func copyEmitArtifact(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o644)
	}); err != nil {
		t.Fatal(err)
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
	// OutDir absence alone is guaranteed by staged assembly, so it cannot show
	// the cleanup ran. The staging sibling is what the cleanup removes.
	assertNoStagingResidue(t, filepath.Dir(harness.options.OutDir))
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

// TestEmitRefusesCheckerThatMutatesPackageInput proves the digest in the
// emitted manifest names the executable that actually produced the result. A
// checker that rewrites itself after its machine-readable run would otherwise
// leave a valid package whose captured result came from different bytes than
// TestCheckerCannotReachThePackage replaces a test that asserted the emitter
// DETECTED a checker mutating the package. Detection was the wrong property to
// hold: it is a race by construction, and every round spent closing one window
// opened another. The checker now runs against a disposable replica, so the
// assertion is the stronger one, that the package is unaffected.
func TestCheckerCannotReachThePackage(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{writeConformanceCommand(t, "pass", 0)}

	// A checker that overwrites everything it can reach, then reports normally.
	vandal := filepath.Join(t.TempDir(), "vandal-checker")
	script := `#!/bin/sh
printf 'TAMPERED\n' > artifact/manifest.json
printf 'TAMPERED\n' > results/conformance.json 2>/dev/null
printf 'TAMPERED\n' > inputs/specification.txt 2>/dev/null
printf '{"runs":[{"run":"run-ael1-valid","grade":1,"r":"pending","checks":{}}]}\n'
`
	if err := os.WriteFile(vandal, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.CheckerPath = vandal

	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}

	// Everything the checker tried to overwrite still holds the emitter's bytes.
	for _, unchanged := range []struct {
		path      string
		forbidden string
	}{
		{filepath.Join("artifact", "manifest.json"), "TAMPERED"},
		{filepath.Join("results", "conformance.json"), "TAMPERED"},
		{filepath.Join("inputs", "specification.txt"), "TAMPERED"},
	} {
		raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, unchanged.path))
		if err != nil {
			t.Fatalf("read %s: %v", unchanged.path, err)
		}
		if indexOf(string(raw), unchanged.forbidden) >= 0 {
			t.Errorf("%s carries bytes the checker wrote: %q", unchanged.path, raw)
		}
	}

	// And the package still validates, so the replica did not cost integrity.
	validation, err := ael.ValidatePackage(harness.options.OutDir, harness.trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validation.DisplayState != "EVALUATED" {
		t.Errorf("display state = %q, want EVALUATED", validation.DisplayState)
	}
}

// TestEmitBindsCopiedSpecAndInitialCorpusDigest makes the checker mutate the
// caller's external sources after they have been copied. The package must bind
// its bundled specification and the corpus identity observed before execution,
// not bytes changed by the subprocess after the evaluation began.
func TestEmitBindsCopiedSpecAndInitialCorpusDigest(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	originalCorpus, err := os.ReadFile(harness.options.CorpusDigestPath)
	if err != nil {
		t.Fatal(err)
	}
	checker := filepath.Join(t.TempDir(), "mutating-external-source-checker")
	const script = `#!/bin/sh
if [ "$1" = "--json" ]; then
  printf '{"runs":[{"run":"run-ael1-valid"}]}\n'
  printf 'changed specification\n' > "$AEL_EMIT_TEST_SPEC"
  printf 'changed corpus\n' > "$AEL_EMIT_TEST_CORPUS"
else
  printf 'checker output\n'
fi
`
	if err := os.WriteFile(checker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEL_EMIT_TEST_SPEC", harness.options.SpecPath)
	t.Setenv("AEL_EMIT_TEST_CORPUS", harness.options.CorpusDigestPath)
	harness.options.CheckerPath = checker

	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ael.PackageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	bundledSpecDigest, err := digestFile(filepath.Join(harness.options.OutDir, "inputs", "specification.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Spec.Digest != bundledSpecDigest {
		t.Errorf("spec digest = %s, want digest of bundled specification %s", manifest.Spec.Digest, bundledSpecDigest)
	}
	corpusSum := sha256.Sum256(originalCorpus)
	wantCorpusDigest := hex.EncodeToString(corpusSum[:])
	if manifest.Conformance.Corpus.Digest != wantCorpusDigest {
		t.Errorf("corpus digest = %s, want pre-execution digest %s", manifest.Conformance.Corpus.Digest, wantCorpusDigest)
	}
}

// TestEmitPublishesOnlyAfterCheckerCompletes ensures a checker cannot observe
// or mutate the requested destination while the package is still being
// assembled and signed.
func TestEmitPublishesOnlyAfterCheckerCompletes(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	checker := filepath.Join(t.TempDir(), "output-visibility-checker")
	marker := filepath.Join(t.TempDir(), "output-state")
	const script = `#!/bin/sh
if [ -e "$AEL_EMIT_TEST_OUT" ]; then
  printf 'visible\n' > "$AEL_EMIT_TEST_MARKER"
else
  printf 'hidden\n' > "$AEL_EMIT_TEST_MARKER"
fi
if [ "$1" = "--json" ]; then
  printf '{"runs":[{"run":"run-ael1-valid"}]}\n'
else
  printf 'checker output\n'
fi
`
	if err := os.WriteFile(checker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEL_EMIT_TEST_OUT", harness.options.OutDir)
	t.Setenv("AEL_EMIT_TEST_MARKER", marker)
	harness.options.CheckerPath = checker

	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	state, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(state) != "hidden\n" {
		t.Errorf("output was %q while checker ran, want hidden", state)
	}
	if _, err := os.Stat(harness.options.OutDir); err != nil {
		t.Errorf("completed package was not published: %v", err)
	}
}

// TestEmitPublishesIntoEmptyRequestedDirectory preserves the documented
// convenience form while still replacing the placeholder atomically.
func TestEmitPublishesIntoEmptyRequestedDirectory(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	if err := os.MkdirAll(harness.options.OutDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(harness.options.OutDir, "manifest.json")); err != nil {
		t.Errorf("published package has no manifest: %v", err)
	}
}

func digestFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// writeConformanceCommand creates a script standing in for a real conformance
// run: it writes a result blob to stdout and exits with the given status.
func writeConformanceCommand(t *testing.T, verdict string, exitStatus int) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "conformance.sh")
	body := "#!/bin/sh\n" +
		"printf '{\"result\":\"" + verdict + "\"}\\n'\n" +
		"exit " + strconv.Itoa(exitStatus) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// TestEmitObservesConformanceExitStatus is the fix for a contradiction the
// declared form allowed: a package could carry a conformance blob reporting
// failure alongside a declared exit of zero, and still validate as EVALUATED.
// Running the command makes the blob and the status come from one process, so
// they cannot disagree.
func TestEmitObservesConformanceExitStatus(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{writeConformanceCommand(t, "FAIL", 3)}

	result, err := ael.EmitEvaluationPackage(harness.options)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if result.ConformanceExitStatus != 3 {
		t.Fatalf("conformance exit status = %d, want the observed 3", result.ConformanceExitStatus)
	}

	validation, err := ael.ValidatePackage(harness.options.OutDir, harness.trustRoot, ael.PackageValidationOptions{})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if validation.DisplayState != "CONFORMANCE-FAILED" {
		t.Errorf("display state = %q, want CONFORMANCE-FAILED", validation.DisplayState)
	}
}

// TestEmitCapturesConformanceOutput holds that the packaged conformance
// evidence is what the run produced, not a file the operator chose.
func TestEmitCapturesConformanceOutput(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{writeConformanceCommand(t, "pass", 0)}

	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(harness.options.OutDir, "results", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(string(raw), `"result":"pass"`) < 0 {
		t.Errorf("packaged conformance result is not the command's output: %q", raw)
	}
}

// TestEmitRefusesConformanceThatMutatesPackageInput closes an ordering hole.
// The input snapshot was taken AFTER the conformance command ran, so the
// mutation guard covered the checker and not conformance: anything the
// conformance command changed was already baked into the digests that get
// signed. The command runs with the emitter's privileges, so this is reachable
// by a buggy suite as easily as a hostile one.
func TestEmitRefusesConformanceThatMutatesPackageInput(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")

	// A conformance command that reaches into the staging directory and
	// rewrites a packaged artifact input while emission is still running.
	script := filepath.Join(t.TempDir(), "mutating-conformance.sh")
	parent := filepath.Dir(harness.options.OutDir)
	base := filepath.Base(harness.options.OutDir)
	body := "#!/bin/sh\n" +
		"for stage in " + parent + "/." + base + ".aelpackage-*; do\n" +
		"  if [ -d \"$stage/artifact\" ]; then\n" +
		"    printf 'mutated\\n' >> \"$stage/artifact/manifest.json\"\n" +
		"  fi\n" +
		"done\n" +
		"printf '{\"result\":\"pass\"}\\n'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.ConformanceCommand = []string{script}

	_, err := ael.EmitEvaluationPackage(harness.options)
	if err == nil {
		t.Fatal("emit accepted a conformance command that rewrote a packaged input")
	}
	if indexOf(err.Error(), "changed package input") < 0 {
		t.Errorf("error does not name the input mutation: %v", err)
	}
	if _, statErr := os.Stat(harness.options.OutDir); !os.IsNotExist(statErr) {
		t.Errorf("a refused emit published a package: %v", statErr)
	}
}

// TestEmitBoundsConformanceOutput holds the limit that keeps a runaway
// conformance command from taking emission down with it. The capture becomes
// signed evidence, so it errors rather than truncating: a clipped conformance
// report can still parse, and the package would then carry evidence that reads
// as complete while describing a partial run.
func TestEmitBoundsConformanceOutput(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	script := filepath.Join(t.TempDir(), "flooding-conformance.sh")
	// Emit far past the stdout ceiling.
	body := "#!/bin/sh\nexec yes ael-flood\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.ConformanceCommand = []string{script}

	_, err := ael.EmitEvaluationPackage(harness.options)
	if err == nil {
		t.Fatal("emit accepted unbounded conformance output")
	}
	if indexOf(err.Error(), "more output than the emitter accepts") < 0 {
		t.Errorf("error does not name the output limit: %v", err)
	}
}

// TestEmitBoundsConformanceRuntime holds the deadline. A conformance process
// that waits forever would otherwise block emission with no way out.
func TestEmitBoundsConformanceRuntime(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	script := filepath.Join(t.TempDir(), "hanging-conformance.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.ConformanceCommand = []string{script}
	harness.options.CommandTimeout = 2 * time.Second

	start := time.Now()
	_, err := ael.EmitEvaluationPackage(harness.options)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("emit accepted a conformance command that never finishes")
	}
	if elapsed > 60*time.Second {
		t.Errorf("emit waited %v, so the deadline did not apply", elapsed)
	}
}

// TestEmitRunsConformanceWithoutAShell records the trust boundary for executing
// a conformance command, because "the emitter runs a command" invites the
// reading that it is a shell-injection surface. It is not one.
//
// The command is passed as an argv vector to exec, with no shell between the
// caller and the process, so metacharacters arrive at the program as literal
// argument bytes rather than being interpreted. The command also reaches the
// emitter only as an operator flag: it is never read from the artifact, the
// package, or any file the evaluated subject can write.
//
// That leaves the operator, who already supplies the checker executable this
// command runs beside. An operator who can choose what the emitter executes can
// already execute anything as themselves, so refusing to run the conformance
// command would remove no capability they lack, while reintroducing the
// declared-conformance contradiction this package exists to close.
func TestEmitRunsConformanceWithoutAShell(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "shell-probe-must-not-exist")
	script := filepath.Join(t.TempDir(), "argv-conformance.sh")
	body := "#!/bin/sh\nprintf '{\"result\":\"pass\",\"argument\":\"%s\"}\\n' \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	// If any shell interpreted this, the substitution runs and the probe appears.
	hostile := "$(touch " + probe + ")"

	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{script, hostile}
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}

	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Fatalf("a shell interpreted the conformance argument and ran the substitution: %v", err)
	}
	packaged, err := os.ReadFile(filepath.Join(harness.options.OutDir, "results", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(packaged), hostile) {
		t.Errorf("the argument did not reach the process literally: %q", packaged)
	}
}

// TestEmitRefusesCheckerThatRewritesConformanceEvidence covers the one file a
// subprocess could still rewrite. The package-input snapshot is taken before
// conformance runs, so the conformance result is legitimately new relative to
// it and is exempted from the mutation check. That same exemption was then
// carried into the check that runs after the CHECKER, which had no business
// touching the file at all, so the checker could replace the conformance
// TestConformanceEvidenceSurvivesAHostileChecker holds the property the whole
// pull request exists for. The conformance result is the evidence a reader
// trusts, and it was once the single file a later subprocess could rewrite and
// have signed. The checker cannot reach it now.
func TestConformanceEvidenceSurvivesAHostileChecker(t *testing.T) {
	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{writeConformanceCommand(t, "pass", 0)}

	forging := filepath.Join(t.TempDir(), "forging-checker")
	script := `#!/bin/sh
printf '{"result":"FORGED"}\n' > results/conformance.json 2>/dev/null
printf '{"runs":[{"run":"run-ael1-valid","grade":1,"r":"pending","checks":{}}]}\n'
`
	if err := os.WriteFile(forging, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	harness.options.CheckerPath = forging

	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}
	packaged, err := os.ReadFile(filepath.Join(harness.options.OutDir, "results", "conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(string(packaged), "FORGED") >= 0 {
		t.Fatalf("the packaged conformance evidence is the checker's: %q", packaged)
	}
	if indexOf(string(packaged), `"result":"pass"`) < 0 {
		t.Errorf("the packaged conformance evidence is not what the conformance run produced: %q", packaged)
	}
}

// TestEmitLeavesNoMutatingDescendant covers a subprocess that exits cleanly and
// leaves a child behind. The process group was signalled only when the context
// cancelled, so a command could spawn a background writer, exit zero, and have
// that writer alter the package after the mutation check and before signing.
func TestEmitLeavesNoMutatingDescendant(t *testing.T) {
	probe := filepath.Join(t.TempDir(), "descendant-wrote-this")
	spawning := filepath.Join(t.TempDir(), "spawning-conformance.sh")
	script := "#!/bin/sh\n(sleep 3; printf 'x' > " + probe + ") &\nprintf '{\"result\":\"pass\"}\\n'\n"
	if err := os.WriteFile(spawning, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	harness := newEmitHarness(t, "ael1/valid")
	harness.options.ConformanceCommand = []string{spawning}
	if _, err := ael.EmitEvaluationPackage(harness.options); err != nil {
		t.Fatalf("emit: %v", err)
	}

	// Outlive the descendant's delay. If the group was reaped it never runs.
	time.Sleep(5 * time.Second)
	if _, err := os.Stat(probe); !os.IsNotExist(err) {
		t.Errorf("a descendant survived its parent's clean exit and kept writing: %v", err)
	}
}
