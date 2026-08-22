// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Emitting an evaluation package is deliberately a narrower act than writing
// one. The format has two kinds, and only one of them can honestly be produced
// by the party that ran the checker.
//
// A verification-record carries grades and is signed by a verifier whom the
// validator rejects when their identity equals the producer or the operator.
// The party invoking an emitter is the operator, so a self-emitted record could
// never validate. Rather than expose a kind flag whose second value always
// fails, this emitter produces evaluation packages only. The grade is somebody
// else's signature to write.
//
// The remaining discipline is that everything recorded here is observed rather
// than declared wherever observation is possible: the checker is executed and
// its streams and exit status captured, the shipped executable is digested as
// shipped, and the discovered runs come from the machine output rather than
// from the caller.

// Package layout. These are fixed so the recorded evaluation arguments are
// literally replayable from the package root.
const (
	emitArtifactDir     = "artifact"
	emitKeysDir         = "inputs/keys"
	emitPackageKeysDir  = "inputs/package-keys"
	emitSpecPath        = "inputs/specification.txt"
	emitResultsDir      = "results"
	emitMachineOutput   = "results/artifact.json"
	emitStdoutPath      = "results/stdout.txt"
	emitStderrPath      = "results/stderr.txt"
	emitConformancePath = "results/conformance.json"
	emitCheckerDir      = "checker"
)

// EmitOptions describes one evaluation to package. Fields divide into three
// groups: what is being evaluated, what produced the evaluation, and what the
// running party must declare because nothing in the run can establish it.
type EmitOptions struct {
	// Subject of the evaluation.
	ArtifactDir     string
	ArtifactKeysDir string

	// Producer of the evaluation. The executable at CheckerPath is both run
	// and digested, so the package binds the evaluation to the exact binary.
	CheckerPath    string
	CheckerName    string
	SourceRevision string

	// Declarations. None of these can be inferred from the run, and the
	// validator requires every one of them.
	PackageID         string
	ProducerID        string
	OperatorID        string
	OperatorKey       ed25519.PrivateKey
	StatusAuthorityID string
	StatusPublicKey   ed25519.PublicKey
	Custody           PackageCustody
	Coverage          PackageCoverage

	// Specification and conformance evidence.
	SpecVersion           string
	SpecPath              string
	CorpusVersion         string
	CorpusDigestPath      string
	ConformanceCommand    []string
	ConformanceResultPath string
	ConformanceExitStatus int

	// Run selects which discovered run the package is about. Empty means the
	// first discovered run.
	Run string

	IssuedAt time.Time
	OutDir   string
}

// EmitResult reports what the emitter observed. ExitStatus is the checker's,
// not the emitter's: a nonzero value means the artifact did not conform and the
// package says so, which is a successful emit of an unsuccessful evaluation.
type EmitResult struct {
	PackageDir     string   `json:"package_dir"`
	PackageID      string   `json:"package_id"`
	Run            string   `json:"run"`
	DiscoveredRuns []string `json:"discovered_runs"`
	ExitStatus     int      `json:"exit_status"`
}

// EmitEvaluationPackage runs the checker against the artifact and writes a
// signed evaluation package recording what happened.
//
// It returns an error only when the package cannot be honestly produced. A
// nonconforming artifact is not such a case: that run is packaged with its real
// exit status, because a reader needs the failure far more than the success,
// and an emitter that refused here would quietly turn every negative result
// into a missing file.
func EmitEvaluationPackage(options EmitOptions) (EmitResult, error) {
	if err := validateEmitOptions(options); err != nil {
		return EmitResult{}, err
	}
	if err := validateEmitPaths(options); err != nil {
		return EmitResult{}, err
	}

	// Assemble privately, then atomically publish the completed signed tree.
	// Writing directly to --out leaves a window after the checker has finished
	// where another local writer can alter bytes before their digests are signed.
	packageDir, err := createEmitStagingDir(options.OutDir)
	if err != nil {
		return EmitResult{}, err
	}

	// A failed emit removes only the private staging directory. Leaving a
	// half-written package behind turns one clear failure into a second,
	// confusing one when the retry reports a directory that is no longer empty.
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.RemoveAll(packageDir)
		}
	}()

	if err := copyTree(options.ArtifactDir, filepath.Join(packageDir, emitArtifactDir)); err != nil {
		return EmitResult{}, fmt.Errorf("copy artifact: %w", err)
	}
	if err := copyTree(options.ArtifactKeysDir, filepath.Join(packageDir, filepath.FromSlash(emitKeysDir))); err != nil {
		return EmitResult{}, fmt.Errorf("copy artifact keys: %w", err)
	}

	operatorPublic, ok := options.OperatorKey.Public().(ed25519.PublicKey)
	if !ok {
		return EmitResult{}, fmt.Errorf("operator key does not yield an ed25519 public key")
	}
	operatorFingerprint, err := writeEmitPublicKey(packageDir, operatorPublic)
	if err != nil {
		return EmitResult{}, err
	}
	statusFingerprint, err := writeEmitPublicKey(packageDir, options.StatusPublicKey)
	if err != nil {
		return EmitResult{}, err
	}

	checkerRelative := emitCheckerDir + "/" + options.CheckerName
	if err := copyFile(options.CheckerPath, filepath.Join(packageDir, filepath.FromSlash(checkerRelative)), 0o755); err != nil {
		return EmitResult{}, fmt.Errorf("copy checker executable: %w", err)
	}
	if err := copyFile(options.SpecPath, filepath.Join(packageDir, filepath.FromSlash(emitSpecPath)), 0o644); err != nil {
		return EmitResult{}, fmt.Errorf("copy specification: %w", err)
	}
	if err := copyFile(options.ConformanceResultPath, filepath.Join(packageDir, filepath.FromSlash(emitConformancePath)), 0o644); err != nil {
		return EmitResult{}, fmt.Errorf("copy conformance result: %w", err)
	}
	// The corpus identity lives outside the package, so capture its declared
	// digest before the checker runs. A later read could otherwise bind a source
	// file modified by the subprocess rather than the identity selected for this
	// evaluation.
	corpusDigest, err := fileDigest(options.CorpusDigestPath)
	if err != nil {
		return EmitResult{}, fmt.Errorf("digest corpus: %w", err)
	}

	// The checker runs inside the package so its relative replay arguments are
	// literal. Snapshot every input after assembly and reject any persistent
	// mutation from either invocation: otherwise the manifest could digest a
	// replacement binary or artifact rather than the bytes that produced its
	// recorded result.
	inputs, err := packageFileBlobs(packageDir)
	if err != nil {
		return EmitResult{}, err
	}
	evaluation, err := runEmitEvaluation(packageDir, checkerRelative, inputs)
	if err != nil {
		return EmitResult{}, err
	}

	var report Report
	if err := json.Unmarshal(evaluation.machineOutput, &report); err != nil {
		// The checker's own stderr says why it could not evaluate, and
		// reporting only the JSON parse error would hide that diagnosis behind
		// a symptom the operator cannot act on.
		diagnosis := strings.TrimSpace(string(evaluation.stderr))
		if diagnosis == "" {
			diagnosis = "checker produced no diagnostic output"
		}
		return EmitResult{}, fmt.Errorf("checker exited %d without a usable report: %s", evaluation.exitStatus, diagnosis)
	}
	discovered := discoveredPackageRuns(report)
	if len(discovered) == 0 {
		return EmitResult{}, fmt.Errorf("checker reported no runs; nothing to package")
	}
	run := options.Run
	if run == "" {
		run = discovered[0]
	} else if !containsString(discovered, run) {
		return EmitResult{}, fmt.Errorf("requested run %q is not among discovered runs %v", run, discovered)
	}

	// Bind the specification bytes actually shipped in the package, not a
	// caller-side source file that could have changed after the copy.
	specDigest, err := fileDigest(filepath.Join(packageDir, filepath.FromSlash(emitSpecPath)))
	if err != nil {
		return EmitResult{}, fmt.Errorf("digest specification: %w", err)
	}

	files, err := packageFileBlobs(packageDir)
	if err != nil {
		return EmitResult{}, err
	}
	blobByPath := map[string]PackageBlob{}
	for _, blob := range files {
		blobByPath[blob.Path] = blob
	}
	lookup := func(name string) (PackageBlob, error) {
		blob, ok := blobByPath[name]
		if !ok {
			return PackageBlob{}, fmt.Errorf("expected package file %q is absent", name)
		}
		return blob, nil
	}

	artifactManifest, err := lookup(emitArtifactDir + "/" + packageManifestName)
	if err != nil {
		return EmitResult{}, err
	}
	executable, err := lookup(checkerRelative)
	if err != nil {
		return EmitResult{}, err
	}
	machineOutput, err := lookup(emitMachineOutput)
	if err != nil {
		return EmitResult{}, err
	}
	stdout, err := lookup(emitStdoutPath)
	if err != nil {
		return EmitResult{}, err
	}
	stderr, err := lookup(emitStderrPath)
	if err != nil {
		return EmitResult{}, err
	}
	conformanceResult, err := lookup(emitConformancePath)
	if err != nil {
		return EmitResult{}, err
	}

	// Every published key must be replayable from inside the package, so the
	// verification inputs carry the artifact keys plus the package signer and
	// status keys rather than assuming a reader can fetch them.
	var verificationInputs []PackageBlob
	for _, blob := range files {
		if strings.HasPrefix(blob.Path, emitKeysDir+"/") || strings.HasPrefix(blob.Path, emitPackageKeysDir+"/") {
			verificationInputs = append(verificationInputs, blob)
		}
	}

	manifest := PackageManifest{
		Kind:                "evaluation-package",
		PackageFormat:       1,
		ID:                  options.PackageID,
		Run:                 run,
		Producer:            PackageParty{ID: options.ProducerID},
		Operator:            PackageSigner{ID: options.OperatorID, Key: operatorFingerprint},
		VerificationCustody: options.Custody,
		EvidenceCoverage:    options.Coverage,
		ArtifactBinding: PackageBinding{
			Root:           emitArtifactDir,
			KeysDir:        emitKeysDir,
			Manifest:       artifactManifest,
			DiscoveredRuns: discovered,
		},
		Files:              files,
		VerificationInputs: verificationInputs,
		Spec:               PackageVersionedSum{Version: options.SpecVersion, DigestAlgorithm: "sha-256", Digest: specDigest},
		Checker: PackageChecker{
			Name:           options.CheckerName,
			SourceRevision: options.SourceRevision,
			Executable:     executable,
		},
		ArtifactEvaluation: PackageEvaluation{
			Arguments:     evaluation.arguments,
			ExitStatus:    evaluation.exitStatus,
			MachineOutput: machineOutput,
			Stdout:        stdout,
			Stderr:        stderr,
		},
		Conformance: PackageConformance{
			Corpus:     PackageVersionedSum{Version: options.CorpusVersion, DigestAlgorithm: "sha-256", Digest: corpusDigest},
			Command:    options.ConformanceCommand,
			ExitStatus: options.ConformanceExitStatus,
			Result:     conformanceResult,
		},
		IssuedAt: options.IssuedAt.UTC().Format(time.RFC3339),
		StatusAuthority: PackageStatusAuthority{
			ID: options.StatusAuthorityID,
			// The validator requires record_id to equal the package id, so it
			// is derived rather than accepted. An option whose only valid value
			// is another option is a way to fail, not a degree of freedom.
			Key:      statusFingerprint,
			RecordID: options.PackageID,
		},
	}

	if err := writeSignedManifest(packageDir, manifest, options.OperatorKey); err != nil {
		return EmitResult{}, err
	}
	if err := publishEmitPackage(packageDir, options.OutDir); err != nil {
		return EmitResult{}, err
	}

	succeeded = true
	return EmitResult{
		PackageDir:     options.OutDir,
		PackageID:      options.PackageID,
		Run:            run,
		DiscoveredRuns: discovered,
		ExitStatus:     evaluation.exitStatus,
	}, nil
}

type emitEvaluation struct {
	arguments     []string
	exitStatus    int
	machineOutput []byte
	stderr        []byte
}

// runEmitEvaluation executes the checker from inside the package directory so
// the recorded arguments replay verbatim, and captures both the machine and
// human views of the same evaluation.
//
// The two invocations must agree on exit status. They are the same checker over
// the same bytes, so a disagreement means the evaluation is not reproducible,
// and a package asserting one of two possible outcomes would be a false record.
// Refusing is the honest direction even though it costs availability.
func runEmitEvaluation(packageDir, checkerRelative string, inputs []PackageBlob) (emitEvaluation, error) {
	checker := "./" + checkerRelative

	machineArgs := []string{"--json", "--keys", emitKeysDir, emitArtifactDir}
	machineStdout, machineStderr, machineExit, err := runChecker(packageDir, checker, machineArgs)
	if err != nil {
		return emitEvaluation{}, err
	}
	if err := assertPackageInputsUnchanged(packageDir, inputs); err != nil {
		return emitEvaluation{}, err
	}

	humanArgs := []string{"--keys", emitKeysDir, emitArtifactDir}
	humanStdout, _, humanExit, err := runChecker(packageDir, checker, humanArgs)
	if err != nil {
		return emitEvaluation{}, err
	}
	if err := assertPackageInputsUnchanged(packageDir, inputs); err != nil {
		return emitEvaluation{}, err
	}
	if machineExit != humanExit {
		return emitEvaluation{}, fmt.Errorf(
			"checker is not reproducible: exit status %d with %v but %d with %v",
			machineExit, machineArgs, humanExit, humanArgs)
	}

	writes := []struct {
		path string
		data []byte
	}{
		{emitMachineOutput, machineStdout},
		{emitStdoutPath, humanStdout},
		{emitStderrPath, machineStderr},
	}
	for _, write := range writes {
		full := filepath.Join(packageDir, filepath.FromSlash(write.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return emitEvaluation{}, err
		}
		if err := os.WriteFile(full, write.data, 0o644); err != nil {
			return emitEvaluation{}, fmt.Errorf("write %s: %w", write.path, err)
		}
	}

	return emitEvaluation{arguments: machineArgs, exitStatus: machineExit, machineOutput: machineStdout, stderr: machineStderr}, nil
}

// runChecker runs one checker invocation. A nonzero exit is a result, not an
// error; only a failure to execute at all is an error, because the two demand
// opposite responses from the caller.
func runChecker(dir, checker string, args []string) (stdout, stderr []byte, exitStatus int, err error) {
	command := exec.Command(checker, args...)
	command.Dir = dir
	var outBuffer, errBuffer strings.Builder
	command.Stdout = &outBuffer
	command.Stderr = &errBuffer
	runErr := command.Run()
	stdout = []byte(outBuffer.String())
	stderr = []byte(errBuffer.String())
	if runErr != nil {
		exitError, ok := runErr.(*exec.ExitError)
		if !ok {
			return nil, nil, 0, fmt.Errorf("run checker %v: %w", args, runErr)
		}
		return stdout, stderr, exitError.ExitCode(), nil
	}
	return stdout, stderr, 0, nil
}

// validateEmitPaths refuses an output directory that overlaps an input.
//
// Nesting the package inside the artifact makes the copy its own source: the
// walk keeps finding the files it just wrote and recurses until the filesystem
// refuses a path, having written thousands of files first. The failure is closed
// rather than silent, but it costs an operator their disk over a plausible slip
// such as --out ./package while standing in the artifact directory, so the
// overlap is rejected before any copying starts.
func validateEmitPaths(options EmitOptions) error {
	out, err := resolveEmitPath(options.OutDir)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	for _, input := range []struct {
		name string
		path string
	}{
		{"artifact directory", options.ArtifactDir},
		{"artifact keys directory", options.ArtifactKeysDir},
	} {
		resolved, err := resolveEmitPath(input.path)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", input.name, err)
		}
		if pathWithin(out, resolved) {
			return fmt.Errorf("output directory %q is inside the %s %q", options.OutDir, input.name, input.path)
		}
		if pathWithin(resolved, out) {
			return fmt.Errorf("%s %q is inside the output directory %q", input.name, input.path, options.OutDir)
		}
	}
	return nil
}

// resolveEmitPath resolves every existing path component while retaining a
// possible final path that has not been created yet. filepath.Abs alone is a
// lexical operation, so it misses an output such as outside-link/package when
// outside-link resolves into the artifact being copied.
func resolveEmitPath(value string) (string, error) {
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	probe := abs
	var missing []string
	for {
		if _, err := os.Lstat(probe); err == nil {
			resolved, err := filepath.EvalSymlinks(probe)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(probe)
		if parent == probe {
			return "", fmt.Errorf("no existing parent for %q", value)
		}
		missing = append(missing, filepath.Base(probe))
		probe = parent
	}
}

// pathWithin reports whether candidate is ancestor itself or lives beneath it.
// Both paths must already be absolute and cleaned.
func pathWithin(candidate, ancestor string) bool {
	if candidate == ancestor {
		return true
	}
	return strings.HasPrefix(candidate, ancestor+string(filepath.Separator))
}

func validateEmitOptions(options EmitOptions) error {
	required := []struct {
		name  string
		value string
	}{
		{"artifact directory", options.ArtifactDir},
		{"artifact keys directory", options.ArtifactKeysDir},
		{"checker path", options.CheckerPath},
		{"checker name", options.CheckerName},
		{"source revision", options.SourceRevision},
		{"package id", options.PackageID},
		{"producer id", options.ProducerID},
		{"operator id", options.OperatorID},
		{"status authority id", options.StatusAuthorityID},
		{"specification version", options.SpecVersion},
		{"specification path", options.SpecPath},
		{"corpus version", options.CorpusVersion},
		{"corpus digest path", options.CorpusDigestPath},
		{"conformance result path", options.ConformanceResultPath},
		{"output directory", options.OutDir},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if strings.Contains(options.CheckerName, "/") || strings.Contains(options.CheckerName, `\`) {
		return fmt.Errorf("checker name must be a bare file name")
	}
	if len(options.OperatorKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("operator key must be a %d-byte ed25519 private key", ed25519.PrivateKeySize)
	}
	if len(options.StatusPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("status authority public key must be a %d-byte ed25519 public key", ed25519.PublicKeySize)
	}
	if len(options.ConformanceCommand) == 0 {
		return fmt.Errorf("conformance command is required")
	}
	if options.ConformanceExitStatus < 0 {
		return fmt.Errorf("conformance exit status must be non-negative")
	}
	if !packageTextPresent(options.Custody.Acquisition, options.Custody.Replay, options.Custody.Review, options.Custody.Issuance) {
		return fmt.Errorf("verification custody fields are required")
	}
	if !packageTextPresent(options.Coverage.Scope, options.Coverage.Disclosure) {
		return fmt.Errorf("evidence coverage fields are required")
	}
	if options.IssuedAt.IsZero() {
		return fmt.Errorf("issued-at time is required")
	}
	return nil
}

// writeSignedManifest canonicalizes and signs the manifest using the same
// canonicalizer the validator applies. A second implementation here could drift
// from that one, and the gap between two canonicalizers is exactly where a
// signature stops covering what a reader parses.
func writeSignedManifest(packageDir string, manifest PackageManifest, signer ed25519.PrivateKey) error {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	canonical, err := Canonicalize(encoded)
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, packageManifestName), canonical, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(signer, canonical))
	if err := os.WriteFile(filepath.Join(packageDir, packageSignatureName), []byte(signature+"\n"), 0o644); err != nil {
		return fmt.Errorf("write manifest signature: %w", err)
	}
	return nil
}

func writeEmitPublicKey(packageDir string, public ed25519.PublicKey) (string, error) {
	sum := sha256.Sum256(public)
	fingerprint := hex.EncodeToString(sum[:])
	dir := filepath.Join(packageDir, filepath.FromSlash(emitPackageKeysDir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(public) + "\n"
	if err := os.WriteFile(filepath.Join(dir, fingerprint+".pub"), []byte(encoded), 0o644); err != nil {
		return "", fmt.Errorf("write package key: %w", err)
	}
	return fingerprint, nil
}

// packageFileBlobs digests every file the package will publish. The manifest
// and its signature are excluded because they cannot describe themselves.
func packageFileBlobs(packageDir string) ([]PackageBlob, error) {
	var blobs []PackageBlob
	err := filepath.WalkDir(packageDir, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			relative, relErr := filepath.Rel(packageDir, current)
			if relErr != nil {
				return relErr
			}
			return fmt.Errorf("package contains non-regular file %q", filepath.ToSlash(relative))
		}
		relative, err := filepath.Rel(packageDir, current)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == packageManifestName || name == packageSignatureName {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		digest, err := fileDigest(current)
		if err != nil {
			return err
		}
		blobs = append(blobs, PackageBlob{
			Path:            name,
			Size:            info.Size(),
			DigestAlgorithm: "sha-256",
			Digest:          digest,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("index package files: %w", err)
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].Path < blobs[j].Path })
	return blobs, nil
}

// assertPackageInputsUnchanged rejects any persistent change to the copied
// artifact, inputs, or checker across an invocation. The checker produces its
// streams through pipes; a package-tree change visible after it exits means the
// recorded evaluation no longer has one stable set of input bytes to bind and
// must not be signed.
func assertPackageInputsUnchanged(packageDir string, expected []PackageBlob) error {
	actual, err := packageFileBlobs(packageDir)
	if err != nil {
		return err
	}
	for index := 0; index < len(expected) || index < len(actual); index++ {
		if index == len(expected) {
			return fmt.Errorf("checker added package input %q", actual[index].Path)
		}
		if index == len(actual) {
			return fmt.Errorf("checker removed package input %q", expected[index].Path)
		}
		if expected[index] != actual[index] {
			return fmt.Errorf("checker changed package input %q", expected[index].Path)
		}
	}
	return nil
}

func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func directoryIsEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	return len(entries) == 0, nil
}

// createEmitStagingDir prepares the requested destination without making a
// partial package visible there. The staging directory is a private sibling so
// publication can use an atomic same-filesystem rename.
func createEmitStagingDir(out string) (string, error) {
	parent := filepath.Dir(out)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("create package parent: %w", err)
	}
	if info, err := os.Stat(out); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("package directory %q is not a directory", out)
		}
		empty, err := directoryIsEmpty(out)
		if err != nil {
			return "", err
		}
		if !empty {
			// Emitting into a populated directory would let unrelated files be
			// swept into the signed file list, so the signature would cover bytes
			// the operator never chose to publish.
			return "", fmt.Errorf("package directory %q is not empty", out)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect package directory: %w", err)
	}
	stage, err := os.MkdirTemp(parent, "."+filepath.Base(out)+".aelpackage-")
	if err != nil {
		return "", fmt.Errorf("create package staging directory: %w", err)
	}
	return stage, nil
}

// publishEmitPackage replaces only an empty requested destination with the
// completed signed staging tree. Staging lives under the same parent, so the
// rename is atomic and a consumer sees either no package or a complete one.
func publishEmitPackage(stage, out string) error {
	if err := os.Chmod(stage, 0o755); err != nil {
		return fmt.Errorf("set package directory mode: %w", err)
	}
	if _, err := os.Lstat(out); err == nil {
		empty, err := directoryIsEmpty(out)
		if err != nil {
			return fmt.Errorf("inspect package directory before publish: %w", err)
		}
		if !empty {
			return fmt.Errorf("package directory %q became non-empty before publish", out)
		}
		if err := os.Remove(out); err != nil {
			return fmt.Errorf("clear empty package directory before publish: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect package directory before publish: %w", err)
	}
	if err := os.Rename(stage, out); err != nil {
		return fmt.Errorf("publish package: %w", err)
	}
	return nil
}

func copyFile(source, destination string, mode fs.FileMode) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destination, raw, mode)
}

// copyTree copies a directory into the package. Only regular files and
// directories are copied; a symlink is refused rather than followed, because a
// link resolving outside the source would pull unrelated bytes under the
// operator's signature.
func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
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
		if !entry.Type().IsRegular() {
			return fmt.Errorf("refusing to copy non-regular file %q", filepath.ToSlash(relative))
		}
		return copyFile(current, target, 0o644)
	})
}
