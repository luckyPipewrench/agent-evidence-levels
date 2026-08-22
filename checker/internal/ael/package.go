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
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	packageManifestName   = "manifest.json"
	packageSignatureName  = "manifest.sig"
	packageTrustOperators = "operators"
	packageTrustVerifiers = "verifiers"
	packageTrustStatus    = "status"
)

// PackageManifest is the signed table of contents for an evaluation package or
// verification record. It deliberately has distinct signing roles: evaluation
// packages are signed by an operator, while verification records are signed by
// an eligible verifier.
type PackageManifest struct {
	Kind                string                 `json:"kind"`
	PackageFormat       int                    `json:"package_format"`
	ID                  string                 `json:"id"`
	Run                 string                 `json:"run"`
	Producer            PackageParty           `json:"producer"`
	Operator            PackageSigner          `json:"operator"`
	Verifier            *PackageVerifier       `json:"verifier,omitempty"`
	VerificationCustody PackageCustody         `json:"verification_custody"`
	EvidenceCoverage    PackageCoverage        `json:"evidence_coverage"`
	ArtifactBinding     PackageBinding         `json:"artifact_binding"`
	Files               []PackageBlob          `json:"files"`
	VerificationInputs  []PackageBlob          `json:"verification_inputs"`
	Spec                PackageVersionedSum    `json:"spec"`
	Checker             PackageChecker         `json:"checker"`
	ArtifactEvaluation  PackageEvaluation      `json:"artifact_evaluation"`
	Conformance         PackageConformance     `json:"conformance"`
	Grades              []PackageGrade         `json:"grades,omitempty"`
	IssuedAt            string                 `json:"issued_at"`
	ExpiresAt           string                 `json:"expires_at,omitempty"`
	StatusAuthority     PackageStatusAuthority `json:"status_authority"`
}

type PackageParty struct {
	ID string `json:"id"`
}

type PackageSigner struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type PackageVerifier struct {
	ID                     string `json:"id"`
	Key                    string `json:"key"`
	RelationshipToProducer string `json:"relationship_to_producer"`
	RelationshipToOperator string `json:"relationship_to_operator"`
}

type PackageCustody struct {
	Acquisition string `json:"acquisition"`
	Replay      string `json:"replay"`
	Review      string `json:"review"`
	Issuance    string `json:"issuance"`
}

type PackageCoverage struct {
	Scope      string `json:"scope"`
	Disclosure string `json:"disclosure"`
}

type PackageBlob struct {
	Path            string `json:"path"`
	Size            int64  `json:"size"`
	DigestAlgorithm string `json:"digest_algorithm"`
	Digest          string `json:"digest"`
	URL             string `json:"url,omitempty"`
}

type PackageBinding struct {
	Root           string      `json:"root"`
	KeysDir        string      `json:"keys_dir"`
	Manifest       PackageBlob `json:"manifest"`
	DiscoveredRuns []string    `json:"discovered_runs"`
}

type PackageVersionedSum struct {
	Version         string `json:"version"`
	DigestAlgorithm string `json:"digest_algorithm"`
	Digest          string `json:"digest"`
}

type PackageChecker struct {
	Name           string      `json:"name"`
	SourceRevision string      `json:"source_revision"`
	Executable     PackageBlob `json:"executable"`
}

type PackageEvaluation struct {
	Arguments     []string    `json:"arguments"`
	ExitStatus    int         `json:"exit_status"`
	MachineOutput PackageBlob `json:"machine_output"`
	Stdout        PackageBlob `json:"stdout"`
	Stderr        PackageBlob `json:"stderr"`
}

type PackageConformance struct {
	Corpus     PackageVersionedSum `json:"corpus"`
	Command    []string            `json:"command"`
	ExitStatus int                 `json:"exit_status"`
	Result     PackageBlob         `json:"result"`
}

type PackageGrade struct {
	Run         string                   `json:"run"`
	Line        string                   `json:"line"`
	Annotations PackageGradeAnnotations  `json:"annotations"`
	Outcomes    map[string]OutcomeStatus `json:"outcomes"`
}

type PackageGradeAnnotations struct {
	Coverage  string `json:"coverage"`
	Custody   string `json:"custody"`
	Anchor    string `json:"anchor"`
	Retention string `json:"retention"`
}

type PackageStatusAuthority struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	RecordID string `json:"record_id"`
	URL      string `json:"url,omitempty"`
}

// VerificationStatus is a separately signed status statement. It is not part
// of the immutable record, and a current statement is valid only for its
// authority-chosen freshness interval.
type VerificationStatus struct {
	StatusFormat int    `json:"status_format"`
	RecordID     string `json:"record_id"`
	Authority    string `json:"authority"`
	IssuedAt     string `json:"issued_at"`
	NextUpdate   string `json:"next_update,omitempty"`
	EffectiveAt  string `json:"effective_at,omitempty"`
	State        string `json:"state"`
	Reason       string `json:"reason,omitempty"`
	Replacement  string `json:"replacement,omitempty"`
}

// PackageValidation is the consumer-facing result. VERIFIED is reachable only
// for a verification record with a trusted, current status statement.
type PackageValidation struct {
	Kind         string `json:"kind"`
	ID           string `json:"id"`
	DisplayState string `json:"display_state"`
}

// PackageValidationError classifies a failed validation for a consumer display.
// Callers must not turn an error into VERIFIED.
type PackageValidationError struct {
	State string
	Err   error
}

// PackageValidationOptions supplies consumer policy inputs that are not part
// of the signed package. A verification record can display VERIFIED only when
// EvaluationTime is set and its status statement is fresh at that time.
// MaxStatusAge optionally shortens a current statement's signed interval; zero
// leaves the authority-chosen interval unchanged.
type PackageValidationOptions struct {
	StatusPath          string
	StatusSignaturePath string
	EvaluationTime      time.Time
	MaxStatusAge        time.Duration
}

func (e *PackageValidationError) Error() string {
	return e.Err.Error()
}

func (e *PackageValidationError) Unwrap() error {
	return e.Err
}

func untrustedPackageError(format string, args ...any) error {
	return &PackageValidationError{State: "UNTRUSTED", Err: fmt.Errorf(format, args...)}
}

// ValidatePackage validates a signed package. keysDir contains separately
// trusted <fingerprint>.pub files in operators/, verifiers/, and status/.
// An operator key can validate an evaluation package but cannot validate a
// verification record. Omitting the status inputs or the consumer-supplied
// EvaluationTime leaves a verification record STATUS-UNKNOWN rather than
// treating it as current.
func ValidatePackage(dir, keysDir string, options PackageValidationOptions) (PackageValidation, error) {
	snapshot, cleanup, err := snapshotPackageDir(dir)
	if err != nil {
		return PackageValidation{}, err
	}
	defer cleanup()
	return validatePackageDir(snapshot, keysDir, options)
}

func validatePackageDir(dir, keysDir string, options PackageValidationOptions) (PackageValidation, error) {
	manifestPath, err := safePackagePath(dir, packageManifestName)
	if err != nil {
		return PackageValidation{}, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return PackageValidation{}, fmt.Errorf("read package manifest: %w", err)
	}
	if !IsCanonical(raw) {
		return PackageValidation{}, fmt.Errorf("package manifest is not canonical")
	}
	if err := validatePackageManifestSchema(raw); err != nil {
		return PackageValidation{}, fmt.Errorf("package schema: %w", err)
	}

	var manifest PackageManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return PackageValidation{}, fmt.Errorf("parse package manifest: %w", err)
	}
	if err := validatePackageSemantics(&manifest); err != nil {
		return PackageValidation{}, err
	}

	signerKeys, err := loadPackageTrustKeys(keysDir, packageSignerTrustRole(&manifest))
	if err != nil {
		return PackageValidation{}, err
	}
	if err := verifyPackageSignature(dir, raw, packageSignerKey(&manifest), signerKeys); err != nil {
		return PackageValidation{}, err
	}
	if err := validatePackageBlobs(dir, &manifest); err != nil {
		return PackageValidation{}, err
	}
	if err := validatePackageInputKeys(dir, &manifest); err != nil {
		return PackageValidation{}, err
	}
	if err := validateArtifactBinding(dir, &manifest); err != nil {
		return PackageValidation{}, err
	}
	if manifest.Kind == "verification-record" && manifest.ArtifactEvaluation.ExitStatus == 0 {
		if err := validatePackageGradesAgainstMachineOutput(dir, &manifest); err != nil {
			return PackageValidation{}, err
		}
	}
	result := PackageValidation{Kind: manifest.Kind, ID: manifest.ID, DisplayState: "EVALUATED"}
	if manifest.ArtifactEvaluation.ExitStatus != 0 {
		result.DisplayState = "EVALUATION-FAILED"
		return result, nil
	}
	if manifest.Conformance.ExitStatus != 0 {
		result.DisplayState = "CONFORMANCE-FAILED"
		return result, nil
	}
	if manifest.Kind == "evaluation-package" {
		return result, nil
	}
	if options.MaxStatusAge < 0 {
		return PackageValidation{}, fmt.Errorf("maximum status age must not be negative")
	}
	if !hasConsumerEvaluationTime(options.EvaluationTime) {
		result.DisplayState = "STATUS-UNKNOWN"
		return result, nil
	}
	evaluationTime := options.EvaluationTime.UTC()
	if manifest.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
		if err != nil {
			return PackageValidation{}, fmt.Errorf("expires_at: %w", err)
		}
		if !evaluationTime.Before(expires) {
			result.DisplayState = "EXPIRED"
			return result, nil
		}
	}
	if options.StatusPath == "" && options.StatusSignaturePath == "" {
		result.DisplayState = "STATUS-UNKNOWN"
		return result, nil
	}
	if options.StatusPath == "" || options.StatusSignaturePath == "" {
		result.DisplayState = "STATUS-UNKNOWN"
		return result, nil
	}
	statusKeys, statusErr := loadPackageTrustKeys(keysDir, packageTrustStatus)
	var status VerificationStatus
	if statusErr == nil {
		status, statusErr = validateVerificationStatus(&manifest, options.StatusPath, options.StatusSignaturePath, statusKeys)
	}
	if statusErr != nil {
		result.DisplayState = "STATUS-UNKNOWN"
		return result, nil
	}
	issued, err := time.Parse(time.RFC3339, status.IssuedAt)
	if err != nil {
		return PackageValidation{}, fmt.Errorf("status issued_at: %w", err)
	}
	if evaluationTime.Before(issued) {
		result.DisplayState = "STATUS-UNKNOWN"
		return result, nil
	}
	switch status.State {
	case "current":
		if options.MaxStatusAge > 0 && !evaluationTime.Before(issued.Add(options.MaxStatusAge)) {
			result.DisplayState = "STATUS-UNKNOWN"
			return result, nil
		}
		nextUpdate, err := time.Parse(time.RFC3339, status.NextUpdate)
		if err != nil {
			return PackageValidation{}, fmt.Errorf("status next_update: %w", err)
		}
		if !evaluationTime.Before(nextUpdate) {
			result.DisplayState = "STATUS-UNKNOWN"
			return result, nil
		}
		result.DisplayState = "VERIFIED"
	case "revoked":
		effective, err := time.Parse(time.RFC3339, status.EffectiveAt)
		if err != nil {
			return PackageValidation{}, fmt.Errorf("status effective_at: %w", err)
		}
		if evaluationTime.Before(effective) {
			result.DisplayState = "STATUS-UNKNOWN"
			return result, nil
		}
		result.DisplayState = "REVOKED"
	case "superseded":
		effective, err := time.Parse(time.RFC3339, status.EffectiveAt)
		if err != nil {
			return PackageValidation{}, fmt.Errorf("status effective_at: %w", err)
		}
		if evaluationTime.Before(effective) {
			result.DisplayState = "STATUS-UNKNOWN"
			return result, nil
		}
		result.DisplayState = "SUPERSEDED"
	default:
		return PackageValidation{}, fmt.Errorf("status state %q is invalid", status.State)
	}
	return result, nil
}

func hasConsumerEvaluationTime(evaluationTime time.Time) bool {
	return !evaluationTime.IsZero()
}

func snapshotPackageDir(dir string) (string, func(), error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return "", nil, fmt.Errorf("inspect package directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", nil, fmt.Errorf("package directory must be a non-symlink directory")
	}

	snapshot, err := os.MkdirTemp("", "aelpackage-")
	if err != nil {
		return "", nil, fmt.Errorf("create package snapshot: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(snapshot) }
	if err := filepath.WalkDir(dir, func(source string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, source)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package contains symlink %q", filepath.ToSlash(rel))
		}
		destination := filepath.Join(snapshot, rel)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("package contains non-regular file %q", filepath.ToSlash(rel))
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		return os.WriteFile(destination, raw, 0o600)
	}); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("snapshot package: %w", err)
	}
	return snapshot, cleanup, nil
}

func packageSignerTrustRole(manifest *PackageManifest) string {
	if manifest.Kind == "verification-record" {
		return packageTrustVerifiers
	}
	return packageTrustOperators
}

func loadPackageTrustKeys(root, role string) (map[string]ed25519.PublicKey, error) {
	keys, err := loadPackageTrustRoleKeys(root, role)
	if err != nil {
		return nil, untrustedPackageError("load trusted %s keys: %v", role, err)
	}
	if role == packageTrustVerifiers {
		operatorKeys, err := loadPackageTrustRoleKeys(root, packageTrustOperators)
		if err != nil {
			return nil, untrustedPackageError("load trusted %s keys: %v", packageTrustOperators, err)
		}
		for fingerprint := range keys {
			if _, alsoOperator := operatorKeys[fingerprint]; alsoOperator {
				return nil, untrustedPackageError("trusted verifier key %s is also trusted as an operator key", fingerprint)
			}
		}
	}
	return keys, nil
}

func loadPackageTrustRoleKeys(root, role string) (map[string]ed25519.PublicKey, error) {
	dir := filepath.Join(root, role)
	info, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]ed25519.PublicKey{}, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("trusted %s key directory must not be a symlink", role)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("trusted %s key directory contains symlink %q", role, entry.Name())
		}
	}
	return loadKeys(dir)
}

func packageSignerKey(manifest *PackageManifest) string {
	if manifest.Kind == "verification-record" && manifest.Verifier != nil {
		return manifest.Verifier.Key
	}
	return manifest.Operator.Key
}

func verifyPackageSignature(dir string, manifest []byte, fingerprint string, keys map[string]ed25519.PublicKey) error {
	pub, ok := keys[strings.ToLower(fingerprint)]
	if !ok {
		return untrustedPackageError("missing trusted package signer key %s", fingerprint)
	}
	sigPath, err := safePackagePath(dir, packageSignatureName)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read package manifest signature: %w", err)
	}
	sig, err := decodeStdBase64Field("manifest signature", strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, manifest, sig) {
		return fmt.Errorf("package manifest signature verification failed")
	}
	return nil
}

func validatePackageManifestSchema(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	kindRaw, ok := root["kind"]
	if !ok {
		return fmt.Errorf("missing required top-level key %q", "kind")
	}
	var kind string
	if err := json.Unmarshal(kindRaw, &kind); err != nil {
		return fmt.Errorf("kind must be a string")
	}
	var known map[string]bool
	required := []string{"kind", "package_format", "id", "run", "producer", "operator", "verification_custody", "evidence_coverage", "artifact_binding", "files", "verification_inputs", "spec", "checker", "artifact_evaluation", "conformance", "issued_at", "status_authority"}
	switch kind {
	case "evaluation-package":
		known = packageCommonKeys()
	case "verification-record":
		known = packageCommonKeys()
		known["verifier"] = true
		known["grades"] = true
		required = append(required, "verifier", "grades")
	default:
		return fmt.Errorf("kind %q must be evaluation-package or verification-record", kind)
	}
	if err := validateObjectSchema(raw, known, required); err != nil {
		return err
	}
	return validatePackageNestedSchema(raw, kind)
}

func packageCommonKeys() map[string]bool {
	return map[string]bool{
		"kind": true, "package_format": true, "id": true, "run": true,
		"producer": true, "operator": true, "verification_custody": true,
		"evidence_coverage": true, "artifact_binding": true, "files": true,
		"verification_inputs": true, "spec": true, "checker": true,
		"artifact_evaluation": true, "conformance": true, "issued_at": true,
		"expires_at": true, "status_authority": true,
	}
}

func validatePackageNestedSchema(raw []byte, kind string) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	if err := validateNestedObjectSchema(raw, "producer", map[string]bool{"id": true}, []string{"id"}); err != nil {
		return fmt.Errorf("producer: %w", err)
	}
	operatorKnown := map[string]bool{"id": true}
	operatorRequired := []string{"id"}
	if kind == "evaluation-package" {
		operatorKnown["key"] = true
		operatorRequired = append(operatorRequired, "key")
	}
	if err := validateNestedObjectSchema(raw, "operator", operatorKnown, operatorRequired); err != nil {
		return fmt.Errorf("operator: %w", err)
	}
	if kind == "verification-record" {
		if err := validateNestedObjectSchema(raw, "verifier", map[string]bool{
			"id": true, "key": true, "relationship_to_producer": true, "relationship_to_operator": true,
		}, []string{"id", "key", "relationship_to_producer", "relationship_to_operator"}); err != nil {
			return fmt.Errorf("verifier: %w", err)
		}
	}
	if err := validateNestedObjectSchema(raw, "verification_custody", map[string]bool{
		"acquisition": true, "replay": true, "review": true, "issuance": true,
	}, []string{"acquisition", "replay", "review", "issuance"}); err != nil {
		return fmt.Errorf("verification_custody: %w", err)
	}
	if err := validateNestedObjectSchema(raw, "evidence_coverage", map[string]bool{"scope": true, "disclosure": true}, []string{"scope", "disclosure"}); err != nil {
		return fmt.Errorf("evidence_coverage: %w", err)
	}
	if err := validateNestedObjectSchema(raw, "artifact_binding", map[string]bool{
		"root": true, "keys_dir": true, "manifest": true, "discovered_runs": true,
	}, []string{"root", "keys_dir", "manifest", "discovered_runs"}); err != nil {
		return fmt.Errorf("artifact_binding: %w", err)
	}
	var binding struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if err := json.Unmarshal(root["artifact_binding"], &binding); err != nil {
		return err
	}
	if err := validatePackageBlobSchema(binding.Manifest); err != nil {
		return fmt.Errorf("artifact_binding.manifest: %w", err)
	}
	for _, field := range []string{"files", "verification_inputs"} {
		var items []json.RawMessage
		if err := json.Unmarshal(root[field], &items); err != nil {
			return fmt.Errorf("%s must be an array: %w", field, err)
		}
		for i, item := range items {
			if err := validatePackageBlobSchema(item); err != nil {
				return fmt.Errorf("%s[%d]: %w", field, i, err)
			}
		}
	}
	if err := validateNestedObjectSchema(raw, "spec", map[string]bool{"version": true, "digest_algorithm": true, "digest": true}, []string{"version", "digest_algorithm", "digest"}); err != nil {
		return fmt.Errorf("spec: %w", err)
	}
	if err := validateNestedObjectSchema(raw, "checker", map[string]bool{"name": true, "source_revision": true, "executable": true}, []string{"name", "source_revision", "executable"}); err != nil {
		return fmt.Errorf("checker: %w", err)
	}
	var checker struct {
		Executable json.RawMessage `json:"executable"`
	}
	if err := json.Unmarshal(root["checker"], &checker); err != nil {
		return err
	}
	if err := validatePackageBlobSchema(checker.Executable); err != nil {
		return fmt.Errorf("checker.executable: %w", err)
	}
	if err := validateNestedObjectSchema(raw, "artifact_evaluation", map[string]bool{"arguments": true, "exit_status": true, "machine_output": true, "stdout": true, "stderr": true}, []string{"arguments", "exit_status", "machine_output", "stdout", "stderr"}); err != nil {
		return fmt.Errorf("artifact_evaluation: %w", err)
	}
	var evaluation struct {
		Arguments     json.RawMessage `json:"arguments"`
		ExitStatus    json.RawMessage `json:"exit_status"`
		MachineOutput json.RawMessage `json:"machine_output"`
		Stdout        json.RawMessage `json:"stdout"`
		Stderr        json.RawMessage `json:"stderr"`
	}
	if err := json.Unmarshal(root["artifact_evaluation"], &evaluation); err != nil {
		return err
	}
	if err := validateStringArraySchema(evaluation.Arguments, "artifact_evaluation.arguments"); err != nil {
		return err
	}
	if err := validateNonNegativeIntegerSchema(evaluation.ExitStatus, "artifact_evaluation.exit_status"); err != nil {
		return err
	}
	for name, value := range map[string]json.RawMessage{"machine_output": evaluation.MachineOutput, "stdout": evaluation.Stdout, "stderr": evaluation.Stderr} {
		if err := validatePackageBlobSchema(value); err != nil {
			return fmt.Errorf("artifact_evaluation.%s: %w", name, err)
		}
	}
	if err := validateNestedObjectSchema(raw, "conformance", map[string]bool{"corpus": true, "command": true, "exit_status": true, "result": true}, []string{"corpus", "command", "exit_status", "result"}); err != nil {
		return fmt.Errorf("conformance: %w", err)
	}
	var conformance struct {
		Corpus     json.RawMessage `json:"corpus"`
		Command    json.RawMessage `json:"command"`
		ExitStatus json.RawMessage `json:"exit_status"`
		Result     json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(root["conformance"], &conformance); err != nil {
		return err
	}
	if err := validateStringArraySchema(conformance.Command, "conformance.command"); err != nil {
		return err
	}
	if err := validateNonNegativeIntegerSchema(conformance.ExitStatus, "conformance.exit_status"); err != nil {
		return err
	}
	if err := validateObjectSchema(conformance.Corpus, map[string]bool{"version": true, "digest_algorithm": true, "digest": true}, []string{"version", "digest_algorithm", "digest"}); err != nil {
		return fmt.Errorf("conformance.corpus: %w", err)
	}
	if err := validatePackageBlobSchema(conformance.Result); err != nil {
		return fmt.Errorf("conformance.result: %w", err)
	}
	if err := validateNestedObjectSchema(raw, "status_authority", map[string]bool{"id": true, "key": true, "record_id": true, "url": true}, []string{"id", "key", "record_id"}); err != nil {
		return fmt.Errorf("status_authority: %w", err)
	}
	if kind == "verification-record" {
		var grades []json.RawMessage
		if err := json.Unmarshal(root["grades"], &grades); err != nil {
			return fmt.Errorf("grades must be an array: %w", err)
		}
		for i, grade := range grades {
			if err := validatePackageGradeSchema(grade); err != nil {
				return fmt.Errorf("grades[%d]: %w", i, err)
			}
		}
	}
	return nil
}

func validatePackageBlobSchema(raw []byte) error {
	if err := validateObjectSchema(raw, map[string]bool{
		"path": true, "size": true, "digest_algorithm": true, "digest": true, "url": true,
	}, []string{"path", "size", "digest_algorithm", "digest"}); err != nil {
		return err
	}
	var blob struct {
		Size json.RawMessage `json:"size"`
	}
	if err := json.Unmarshal(raw, &blob); err != nil {
		return err
	}
	return validateNonNegativeIntegerSchema(blob.Size, "size")
}

func validateStringArraySchema(raw json.RawMessage, field string) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s must be an array: %w", field, err)
	}
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s must be an array", field)
	}
	for i, item := range items {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("%s[%d] must be a string", field, i)
		}
	}
	return nil
}

func validateNonNegativeIntegerSchema(raw json.RawMessage, field string) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("%s must be a non-negative integer: %w", field, err)
	}
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("%s must be a non-negative integer", field)
	}
	integer, err := number.Int64()
	if err != nil || integer < 0 {
		return fmt.Errorf("%s must be a non-negative integer", field)
	}
	return nil
}

func validatePackageGradeSchema(raw []byte) error {
	if err := validateObjectSchema(raw, map[string]bool{"run": true, "line": true, "annotations": true, "outcomes": true}, []string{"run", "line", "annotations", "outcomes"}); err != nil {
		return err
	}
	var grade struct {
		Annotations json.RawMessage `json:"annotations"`
	}
	if err := json.Unmarshal(raw, &grade); err != nil {
		return err
	}
	return validateObjectSchema(grade.Annotations, map[string]bool{"coverage": true, "custody": true, "anchor": true, "retention": true}, []string{"coverage", "custody", "anchor", "retention"})
}

func validatePackageSemantics(manifest *PackageManifest) error {
	if manifest.PackageFormat != 1 || !packageTextPresent(manifest.ID, manifest.Run) {
		return fmt.Errorf("package format, id, and run must be present")
	}
	if !packageTextPresent(manifest.Producer.ID, manifest.Operator.ID) {
		return fmt.Errorf("producer and operator identities must be present")
	}
	if manifest.Kind == "evaluation-package" && !isSHA256(manifest.Operator.Key) {
		return fmt.Errorf("evaluation package operator must identify a sha-256 public key")
	}
	if manifest.Kind == "verification-record" {
		if manifest.Verifier == nil || !packageTextPresent(manifest.Verifier.ID, manifest.Verifier.Key) {
			return fmt.Errorf("verification record requires verifier identity and key")
		}
		if !packageTextPresent(manifest.Verifier.RelationshipToProducer, manifest.Verifier.RelationshipToOperator) {
			return fmt.Errorf("verifier relationships must be present")
		}
		if !isSHA256(manifest.Verifier.Key) {
			return fmt.Errorf("verification record verifier must identify a sha-256 public key")
		}
		if manifest.Verifier.ID == manifest.Producer.ID {
			return fmt.Errorf("verifier must not equal producer")
		}
		if manifest.Verifier.ID == manifest.Operator.ID {
			return fmt.Errorf("verifier must not equal operator")
		}
	} else if len(manifest.Grades) != 0 {
		return fmt.Errorf("evaluation package must not carry grades")
	}
	if !packageTextPresent(manifest.VerificationCustody.Acquisition, manifest.VerificationCustody.Replay, manifest.VerificationCustody.Review, manifest.VerificationCustody.Issuance) {
		return fmt.Errorf("verification custody fields must be present")
	}
	if !packageTextPresent(manifest.EvidenceCoverage.Scope, manifest.EvidenceCoverage.Disclosure) {
		return fmt.Errorf("evidence coverage fields must be present")
	}
	if manifest.ArtifactEvaluation.ExitStatus < 0 {
		return fmt.Errorf("artifact evaluation exit status must be non-negative")
	}
	if manifest.Conformance.ExitStatus < 0 {
		return fmt.Errorf("conformance exit status must be non-negative")
	}
	if len(manifest.Conformance.Command) == 0 {
		return fmt.Errorf("conformance command must not be empty")
	}
	if err := validateRFC3339("issued_at", manifest.IssuedAt); err != nil {
		return err
	}
	if manifest.ExpiresAt != "" {
		if err := validateRFC3339("expires_at", manifest.ExpiresAt); err != nil {
			return err
		}
	}
	if err := validatePackagePath(manifest.ArtifactBinding.Root); err != nil {
		return fmt.Errorf("artifact root: %w", err)
	}
	if err := validatePackagePath(manifest.ArtifactBinding.KeysDir); err != nil {
		return fmt.Errorf("artifact keys_dir: %w", err)
	}
	if len(manifest.ArtifactBinding.DiscoveredRuns) == 0 {
		return fmt.Errorf("artifact binding must list discovered runs")
	}
	for _, run := range manifest.ArtifactBinding.DiscoveredRuns {
		if !packageTextPresent(run) {
			return fmt.Errorf("artifact binding has an empty discovered run")
		}
	}
	if err := validateBlobShape("artifact manifest", manifest.ArtifactBinding.Manifest); err != nil {
		return err
	}
	if err := validateVersionedSum("spec", manifest.Spec); err != nil {
		return err
	}
	if err := validateVersionedSum("conformance corpus", manifest.Conformance.Corpus); err != nil {
		return err
	}
	if !packageTextPresent(manifest.Checker.Name, manifest.Checker.SourceRevision) {
		return fmt.Errorf("checker name and source revision must be present")
	}
	for _, ref := range []struct {
		name string
		blob PackageBlob
	}{
		{"checker executable", manifest.Checker.Executable},
		{"artifact evaluation machine output", manifest.ArtifactEvaluation.MachineOutput},
		{"artifact evaluation stdout", manifest.ArtifactEvaluation.Stdout},
		{"artifact evaluation stderr", manifest.ArtifactEvaluation.Stderr},
		{"conformance result", manifest.Conformance.Result},
	} {
		if err := validateBlobShape(ref.name, ref.blob); err != nil {
			return err
		}
	}
	if !packageTextPresent(manifest.StatusAuthority.ID, manifest.StatusAuthority.RecordID) || !isSHA256(manifest.StatusAuthority.Key) || manifest.StatusAuthority.RecordID != manifest.ID {
		return fmt.Errorf("status authority must identify this record and its key")
	}
	if manifest.Kind == "verification-record" {
		if err := validatePackageGrades(manifest); err != nil {
			return err
		}
	}
	return nil
}

type packageMachineRun struct {
	Grade      json.RawMessage    `json:"grade"`
	Run        string             `json:"run"`
	R          string             `json:"r"`
	Checks     map[string]Outcome `json:"checks"`
	Coverage   string             `json:"coverage"`
	Custody    string             `json:"custody"`
	Anchor     string             `json:"anchor"`
	Retention  string             `json:"retention"`
	Open       bool               `json:"open"`
	OpenStatus string             `json:"open_status,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
}

func validatePackageGradesAgainstMachineOutput(root string, manifest *PackageManifest) error {
	machineOutputPath, err := safePackagePath(root, manifest.ArtifactEvaluation.MachineOutput.Path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(machineOutputPath)
	if err != nil {
		return fmt.Errorf("read artifact evaluation machine output: %w", err)
	}
	var machineReport struct {
		Runs []packageMachineRun `json:"runs"`
	}
	if err := json.Unmarshal(raw, &machineReport); err != nil {
		return fmt.Errorf("artifact evaluation machine output is invalid: %w", err)
	}
	if len(machineReport.Runs) != len(manifest.Grades) {
		return fmt.Errorf("verification record grades disagree with artifact evaluation machine output")
	}

	results := make(map[string]Result, len(machineReport.Runs))
	for _, machineRun := range machineReport.Runs {
		result, err := packageMachineResult(machineRun)
		if err != nil {
			return err
		}
		if _, exists := results[result.Run]; exists || !packageTextPresent(result.Run) {
			return fmt.Errorf("artifact evaluation machine output has invalid run identities")
		}
		results[result.Run] = result
	}
	for _, grade := range manifest.Grades {
		result, ok := results[grade.Run]
		if !ok || grade.Line != result.GradeLine() || grade.Annotations.Coverage != result.Coverage || grade.Annotations.Custody != result.Custody || grade.Annotations.Anchor != result.Anchor || grade.Annotations.Retention != result.Retention || !samePackageOutcomes(grade.Outcomes, result.Checks) {
			return fmt.Errorf("verification record grade %q disagrees with artifact evaluation machine output", grade.Run)
		}
	}
	return nil
}

func packageMachineResult(machineRun packageMachineRun) (Result, error) {
	result := Result{
		Run:        machineRun.Run,
		R:          machineRun.R,
		Checks:     machineRun.Checks,
		Coverage:   machineRun.Coverage,
		Custody:    machineRun.Custody,
		Anchor:     machineRun.Anchor,
		Retention:  machineRun.Retention,
		Open:       machineRun.Open,
		OpenStatus: machineRun.OpenStatus,
		Notes:      machineRun.Notes,
	}
	decoder := json.NewDecoder(strings.NewReader(string(machineRun.Grade)))
	decoder.UseNumber()
	var grade any
	if err := decoder.Decode(&grade); err != nil {
		return Result{}, fmt.Errorf("artifact evaluation machine output has invalid grade for run %q", machineRun.Run)
	}
	switch value := grade.(type) {
	case json.Number:
		parsed, err := value.Int64()
		if err != nil || parsed < 0 || parsed > 4 {
			return Result{}, fmt.Errorf("artifact evaluation machine output has invalid grade for run %q", machineRun.Run)
		}
		result.Grade = int(parsed)
		return result, nil
	case string:
		if value == "ungraded" {
			result.Ungraded = true
			return result, nil
		}
	}
	return Result{}, fmt.Errorf("artifact evaluation machine output has invalid grade for run %q", machineRun.Run)
}

func samePackageOutcomes(grades map[string]OutcomeStatus, checks map[string]Outcome) bool {
	if len(grades) != len(checks) {
		return false
	}
	for id, check := range checks {
		if grades[id] != check.Status {
			return false
		}
	}
	return true
}

func packageTextPresent(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func validatePackageGrades(manifest *PackageManifest) error {
	seen := map[string]bool{}
	for _, grade := range manifest.Grades {
		if !packageTextPresent(grade.Run, grade.Line) || seen[grade.Run] {
			return fmt.Errorf("grades must have one non-empty entry for each run")
		}
		seen[grade.Run] = true
		if !packageTextPresent(grade.Annotations.Coverage, grade.Annotations.Custody, grade.Annotations.Anchor, grade.Annotations.Retention) {
			return fmt.Errorf("grade %q is missing required annotations", grade.Run)
		}
		if len(grade.Outcomes) == 0 {
			return fmt.Errorf("grade %q is missing PASS / FAIL / UV outcomes", grade.Run)
		}
		for id, outcome := range grade.Outcomes {
			if !packageTextPresent(id) || (outcome != Pass && outcome != Fail && outcome != UV) {
				return fmt.Errorf("grade %q has invalid outcome", grade.Run)
			}
		}
	}
	return nil
}

func validateRFC3339(name, value string) error {
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func validateVersionedSum(name string, sum PackageVersionedSum) error {
	if !packageTextPresent(sum.Version) || sum.DigestAlgorithm != "sha-256" || !isSHA256(sum.Digest) {
		return fmt.Errorf("%s must carry a versioned sha-256 digest", name)
	}
	return nil
}

func validateBlobShape(name string, blob PackageBlob) error {
	if err := validatePackagePath(blob.Path); err != nil {
		return fmt.Errorf("%s path: %w", name, err)
	}
	if blob.Size < 0 || blob.DigestAlgorithm != "sha-256" || !isSHA256(blob.Digest) {
		return fmt.Errorf("%s must carry size and sha-256 digest", name)
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func validatePackageBlobs(root string, manifest *PackageManifest) error {
	declared := map[string]PackageBlob{}
	for _, blob := range manifest.Files {
		name, err := normalizedPackageBlobPath("file manifest entry", blob)
		if err != nil {
			return err
		}
		if _, exists := declared[name]; exists {
			return fmt.Errorf("file manifest lists %q more than once", name)
		}
		declared[name] = blob
	}
	verificationInputs := map[string]bool{}
	for _, blob := range manifest.VerificationInputs {
		name, err := normalizedPackageBlobPath("verification input", blob)
		if err != nil {
			return err
		}
		if verificationInputs[name] {
			return fmt.Errorf("verification inputs list %q more than once", name)
		}
		verificationInputs[name] = true
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("verification input %q is absent from file manifest", name)
		}
	}
	for _, ref := range packageRequiredBlobs(manifest) {
		file, ok := declared[ref.Path]
		if !ok {
			return fmt.Errorf("required blob %q is absent from file manifest", ref.Path)
		}
		if file.Size != ref.Size || file.DigestAlgorithm != ref.DigestAlgorithm || file.Digest != ref.Digest {
			return fmt.Errorf("required blob %q does not match file manifest", ref.Path)
		}
	}

	actual := map[string]bool{}
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("package contains symlink %q", filepath.ToSlash(rel))
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("package contains non-regular file %q", filepath.ToSlash(rel))
		}
		name := filepath.ToSlash(rel)
		if name == packageManifestName || name == packageSignatureName {
			return nil
		}
		actual[name] = true
		blob, ok := declared[name]
		if !ok {
			return fmt.Errorf("package file %q is absent from file manifest", name)
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != blob.Size || hex.EncodeToString(sum[:]) != blob.Digest {
			return fmt.Errorf("blob %q size or digest mismatch", name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for name := range declared {
		if !actual[name] {
			return fmt.Errorf("required blob %q is missing", name)
		}
	}
	return nil
}

func normalizedPackageBlobPath(name string, blob PackageBlob) (string, error) {
	if err := validateBlobShape(name, blob); err != nil {
		return "", err
	}
	return path.Clean(blob.Path), nil
}

func packageRequiredBlobs(manifest *PackageManifest) []PackageBlob {
	return []PackageBlob{
		manifest.ArtifactBinding.Manifest,
		manifest.Checker.Executable,
		manifest.ArtifactEvaluation.MachineOutput,
		manifest.ArtifactEvaluation.Stdout,
		manifest.ArtifactEvaluation.Stderr,
		manifest.Conformance.Result,
	}
}

func validatePackageInputKeys(root string, manifest *PackageManifest) error {
	declared := map[string]bool{}
	for _, blob := range manifest.VerificationInputs {
		declared[blob.Path] = true
	}
	keysDir, err := safePackagePath(root, manifest.ArtifactBinding.KeysDir)
	if err != nil {
		return err
	}
	err = filepath.WalkDir(keysDir, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if !declared[name] {
			return fmt.Errorf("artifact verification key %q is absent from verification inputs", name)
		}
		return nil
	})
	if err != nil {
		return err
	}

	keys := map[string]bool{}
	for _, blob := range manifest.VerificationInputs {
		file, err := safePackagePath(root, blob.Path)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			continue
		}
		if base64.StdEncoding.EncodeToString(decoded) != strings.TrimSpace(string(raw)) {
			continue
		}
		sum := sha256.Sum256(decoded)
		keys[hex.EncodeToString(sum[:])] = true
	}
	for _, fingerprint := range []string{packageSignerKey(manifest), manifest.StatusAuthority.Key} {
		if !keys[strings.ToLower(fingerprint)] {
			return fmt.Errorf("package signer public key is absent from verification inputs")
		}
	}
	return nil
}

func validateArtifactBinding(root string, manifest *PackageManifest) error {
	artifactRoot, err := safePackagePath(root, manifest.ArtifactBinding.Root)
	if err != nil {
		return err
	}
	keysDir, err := safePackagePath(root, manifest.ArtifactBinding.KeysDir)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(manifest.ArtifactBinding.Manifest.Path, manifest.ArtifactBinding.Root+"/") {
		return fmt.Errorf("artifact manifest must be inside artifact root")
	}
	if !strings.HasSuffix(manifest.ArtifactBinding.Manifest.Path, "/manifest.json") {
		return fmt.Errorf("artifact manifest must name manifest.json")
	}
	art, err := LoadArtifact(artifactRoot, keysDir)
	if err != nil {
		return fmt.Errorf("load bound artifact: %w", err)
	}
	runs := discoveredPackageRuns(Evaluate(art))
	if !sameStringSet(runs, manifest.ArtifactBinding.DiscoveredRuns) {
		return fmt.Errorf("artifact binding discovered runs %v do not match submitted runs %v", runs, manifest.ArtifactBinding.DiscoveredRuns)
	}
	if !containsString(runs, manifest.Run) {
		return fmt.Errorf("package run %q is not in discovered runs", manifest.Run)
	}
	if manifest.Kind == "verification-record" {
		gradeRuns := make([]string, 0, len(manifest.Grades))
		for _, grade := range manifest.Grades {
			gradeRuns = append(gradeRuns, grade.Run)
		}
		if !sameStringSet(runs, gradeRuns) {
			return fmt.Errorf("verification record grades do not cover every discovered run")
		}
	}
	return nil
}

func discoveredPackageRuns(report Report) []string {
	runs := make([]string, 0, len(report.Runs))
	for _, result := range report.Runs {
		if result.Run != "" {
			runs = append(runs, result.Run)
		}
	}
	sort.Strings(runs)
	return runs
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func validateVerificationStatus(manifest *PackageManifest, statusPath, signaturePath string, keys map[string]ed25519.PublicKey) (VerificationStatus, error) {
	raw, err := os.ReadFile(statusPath)
	if err != nil {
		return VerificationStatus{}, fmt.Errorf("read verification status: %w", err)
	}
	if !IsCanonical(raw) {
		return VerificationStatus{}, fmt.Errorf("verification status is not canonical")
	}
	if err := validateVerificationStatusSchema(raw); err != nil {
		return VerificationStatus{}, fmt.Errorf("verification status schema: %w", err)
	}
	var status VerificationStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return VerificationStatus{}, err
	}
	if status.RecordID != manifest.ID || status.Authority != manifest.StatusAuthority.ID {
		return VerificationStatus{}, fmt.Errorf("verification status does not bind this record and authority")
	}
	pub, ok := keys[strings.ToLower(manifest.StatusAuthority.Key)]
	if !ok {
		return VerificationStatus{}, untrustedPackageError("missing trusted status authority key %s", manifest.StatusAuthority.Key)
	}
	sigRaw, err := os.ReadFile(signaturePath)
	if err != nil {
		return VerificationStatus{}, fmt.Errorf("read verification status signature: %w", err)
	}
	sig, err := decodeStdBase64Field("status signature", strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return VerificationStatus{}, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, raw, sig) {
		return VerificationStatus{}, fmt.Errorf("verification status signature verification failed")
	}
	return status, nil
}

func validateVerificationStatusSchema(raw []byte) error {
	if err := validateObjectSchema(raw, map[string]bool{
		"status_format": true, "record_id": true, "authority": true, "issued_at": true,
		"next_update": true, "effective_at": true, "state": true, "reason": true,
		"replacement": true,
	}, []string{"status_format", "record_id", "authority", "issued_at", "state"}); err != nil {
		return err
	}
	var status VerificationStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return err
	}
	if status.StatusFormat != 1 {
		return fmt.Errorf("status_format must be 1")
	}
	if err := validateRFC3339("status issued_at", status.IssuedAt); err != nil {
		return err
	}
	issued, err := time.Parse(time.RFC3339, status.IssuedAt)
	if err != nil {
		return fmt.Errorf("status issued_at: %w", err)
	}
	switch status.State {
	case "current":
		if !packageTextPresent(status.NextUpdate) {
			return fmt.Errorf("current status requires next_update")
		}
		if err := validateRFC3339("status next_update", status.NextUpdate); err != nil {
			return err
		}
		nextUpdate, err := time.Parse(time.RFC3339, status.NextUpdate)
		if err != nil {
			return fmt.Errorf("status next_update: %w", err)
		}
		if !nextUpdate.After(issued) {
			return fmt.Errorf("current status next_update must be later than issued_at")
		}
	case "revoked":
		if !packageTextPresent(status.Reason, status.EffectiveAt) {
			return fmt.Errorf("revoked status requires reason and effective_at")
		}
		if err := validateRFC3339("status effective_at", status.EffectiveAt); err != nil {
			return err
		}
	case "superseded":
		if !packageTextPresent(status.Reason, status.Replacement, status.EffectiveAt) {
			return fmt.Errorf("superseded status requires reason, replacement, and effective_at")
		}
		if err := validateRFC3339("status effective_at", status.EffectiveAt); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid status state %q", status.State)
	}
	return nil
}

func validatePackagePath(value string) error {
	if value == "" || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return fmt.Errorf("must be a normalized relative path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("must be a normalized relative path")
		}
	}
	return nil
}

func safePackagePath(root, rel string) (string, error) {
	if err := validatePackagePath(rel); err != nil {
		return "", fmt.Errorf("unsafe package path %q: %w", rel, err)
	}
	return filepath.Join(root, filepath.FromSlash(rel)), nil
}
