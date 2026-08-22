// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// runEmit builds a signed evaluation package from a real checker run.
//
// Custody and coverage arrive as flags with no defaults because they are
// declarations the operator makes and then signs. Hardcoding them had the
// command assert things on the operator's behalf, including a disclosure claim
// no command can observe. validateEmitOptions refuses them empty, so a missing
// declaration stops the emit rather than being filled in.
//
// There is no --kind flag. A verification record must be signed by a verifier
// the validator rejects when their identity matches the producer or operator,
// and the party running this command is the operator, so the only record this
// command could produce is one that can never validate. Offering the choice
// would advertise a path that always fails.
func runEmit(arguments []string) int {
	flags := flag.NewFlagSet("emit", flag.ContinueOnError)
	artifact := flags.String("artifact", "", "artifact directory to evaluate")
	artifactKeys := flags.String("artifact-keys", "", "directory of published artifact keys")
	checker := flags.String("checker", "", "checker executable to run and digest")
	checkerName := flags.String("checker-name", "aelcheck", "name recorded for the checker")
	sourceRevision := flags.String("source-revision", "", "source revision of the checker")
	operatorKey := flags.String("operator-key", "", "operator ed25519 private key file")
	operatorID := flags.String("operator-id", "", "operator identity")
	producerID := flags.String("producer-id", "", "producer identity")
	statusAuthorityID := flags.String("status-authority-id", "", "status authority identity")
	statusKey := flags.String("status-key", "", "status authority ed25519 public key file")
	specPath := flags.String("spec", "", "specification file to digest")
	specVersion := flags.String("spec-version", "", "specification version")
	corpusDigestSource := flags.String("corpus-digest-source", "", "file whose digest identifies the conformance corpus")
	corpusVersion := flags.String("corpus-version", "", "conformance corpus version")
	conformanceResult := flags.String("conformance-result", "", "result file from the conformance run")
	conformanceCommand := flags.String("conformance-command", "", "conformance command, space separated")
	conformanceExit := flags.Int("conformance-exit", 0, "exit status of the conformance run")
	custodyAcquisition := flags.String("custody-acquisition", "", "operator declaration: how the artifact was acquired")
	custodyReplay := flags.String("custody-replay", "", "operator declaration: replay availability")
	custodyReview := flags.String("custody-review", "", "operator declaration: review performed")
	custodyIssuance := flags.String("custody-issuance", "", "operator declaration: issuance basis")
	coverageScope := flags.String("coverage-scope", "", "operator declaration: evidence scope")
	coverageDisclosure := flags.String("coverage-disclosure", "", "operator declaration: disclosure completeness")
	packageID := flags.String("id", "", "package identifier")
	run := flags.String("run", "", "run to package; default is the first discovered run")
	issuedAt := flags.String("issued-at", "", "RFC3339 issue time; default is now")
	out := flags.String("out", "", "output package directory, which must not already exist or must be empty")
	jsonOut := flags.Bool("json", false, "print the machine-readable emit result")

	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "aelpackage emit: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	operatorPrivate, err := readPrivateKey(*operatorKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage emit: %v\n", err)
		return 2
	}
	statusPublic, err := readPublicKey(*statusKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage emit: %v\n", err)
		return 2
	}

	issued := time.Now().UTC()
	if *issuedAt != "" {
		parsed, err := time.Parse(time.RFC3339, *issuedAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aelpackage emit: --issued-at: %v\n", err)
			return 2
		}
		issued = parsed
	}

	command := strings.Fields(*conformanceCommand)

	result, err := ael.EmitEvaluationPackage(ael.EmitOptions{
		ArtifactDir:       *artifact,
		ArtifactKeysDir:   *artifactKeys,
		CheckerPath:       *checker,
		CheckerName:       *checkerName,
		SourceRevision:    *sourceRevision,
		PackageID:         *packageID,
		ProducerID:        *producerID,
		OperatorID:        *operatorID,
		OperatorKey:       operatorPrivate,
		StatusAuthorityID: *statusAuthorityID,
		StatusPublicKey:   statusPublic,
		Custody: ael.PackageCustody{
			Acquisition: *custodyAcquisition,
			Replay:      *custodyReplay,
			Review:      *custodyReview,
			Issuance:    *custodyIssuance,
		},
		Coverage: ael.PackageCoverage{
			Scope:      *coverageScope,
			Disclosure: *coverageDisclosure,
		},
		SpecVersion:           *specVersion,
		SpecPath:              *specPath,
		CorpusVersion:         *corpusVersion,
		CorpusDigestPath:      *corpusDigestSource,
		ConformanceCommand:    command,
		ConformanceResultPath: *conformanceResult,
		ConformanceExitStatus: *conformanceExit,
		Run:                   *run,
		IssuedAt:              issued,
		OutDir:                *out,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "aelpackage emit: %v\n", err)
		return 1
	}

	if *jsonOut {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			// The package is already published at this point. Returning 1 would
			// say no package exists, and a caller acting on that would retry an
			// emission that already completed.
			fmt.Fprintf(os.Stderr, "aelpackage emit: package published at %s but the result could not be reported: %v\n", result.PackageDir, err)
			return exitReportFailed
		}
	} else {
		fmt.Printf("evaluation-package %s: run %s, checker exit %d\n", result.PackageID, result.Run, result.ExitStatus)
	}

	// The emit succeeded. Whether the artifact conformed is a separate fact,
	// carried by the package's recorded exit status and reported here so a
	// caller reading only the status cannot mistake a packaged failure for a
	// clean result.
	if result.ExitStatus != 0 {
		return exitEmittedNonconforming
	}
	return 0
}

// exitEmittedNonconforming means the package was written and the artifact did
// not conform. It is distinct from 1, which means no package exists.
const exitEmittedNonconforming = 3

// exitReportFailed means the package was written and published but its result
// could not be reported. It is distinct from 1, which means no package exists,
// because the two call for opposite responses: one is safe to retry and the
// other would duplicate completed work.
const exitReportFailed = 4

// readPrivateKey loads an Ed25519 signing key. A signing key readable by other
// accounts is refused: the whole package rests on that key being the operator's
// alone, and silently signing with an exposed key would produce evidence whose
// authority is already gone.
func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--operator-key is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("operator key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("operator key %s is accessible to other accounts (mode %04o); run: chmod 600 %s", path, info.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("operator key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("operator key must be standard base64: %w", err)
	}
	switch len(decoded) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	default:
		return nil, fmt.Errorf("operator key must decode to %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(decoded))
	}
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("--status-key is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("status key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("status key must be standard base64: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("status key must decode to %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}
