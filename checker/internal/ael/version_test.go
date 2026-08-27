// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

func TestPublishedVersionsMatchCode(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate version test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))

	spec := readVersionFile(t, filepath.Join(root, "SPEC.md"))
	assertVersionMatch(t, spec, `(?m)^Version ([0-9]+\.[0-9]+) `, SpecificationVersion, "SPEC.md header")

	formatDoc := readVersionFile(t, filepath.Join(root, "docs", "ARTIFACT-FORMAT.md"))
	assertVersionMatch(t, formatDoc, `(?m)^# AEL artifact format v([0-9]+\.[0-9]+)$`, SpecificationVersion, "artifact format heading")
	assertFormatMatch(t, formatDoc, `"ael_format": ([0-9]+)`, ArtifactFormatVersion, "artifact format example")

	manifestSchema := readVersionFile(t, filepath.Join(root, "schema", "manifest.schema.json"))
	assertVersionMatch(t, manifestSchema, `"title": "AEL manifest \(v([0-9]+\.[0-9]+)\)"`, SpecificationVersion, "manifest schema title")
	var schema struct {
		Properties struct {
			AELFormat struct {
				Const int `json:"const"`
			} `json:"ael_format"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(manifestSchema), &schema); err != nil {
		t.Fatalf("parse manifest schema: %v", err)
	}
	if schema.Properties.AELFormat.Const != ArtifactFormatVersion {
		t.Fatalf("manifest schema ael_format = %d, want %d", schema.Properties.AELFormat.Const, ArtifactFormatVersion)
	}
}

func TestAELV01SchemaCanonicalIDs(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate version test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))

	for filename, want := range map[string]string{
		"evaluation-package.schema.json":  "https://pipelab.org/schemas/ael/v0.1/evaluation-package.schema.json",
		"manifest.schema.json":            "https://pipelab.org/schemas/ael/v0.1/manifest.schema.json",
		"record-payload.schema.json":      "https://pipelab.org/schemas/ael/v0.1/record-payload.schema.json",
		"verification-record.schema.json": "https://pipelab.org/schemas/ael/v0.1/verification-record.schema.json",
		"verification-status.schema.json": "https://pipelab.org/schemas/ael/v0.1/verification-status.schema.json",
	} {
		t.Run(filename, func(t *testing.T) {
			var schema struct {
				ID string `json:"$id"`
			}
			if err := json.Unmarshal([]byte(readVersionFile(t, filepath.Join(root, "schema", filename))), &schema); err != nil {
				t.Fatalf("parse schema: %v", err)
			}
			if schema.ID != want {
				t.Fatalf("schema $id = %q, want %q", schema.ID, want)
			}
		})
	}
}

func TestManifestSchemaConstrainsArtifactPaths(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate version test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	var schema map[string]any
	if err := json.Unmarshal([]byte(readVersionFile(t, filepath.Join(root, "schema", "manifest.schema.json"))), &schema); err != nil {
		t.Fatalf("parse manifest schema: %v", err)
	}
	properties := schema["properties"].(map[string]any)
	paths := []map[string]any{
		properties["recorders"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["file"].(map[string]any),
		properties["anchor"].(map[string]any)["properties"].(map[string]any)["file"].(map[string]any),
		properties["counterparty"].(map[string]any)["properties"].(map[string]any)["file"].(map[string]any),
	}
	for _, field := range paths {
		if field["$ref"] != "#/$defs/relativePath" {
			t.Fatalf("manifest path schema = %#v, want relativePath reference", field)
		}
	}
}

func readVersionFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertVersionMatch(t *testing.T, content, pattern, want, source string) {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(content)
	if len(match) != 2 {
		t.Fatalf("%s does not declare a version", source)
	}
	if match[1] != want {
		t.Fatalf("%s version = %q, want %q", source, match[1], want)
	}
}

func assertFormatMatch(t *testing.T, content, pattern string, want int, source string) {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(content)
	if len(match) != 2 {
		t.Fatalf("%s does not declare an artifact format", source)
	}
	got, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("parse %s artifact format: %v", source, err)
	}
	if got != want {
		t.Fatalf("%s artifact format = %d, want %d", source, got, want)
	}
}
