// SPDX-License-Identifier: Apache-2.0

package ael

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadArtifactRejectsUnsafeRecorderPaths(t *testing.T) {
	for _, file := range []string{"/tmp/records.jsonl", "../records.jsonl", "recorders/../records.jsonl", "recorders//r1.jsonl", "recorders\\r1.jsonl", "."} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			raw := manifestForRecorderPathTest(t, file)
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil || !strings.Contains(err.Error(), "file must be a clean non-empty relative path") {
				t.Fatalf("LoadArtifact error = %v, want unsafe path rejection", err)
			}
		})
	}
}

func TestLoadRecorderLogDefendsAgainstSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	escape := filepath.Join(t.TempDir(), "records.jsonl")
	if err := os.WriteFile(escape, []byte("outside artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(escape), filepath.Join(dir, "recorders")); err != nil {
		t.Fatal(err)
	}
	f, err := openArtifactFile(dir, "recorders/records.jsonl")
	if f != nil {
		_ = f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "open artifact file") {
		t.Fatalf("openArtifactFile error = %v, want rooted-open symlink rejection", err)
	}
}

func TestLoadArtifactDefendsAgainstManifestSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	escape := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(escape, manifestForRecorderPathTest(t, "recorders/r1.jsonl"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escape, filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
	if err == nil || !strings.Contains(err.Error(), "read manifest: open artifact file") {
		t.Fatalf("LoadArtifact error = %v, want rooted-open manifest rejection", err)
	}
}

func TestLoadAnchorsRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAnchorBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	art := &Artifact{Dir: dir, Manifest: Manifest{Anchor: &AnchorDecl{File: "anchors.json"}}}
	art.loadAnchors()
	if art.AnchorsErr == nil || !strings.Contains(art.AnchorsErr.Error(), "maximum size") {
		t.Fatalf("AnchorsErr = %v, want anchor size rejection", art.AnchorsErr)
	}
}

func TestReadBoundedArtifactFileSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bounded.json")
	if err := os.WriteFile(path, []byte("1234"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := readBoundedArtifactFile(dir, "bounded.json", 4)
	if err != nil || string(raw) != "1234" {
		t.Fatalf("exact-limit read = %q, %v; want success", raw, err)
	}
	if _, err := readBoundedArtifactFile(dir, "bounded.json", 3); err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("over-limit read error = %v, want size rejection", err)
	}
}

func TestManifestResourceLimits(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "array items",
			mutate: func(v map[string]any) {
				items := make([]any, maxManifestArrayItems+1)
				for i := range items {
					items[i] = fmt.Sprintf("run-%d", i)
				}
				v["runs"] = items
			},
			want: "manifest array has more than",
		},
		{
			name: "string bytes",
			mutate: func(v map[string]any) {
				v["runs"] = []any{strings.Repeat("r", maxManifestStringBytes+1)}
			},
			want: "manifest string exceeds maximum size",
		},
		{
			name: "extension object members",
			mutate: func(v map[string]any) {
				ext := make(map[string]any, maxManifestObjectFields+1)
				for i := range maxManifestObjectFields + 1 {
					ext[fmt.Sprintf("field-%d", i)] = true
				}
				v["ext"] = ext
			},
			want: "manifest object has more than",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := validManifestForSchemaTests()
			tc.mutate(manifest)
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateManifestSchema(raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateManifestSchema error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadArtifactRejectsOversizedManifestBeforeDecode(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"ael_format":1,"ext":"` + strings.Repeat("x", maxManifestBytes) + `","recorders":[{"file":"recorders/r1.jsonl","id":"r1","run":"run-a"}],"runs":["run-a"]}`)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
	if err == nil || !strings.Contains(err.Error(), "maximum size") {
		t.Fatalf("LoadArtifact error = %v, want manifest size rejection", err)
	}
}

func TestDecisionInputMemberLimit(t *testing.T) {
	inputs := make(map[string]any, maxDecisionInputFields+1)
	for i := range maxDecisionInputFields + 1 {
		inputs[fmt.Sprintf("input-%d", i)] = true
	}
	raw, err := json.Marshal(map[string]any{
		"v": 1, "type": "activity", "run": "run-a", "recorder": "r1",
		"key": strings.Repeat("0", 64), "seq": 1, "prev": strings.Repeat("0", 64), "ts": "2026-01-01T00:00:00Z",
		"event":    map[string]any{"class": "net", "id": "event-1", "dir": "out"},
		"decision": map[string]any{"policy": strings.Repeat("0", 64), "request_fp": "request", "inputs": inputs, "verdict": "allow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRecordPayloadSchema(raw, "activity"); err == nil || !strings.Contains(err.Error(), "decision.inputs has more than") {
		t.Fatalf("validateRecordPayloadSchema error = %v, want decision input limit", err)
	}
}

func manifestForRecorderPathTest(t *testing.T, file string) []byte {
	t.Helper()
	manifest := validManifestForSchemaTests()
	manifest["recorders"].([]any)[0].(map[string]any)["file"] = file
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLoadArtifactRejectsUnsupportedAELFormat(t *testing.T) {
	for _, format := range []string{"0", "2"} {
		t.Run("ael_format "+format, func(t *testing.T) {
			dir := t.TempDir()
			raw := `{"ael_format":` + format + `,"recorders":[],"runs":["run-a"]}`
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil {
				t.Fatal("LoadArtifact accepted an unsupported ael_format")
			}
			if !strings.Contains(err.Error(), "unsupported ael_format "+format) {
				t.Fatalf("error %q does not name the unsupported format", err.Error())
			}
		})
	}
}

func TestLoadArtifactRejectsNonCanonicalManifest(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "whitespace",
			raw:  "{\n  \"ael_format\":1,\n  \"runs\":[\"run-a\"],\n  \"recorders\":[]\n}\n",
			want: "manifest.json is not canonical",
		},
		{
			name: "duplicate key",
			raw:  `{"ael_format":1,"recorders":[],"runs":["run-a"],"runs":["run-b"]}`,
			want: "duplicate object key",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tc.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil {
				t.Fatal("LoadArtifact accepted a non-canonical manifest")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadArtifactRejectsManifestNumericSchemaGaps(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "retained claimed rung below range",
			raw:  `{"ael_format":1,"claimed_rung":-1,"recorders":[{"file":"recorders/r1.jsonl","id":"r1","run":"run-a"}],"runs":["run-a"]}`,
			want: "claimed_rung must be an integer between 0 and 4",
		},
		{
			name: "retained claimed rung above range",
			raw:  `{"ael_format":1,"claimed_rung":5,"recorders":[{"file":"recorders/r1.jsonl","id":"r1","run":"run-a"}],"runs":["run-a"]}`,
			want: "claimed_rung must be an integer between 0 and 4",
		},
		{
			name: "negative declared retention",
			raw:  `{"ael_format":1,"recorders":[{"file":"recorders/r1.jsonl","id":"r1","run":"run-a"}],"retention":{"period_days":-1},"runs":["run-a"]}`,
			want: "retention: period_days must be an integer >= 0",
		},
		{
			name: "empty recorder set",
			raw:  `{"ael_format":1,"recorders":[],"runs":["run-a"]}`,
			want: "recorders must be a non-empty array",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tc.raw), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadArtifact error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestManifestSchemaParityConstraintFamilies(t *testing.T) {
	sha := "0000000000000000000000000000000000000000000000000000000000000000"
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "runs item must be string", mutate: func(v map[string]any) { v["runs"] = []any{1} }, want: "runs[0] must be a string"},
		{name: "runs item must not be null", mutate: func(v map[string]any) { v["runs"] = []any{nil} }, want: "runs[0] must be a string"},
		{name: "runs must be nonempty", mutate: func(v map[string]any) { v["runs"] = []any{} }, want: "runs must be a non-empty array"},
		{name: "recorder missing id", mutate: func(v map[string]any) { delete(v["recorders"].([]any)[0].(map[string]any), "id") }, want: "missing required top-level key \"id\""},
		{name: "recorder run must be string", mutate: func(v map[string]any) { v["recorders"].([]any)[0].(map[string]any)["run"] = nil }, want: "run must be a string"},
		{name: "recorder optional key must be string", mutate: func(v map[string]any) { v["recorders"].([]any)[0].(map[string]any)["key"] = 1 }, want: "key must be a string"},
		{name: "recorder file must stay relative", mutate: func(v map[string]any) { v["recorders"].([]any)[0].(map[string]any)["file"] = "../records.jsonl" }, want: "file must be a clean non-empty relative path"},
		{name: "coverage enum", mutate: func(v map[string]any) { v["coverage"] = "all" }, want: "coverage must be one of"},
		{name: "custody enum", mutate: func(v map[string]any) { v["custody"] = "somewhere" }, want: "custody must be one of"},
		{name: "retention must be object", mutate: func(v map[string]any) { v["retention"] = nil }, want: "retention must be an object"},
		{name: "retention period must not be null", mutate: func(v map[string]any) { v["retention"] = map[string]any{"period_days": nil} }, want: "retention: period_days must be an integer >= 0"},
		{name: "retention custody string", mutate: func(v map[string]any) { v["retention"] = map[string]any{"custody": false} }, want: "retention: custody must be a string"},
		{name: "correspondence must be object", mutate: func(v map[string]any) { v["correspondence"] = nil }, want: "correspondence must be an object"},
		{name: "correspondence requires match", mutate: func(v map[string]any) { v["correspondence"] = map[string]any{"classes": []any{"tool"}} }, want: "missing required top-level key \"match\""},
		{name: "correspondence class string", mutate: func(v map[string]any) { v["correspondence"] = map[string]any{"classes": []any{1}, "match": "id"} }, want: "classes[0] must be a string"},
		{name: "correspondence class must not be null", mutate: func(v map[string]any) { v["correspondence"] = map[string]any{"classes": []any{nil}, "match": "id"} }, want: "classes[0] must be a string"},
		{name: "correspondence match const", mutate: func(v map[string]any) { v["correspondence"] = map[string]any{"classes": []any{}, "match": "name"} }, want: "match must be one of id"},
		{name: "anchor must be object", mutate: func(v map[string]any) { v["anchor"] = nil }, want: "anchor must be an object"},
		{name: "anchor digest pattern", mutate: func(v map[string]any) {
			v["anchor"] = map[string]any{"log": "log", "log_key": "bad", "file": "anchors.json"}
		}, want: "log_key must be a lowercase sha-256 hex string"},
		{name: "anchor file must stay relative", mutate: func(v map[string]any) {
			v["anchor"] = map[string]any{"log": "log", "log_key": sha, "file": "../anchors.json"}
		}, want: "file must be a clean non-empty relative path"},
		{name: "counterparty must be object", mutate: func(v map[string]any) { v["counterparty"] = nil }, want: "counterparty must be an object"},
		{name: "counterparty requires file", mutate: func(v map[string]any) { v["counterparty"] = map[string]any{"flows": []any{}, "key": sha} }, want: "missing required top-level key \"file\""},
		{name: "counterparty flows strings", mutate: func(v map[string]any) {
			v["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{false}, "key": sha}
		}, want: "flows[0] must be a string"},
		{name: "counterparty flow must not be null", mutate: func(v map[string]any) {
			v["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{nil}, "key": sha}
		}, want: "flows[0] must be a string"},
		{name: "counterparty digest pattern", mutate: func(v map[string]any) {
			v["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{}, "key": "bad"}
		}, want: "key must be a lowercase sha-256 hex string"},
		{name: "counterparty file must stay relative", mutate: func(v map[string]any) {
			v["counterparty"] = map[string]any{"file": "../counterparty.jsonl", "flows": []any{}, "key": sha}
		}, want: "file must be a clean non-empty relative path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := validManifestForSchemaTests()
			tc.mutate(manifest)
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateManifestSchema(raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("schema error = %v, want %q", err, tc.want)
			}
		})
	}
}

func validManifestForSchemaTests() map[string]any {
	return map[string]any{
		"ael_format": 1,
		"runs":       []any{"run-a"},
		"recorders":  []any{map[string]any{"id": "r1", "run": "run-a", "file": "recorders/r1.jsonl"}},
	}
}

// These are literal canonical artifact bytes from an operator-shaped AEL-1
// control. Keep this independent of aelgen: a generator and its checker tests
// agreeing on their own output cannot prove that ordinary producer bytes load.
const handAuthoredManifest = `{"ael_format":1,"claimed_rung":1,"coverage":"declared-only","custody":"same-process","recorders":[{"file":"recorders/r1.jsonl","id":"r1","key":"edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066","run":"run-ael1-valid"}],"retention":{"custody":"fixture","period_days":30},"runs":["run-ael1-valid"]}`

const handAuthoredRecords = `eyJobWF4Ijo2MCwiaHRvbCI6NSwia2V5IjoiZWRlZTdlZjllMTkzNTU1MjhjZjAzOGRhY2U3MjA5NTMzN2VmNzZmZWViY2YyYWFkMWQyYzcxMTMwY2IwODA2NiIsInByZXYiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwicmVjb3JkZXIiOiJyMSIsInJ1biI6InJ1bi1hZWwxLXZhbGlkIiwic2VxIjowLCJ0cyI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwidHlwZSI6Im9wZW4iLCJ2IjoxfQ.wke1ciLUbRTd4SIyGicFXvIxZ6oahTnW5awSXmgG4NXPD4LebscIh8HsX2y-tzgJrtdnbaO1orRDLRRgtbliDg
eyJldmVudCI6eyJjbGFzcyI6Im5ldCIsImRpciI6Im91dCIsImlkIjoiZXZ0LTEifSwia2V5IjoiZWRlZTdlZjllMTkzNTU1MjhjZjAzOGRhY2U3MjA5NTMzN2VmNzZmZWViY2YyYWFkMWQyYzcxMTMwY2IwODA2NiIsInByZXYiOiI0ZWYxMjI4OGM0MGFjMDNlOWUyOTc5ODMyYjAyYjgwOGU0YjNmMTg4OTQ2OTUxMGUzMWMwZTQzNWEwYzQ0ZDc1IiwicmVjb3JkZXIiOiJyMSIsInJ1biI6InJ1bi1hZWwxLXZhbGlkIiwic2VxIjoxLCJ0cyI6IjIwMjYtMDEtMDFUMDA6MDA6MTBaIiwidHlwZSI6ImFjdGl2aXR5IiwidiI6MX0.P1j9p_VX0xIVOR4XlVi0S52NU07mwatXTcHgcMEc6s1ar7w7G_tKhcaktzcY7zF9scDo9lKFudBzkQdBj-EgBA
eyJldmVudCI6eyJjbGFzcyI6Im5ldCIsImRpciI6Im91dCIsImlkIjoiZXZ0LTIifSwia2V5IjoiZWRlZTdlZjllMTkzNTU1MjhjZjAzOGRhY2U3MjA5NTMzN2VmNzZmZWViY2YyYWFkMWQyYzcxMTMwY2IwODA2NiIsInByZXYiOiI5OWI0YTY5ZDExYzBhZWFmM2NhZmNkZGU2M2EzMTUwNjQ3ZjU1MWRhZDhiYTYwNzVlNWYyZWM4ZTFiNGVhZWUzIiwicmVjb3JkZXIiOiJyMSIsInJ1biI6InJ1bi1hZWwxLXZhbGlkIiwic2VxIjoyLCJ0cyI6IjIwMjYtMDEtMDFUMDA6MDA6MjBaIiwidHlwZSI6ImFjdGl2aXR5IiwidiI6MX0.1-3keZrS1shcPQ3XaEghl0uB6MPMkPrG1o5HWPo3eSZR7_QsZq382KGvqAVhzNnjydbgaMRfesljcXKVq1IADA
eyJrZXkiOiJlZGVlN2VmOWUxOTM1NTUyOGNmMDM4ZGFjZTcyMDk1MzM3ZWY3NmZlZWJjZjJhYWQxZDJjNzExMzBjYjA4MDY2IiwicHJldiI6IjI3NThiODU5ZjA2ZWFmMjQyNTYzZDRhYTZkM2Q1ZjNkMzkxOWM4Njg5ZTYzMmI2ODc1ZjMxMTg4ZmFjYzUwMDIiLCJyZWNvcmRlciI6InIxIiwicnVuIjoicnVuLWFlbDEtdmFsaWQiLCJzZXEiOjMsInRzIjoiMjAyNi0wMS0wMVQwMDowMDozMFoiLCJ0eXBlIjoiaGVhcnRiZWF0IiwidiI6MX0.Leqg5x58T1jF9l0yHqznuiVPH3xgzbnxfN9sV11AggI4vbgOc1qn76nkjs66AJCupnxquKt6xHNueLGZzbjVBw
eyJjb3VudCI6NSwiaGVhZCI6ImI5OWJiMjA4YjUwNmM5NzQ4NzYyZjIzYzBhNDc1MGU1ODIxNTNmZjM4NTIxNmI0ZGZiNjMwNWFiOTA5OWU2MjEiLCJrZXkiOiJlZGVlN2VmOWUxOTM1NTUyOGNmMDM4ZGFjZTcyMDk1MzM3ZWY3NmZlZWJjZjJhYWQxZDJjNzExMzBjYjA4MDY2IiwicHJldiI6ImI5OWJiMjA4YjUwNmM5NzQ4NzYyZjIzYzBhNDc1MGU1ODIxNTNmZjM4NTIxNmI0ZGZiNjMwNWFiOTA5OWU2MjEiLCJyZWNvcmRlciI6InIxIiwicnVuIjoicnVuLWFlbDEtdmFsaWQiLCJzZXEiOjQsInRzIjoiMjAyNi0wMS0wMVQwMDowMDo0MFoiLCJ0eXBlIjoiY2xvc2UiLCJ2IjoxfQ.gTthOvblwGaS9Cl-z6mH8cI7oluydjXWZbJhIawfdnVKzMGdF4HL3BrXv0c-_hD2B1SFKTNcnwO_jBCuU8ToDA
`

const handAuthoredPublicKey = "ye3LEiI6/kU6QfwwozxpONhHLtxrMqFANLVGB2Ykj1g=\n"

func TestHandAuthoredArtifactLoadsAndEvaluates(t *testing.T) {
	dir := t.TempDir()
	for path, raw := range map[string]string{
		"manifest.json":      handAuthoredManifest,
		"recorders/r1.jsonl": handAuthoredRecords,
		"keys/edee7ef9e19355528cf038dace72095337ef76feebcf2aad1d2c71130cb08066.pub": handAuthoredPublicKey,
	} {
		fullPath := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(raw), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	artifact, err := LoadArtifact(dir, filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatalf("LoadArtifact rejected static operator-shaped bytes: %v", err)
	}
	report := Evaluate(artifact)
	if len(report.Runs) != 1 || report.Runs[0].Ungraded || report.Runs[0].Grade != 1 {
		t.Fatalf("static artifact result = %#v, want one AEL-1 run", report.Runs)
	}
}
