package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luckyPipewrench/agent-evidence-levels/checker/internal/ael"
)

// Test-only deterministic fixture material. This is not a secret and must never
// be reused outside the public conformance corpus.
var fixtureSeed = []byte("AEL-FIXTURE-TEST-SEED-v1-0000000")

type signedRecord struct {
	payload []byte
	sig     []byte
}

func (r signedRecord) line() string {
	return base64.RawURLEncoding.EncodeToString(r.payload) + "." + base64.RawURLEncoding.EncodeToString(r.sig)
}

type recordPlan struct {
	typ      string
	ts       string
	seq      *int
	extra    map[string]any
	rawPatch func([]byte) []byte
}

type expected struct {
	Grade any               `json:"grade"`
	R     string            `json:"r"`
	Must  map[string]string `json:"must"`
	Note  string            `json:"note"`
}

type caseDef struct {
	name        string
	records     []signedRecord
	policies    map[string][]byte
	expect      expected
	publishKeys bool
}

func main() {
	outDir := flag.String("out", "", "fixture output directory")
	report := flag.Bool("report", false, "run checker over generated fixtures and print a report")
	flag.Parse()
	if *outDir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: aelgen --out <dir> [--report]")
		os.Exit(2)
	}
	if err := generate(*outDir, *report); err != nil {
		fmt.Fprintf(os.Stderr, "aelgen: %v\n", err)
		os.Exit(1)
	}
}

func generate(outDir string, report bool) error {
	if err := os.RemoveAll(outDir); err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(fixtureSeed)
	pub := priv.Public().(ed25519.PublicKey)
	fp := fingerprint(pub)

	cases, err := buildCases(priv, fp)
	if err != nil {
		return err
	}
	for _, c := range cases {
		if err := writeCase(outDir, c, pub, fp); err != nil {
			return err
		}
	}
	if report {
		return reportCases(outDir, cases)
	}
	return nil
}

func buildCases(priv ed25519.PrivateKey, fp string) ([]caseDef, error) {
	ael0Valid, err := buildRecords(priv, "run-ael0-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael0Four, err := buildRecords(priv, "run-ael0-perturb", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:15Z"),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael1Valid, err := buildRecords(priv, "run-ael1-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	policyHash, policyRaw, err := policyFixture()
	if err != nil {
		return nil, err
	}
	decision := map[string]any{
		"policy":     policyHash,
		"request_fp": "req-r-valid",
		"inputs":     map[string]any{"risk": 7, "kind": "egress"},
		"verdict":    "block",
	}
	rValid, err := buildRecords(priv, "run-r-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", decision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	badDecision := cloneMap(decision)
	badDecision["verdict"] = "allow"
	rMismatch, err := buildRecords(priv, "run-r-mismatch", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", badDecision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	seqTwo := 2
	seqThree := 3
	seqGap, err := buildRecords(priv, "run-ael1-seq-gap", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		{typ: "activity", ts: "2026-01-01T00:00:10Z", seq: &seqTwo, extra: eventExtra("net", "evt-1", "out", nil)},
		{typ: "close", ts: "2026-01-01T00:00:20Z", seq: &seqThree},
	})
	if err != nil {
		return nil, err
	}
	heartbeatGap, err := buildRecords(priv, "run-ael1-heartbeat-gap", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:02:00Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:02:10Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	wrongCount := 4
	tailTruncated, err := buildRecords(priv, "run-ael1-tail-truncated", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		closePlan("2026-01-01T00:00:20Z", &wrongCount, ""),
	})
	if err != nil {
		return nil, err
	}
	noClose, err := buildRecords(priv, "run-ael1-no-close", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
	})
	if err != nil {
		return nil, err
	}

	byteflip := cloneRecords(ael0Valid)
	byteflip[1].payload = append([]byte(nil), byteflip[1].payload...)
	byteflip[1].payload[1] = 'x'

	transpose := cloneRecords(ael0Four)
	transpose[1], transpose[2] = transpose[2], transpose[1]

	interiorDel := append(cloneRecords(ael0Four[:1]), cloneRecords(ael0Four[2:])...)

	noncanonical, err := buildRecords(priv, "run-ael0-noncanonical", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, prettyPatch),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	dupKey, err := buildRecords(priv, "run-ael0-dupkey", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 0, 0),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, dupVPatch),
		closePlan("2026-01-01T00:00:20Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	return []caseDef{
		{name: "ael0/valid", records: ael0Valid, expect: expect(0, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS"})},
		{name: "ael0/byteflip", records: byteflip, expect: expect("ungraded", "pending", map[string]string{"a": "FAIL"})},
		{name: "ael0/transpose", records: transpose, expect: expect("ungraded", "pending", map[string]string{"d": "FAIL"})},
		{name: "ael0/interior_del", records: interiorDel, expect: expect("ungraded", "pending", map[string]string{"e": "FAIL"})},
		{name: "ael0/noncanonical", records: noncanonical, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{name: "ael0/dupkey", records: dupKey, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{name: "ael0/unpublished_key", records: ael0Valid, publishKeys: false, expect: expect("ungraded", "pending", map[string]string{"a": "UV"})},
		{name: "ael1/valid", records: ael1Valid, expect: expect(1, "pending", map[string]string{"f": "PASS", "g": "PASS", "h": "PASS", "i": "PASS"})},
		{name: "ael1/seq_gap", records: seqGap, expect: expect(0, "pending", map[string]string{"g": "FAIL"})},
		{name: "ael1/heartbeat_gap", records: heartbeatGap, expect: expect(0, "pending", map[string]string{"h": "FAIL"})},
		{name: "ael1/tail_truncated", records: tailTruncated, expect: expect(0, "pending", map[string]string{"i": "FAIL"})},
		{name: "ael1/no_close", records: noClose, expect: expect(0, "pending", map[string]string{"j": "FAIL"})},
		{name: "r/valid", records: rValid, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "+R", map[string]string{"R": "PASS"})},
		{name: "r/verdict_mismatch", records: rMismatch, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "fail", map[string]string{"R": "FAIL"})},
	}, nil
}

func expect(grade any, r string, must map[string]string) expected {
	return expected{Grade: grade, R: r, Must: must, Note: ""}
}

func writeCase(root string, c caseDef, pub ed25519.PublicKey, fp string) error {
	caseDir := filepath.Join(root, filepath.FromSlash(c.name))
	if err := os.MkdirAll(filepath.Join(caseDir, "recorders"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(caseDir, "keys"), 0o755); err != nil {
		return err
	}
	if len(c.policies) > 0 {
		if err := os.MkdirAll(filepath.Join(caseDir, "policy"), 0o755); err != nil {
			return err
		}
		for hash, raw := range c.policies {
			if err := os.WriteFile(filepath.Join(caseDir, "policy", hash+".json"), raw, 0o644); err != nil {
				return err
			}
		}
	}
	publishKeys := c.publishKeys || c.name != "ael0/unpublished_key"
	if publishKeys {
		if err := os.WriteFile(filepath.Join(caseDir, "keys", fp+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return err
		}
	}

	var lines []string
	for _, rec := range c.records {
		lines = append(lines, rec.line())
	}
	if err := os.WriteFile(filepath.Join(caseDir, "recorders", "r1.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	run := "run-" + strings.ReplaceAll(strings.ReplaceAll(c.name, "/", "-"), "_", "-")
	if len(c.records) > 0 {
		var payload ael.Payload
		_ = json.Unmarshal(c.records[0].payload, &payload)
		if payload.Run != "" {
			run = payload.Run
		}
	}
	manifest, err := canonicalValue(map[string]any{
		"ael_format":   1,
		"claimed_rung": claimedRung(c.expect.Grade),
		"coverage":     "declared-only",
		"custody":      "same-process",
		"retention":    map[string]any{"period_days": 30, "custody": "fixture"},
		"runs":         []any{run},
		"recorders": []any{map[string]any{
			"id": "r1", "run": run, "key": fp, "file": "recorders/r1.jsonl",
		}},
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caseDir, "manifest.json"), manifest, 0o644); err != nil {
		return err
	}
	expectRaw, err := json.MarshalIndent(c.expect, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(caseDir, "expect.json"), append(expectRaw, '\n'), 0o644)
}

func buildRecords(priv ed25519.PrivateKey, run, recorder, fp string, plans []recordPlan) ([]signedRecord, error) {
	var out []signedRecord
	prev := zeroHash()
	for i, plan := range plans {
		seq := i
		if plan.seq != nil {
			seq = *plan.seq
		}
		payload := map[string]any{
			"v":        1,
			"type":     plan.typ,
			"run":      run,
			"recorder": recorder,
			"key":      fp,
			"seq":      seq,
			"prev":     prev,
			"ts":       plan.ts,
		}
		for k, v := range plan.extra {
			payload[k] = v
		}
		if plan.typ == "close" {
			if _, ok := payload["count"]; !ok {
				payload["count"] = len(plans)
			}
			if _, ok := payload["head"]; !ok {
				payload["head"] = prev
			}
		}
		raw, err := canonicalValue(payload)
		if err != nil {
			return nil, err
		}
		if plan.rawPatch != nil {
			raw = plan.rawPatch(raw)
		}
		sig := ed25519.Sign(priv, raw)
		out = append(out, signedRecord{payload: raw, sig: sig})
		prev = shaHex(raw)
	}
	return out, nil
}

func open(ts string, hmax, htol int) recordPlan {
	return recordPlan{typ: "open", ts: ts, extra: map[string]any{"hmax": hmax, "htol": htol}}
}

func activity(ts, class, id, dir string, decision map[string]any, patch func([]byte) []byte) recordPlan {
	return recordPlan{typ: "activity", ts: ts, extra: eventExtra(class, id, dir, decision), rawPatch: patch}
}

func heartbeat(ts string) recordPlan {
	return recordPlan{typ: "heartbeat", ts: ts}
}

func closePlan(ts string, count *int, head string) recordPlan {
	extra := map[string]any{}
	if count != nil {
		extra["count"] = *count
	}
	if head != "" {
		extra["head"] = head
	}
	return recordPlan{typ: "close", ts: ts, extra: extra}
}

func eventExtra(class, id, dir string, decision map[string]any) map[string]any {
	extra := map[string]any{"event": map[string]any{"class": class, "id": id, "dir": dir}}
	if decision != nil {
		extra["decision"] = decision
	}
	return extra
}

func policyFixture() (string, []byte, error) {
	raw, err := canonicalValue(map[string]any{
		"v": 1,
		"rules": []any{map[string]any{
			"when":    map[string]any{"field": "risk", "op": "gte", "value": 5},
			"verdict": "block",
		}},
		"default": "allow",
	})
	if err != nil {
		return "", nil, err
	}
	return shaHex(raw), raw, nil
}

func canonicalValue(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ael.Canonicalize(raw)
}

func prettyPatch(raw []byte) []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return raw
	}
	return buf.Bytes()
}

func dupVPatch(raw []byte) []byte {
	out := append([]byte(nil), raw[:len(raw)-1]...)
	out = append(out, []byte(`,"v":1}`)...)
	return out
}

func cloneRecords(in []signedRecord) []signedRecord {
	out := make([]signedRecord, len(in))
	for i, rec := range in {
		out[i] = signedRecord{payload: append([]byte(nil), rec.payload...), sig: append([]byte(nil), rec.sig...)}
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func shaHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func zeroHash() string {
	return strings.Repeat("0", 64)
}

func claimedRung(grade any) int {
	if n, ok := grade.(int); ok {
		return n
	}
	return 0
}

func reportCases(root string, cases []caseDef) error {
	for _, c := range cases {
		caseDir := filepath.Join(root, filepath.FromSlash(c.name))
		art, err := ael.LoadArtifact(caseDir, filepath.Join(caseDir, "keys"))
		if err != nil {
			return err
		}
		res := ael.Evaluate(art)
		ok := compareExpected(res, c.expect)
		fmt.Printf("%s: grade=%s r=%s | %s expected: %s [%s]\n",
			c.name, reportGrade(res), res.R, reportChecks(res), reportExpected(c.expect), okLabel(ok))
	}
	return nil
}

func compareExpected(res ael.Result, exp expected) bool {
	if reportGrade(res) != expectedGrade(exp.Grade) || res.R != exp.R {
		return false
	}
	for id, want := range exp.Must {
		got, ok := res.Checks[id]
		if !ok || string(got.Status) != want {
			return false
		}
	}
	return true
}

func reportChecks(res ael.Result) string {
	var parts []string
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "R"} {
		if out, ok := res.Checks[id]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", id, out.Status))
		}
	}
	return strings.Join(parts, " ")
}

func reportExpected(exp expected) string {
	var keys []string
	for k := range exp.Must {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, exp.Must[k]))
	}
	return fmt.Sprintf("grade=%s r=%s %s", expectedGrade(exp.Grade), exp.R, strings.Join(parts, " "))
}

func reportGrade(res ael.Result) string {
	if res.Ungraded {
		return "ungraded"
	}
	return fmt.Sprintf("AEL%d", res.Grade)
}

func expectedGrade(v any) string {
	switch t := v.(type) {
	case int:
		return fmt.Sprintf("AEL%d", t)
	case float64:
		return fmt.Sprintf("AEL%d", int(t))
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func okLabel(ok bool) string {
	if ok {
		return "OK"
	}
	return "MISMATCH"
}
