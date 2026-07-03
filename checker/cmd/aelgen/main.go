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
	name            string
	records         []signedRecord
	recorderRecords map[string][]signedRecord
	recorderKeys    map[string]string
	policies        map[string][]byte
	anchors         []byte
	counterparty    []signedRecord
	expect          expected
	publishKeys     bool
	omitKeys        map[string]bool
	badKeyFiles     map[string][]byte
	keys            map[string]ed25519.PublicKey
	manifestExtra   map[string]any
	coverage        string
	custody         string
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
	pub := priv.Public().(ed25519.PublicKey)
	rec2Priv, rec2Pub, rec2FP := labeledKey("recorder-2")
	rec3Priv, rec3Pub, rec3FP := labeledKey("recorder-3")
	logPriv, logPub, logFP := labeledKey("log-key")
	cpPriv, cpPub, cpFP := labeledKey("counterparty")

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

	ael2R1, err := buildRecords(priv, "run-ael2-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael2R2, err := buildRecords(rec2Priv, "run-ael2-valid", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	oneSideR2, err := buildRecords(rec2Priv, "run-ael2-valid", "r2", rec2FP, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	sameKeyR2, err := buildRecords(priv, "run-ael2-valid", "r2", fp, []recordPlan{
		open("2026-01-01T00:00:01Z", 60, 5),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	sameKeyR3, err := buildRecords(priv, "run-ael2-valid", "r3", fp, []recordPlan{
		open("2026-01-01T00:00:02Z", 60, 5),
		activity("2026-01-01T00:00:12Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:32Z"),
		closePlan("2026-01-01T00:00:42Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	thirdOmitR3, err := buildRecords(rec3Priv, "run-ael2-valid", "r3", rec3FP, []recordPlan{
		open("2026-01-01T00:00:02Z", 60, 5),
		heartbeat("2026-01-01T00:00:32Z"),
		closePlan("2026-01-01T00:00:42Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	ael3Anchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2})
	if err != nil {
		return nil, err
	}
	ael3RecorderKeyAnchor, err := buildAnchors("test-log", priv, map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2})
	if err != nil {
		return nil, err
	}
	ael3PrefixAnchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael2R1[:3], "r2": ael2R2[:3]})
	if err != nil {
		return nil, err
	}
	badInclusion, err := corruptFirstProof(ael3Anchor)
	if err != nil {
		return nil, err
	}
	altHistoryR1, err := buildRecords(priv, "run-ael2-valid", "r1", fp, []recordPlan{
		open("2026-01-01T00:00:00Z", 60, 5),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", nil, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}

	cpNonce := "fixture-cp-nonce-ael4"
	ael4Decision := map[string]any{
		"policy":     policyHash,
		"request_fp": "req-ael4-valid",
		"inputs":     map[string]any{"risk": 7, "kind": "egress"},
		"verdict":    "block",
	}
	ael4R1, err := buildRecords(priv, "run-ael4-valid", "r1", fp, []recordPlan{
		openNonce("2026-01-01T00:00:00Z", 60, 5, cpNonce),
		activity("2026-01-01T00:00:10Z", "net", "evt-1", "out", ael4Decision, nil),
		heartbeat("2026-01-01T00:00:30Z"),
		closePlan("2026-01-01T00:00:40Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4R2, err := buildRecords(rec2Priv, "run-ael4-valid", "r2", rec2FP, []recordPlan{
		openNonce("2026-01-01T00:00:01Z", 60, 5, cpNonce),
		activity("2026-01-01T00:00:11Z", "net", "evt-1", "out", ael4Decision, nil),
		heartbeat("2026-01-01T00:00:31Z"),
		closePlan("2026-01-01T00:00:41Z", nil, ""),
	})
	if err != nil {
		return nil, err
	}
	ael4Anchor, err := buildAnchors("test-log", logPriv, map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2})
	if err != nil {
		return nil, err
	}
	cpValid, err := buildCounterparty(cpPriv, "run-ael4-valid", cpNonce, "net", "evt-1")
	if err != nil {
		return nil, err
	}
	cpWrongRun, err := buildCounterparty(cpPriv, "run-other", "other-nonce", "net", "evt-1")
	if err != nil {
		return nil, err
	}
	cpUnrecorded, err := buildCounterparty(cpPriv, "run-ael4-valid", cpNonce, "net", "evt-missing")
	if err != nil {
		return nil, err
	}
	cpRecorderKey, err := buildCounterparty(priv, "run-ael4-valid", cpNonce, "net", "evt-1")
	if err != nil {
		return nil, err
	}

	ael2Extra := map[string]any{"correspondence": map[string]any{"classes": []any{"net"}, "match": "id"}}
	ael2EmptyClassesExtra := map[string]any{"correspondence": map[string]any{"classes": []any{}, "match": "id"}}
	ael3Extra := cloneAnyMap(ael2Extra)
	ael3Extra["anchor"] = map[string]any{"log": "test-log", "log_key": logFP, "file": "anchors.json"}
	ael3RecorderKeyExtra := cloneAnyMap(ael2Extra)
	ael3RecorderKeyExtra["anchor"] = map[string]any{"log": "test-log", "log_key": fp, "file": "anchors.json"}
	ael3LogKeyForgeryExtra := cloneAnyMap(ael2Extra)
	ael3LogKeyForgeryExtra["anchor"] = map[string]any{"log": "test-log", "log_key": fp, "file": "anchors.json"}
	ael4Extra := cloneAnyMap(ael3Extra)
	ael4Extra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{"net"}, "key": cpFP}
	ael4EmptyFlowsExtra := cloneAnyMap(ael3Extra)
	ael4EmptyFlowsExtra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{}, "key": cpFP}
	ael4RecorderKeyExtra := cloneAnyMap(ael3Extra)
	ael4RecorderKeyExtra["counterparty"] = map[string]any{"file": "counterparty.jsonl", "flows": []any{"net"}, "key": fp}
	multiKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub}
	threeKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, rec3FP: rec3Pub}
	anchoredKeys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, logFP: logPub}
	ael4Keys := map[string]ed25519.PublicKey{fp: pub, rec2FP: rec2Pub, logFP: logPub, cpFP: cpPub}

	return []caseDef{
		{name: "ael0/valid", records: ael0Valid, expect: expect(0, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS"})},
		{name: "ael0/byteflip", records: byteflip, expect: expect("ungraded", "pending", map[string]string{"a": "FAIL"})},
		{name: "ael0/transpose", records: transpose, expect: expect("ungraded", "pending", map[string]string{"d": "FAIL"})},
		{name: "ael0/interior_del", records: interiorDel, expect: expect("ungraded", "pending", map[string]string{"e": "FAIL"})},
		{name: "ael0/noncanonical", records: noncanonical, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{name: "ael0/dupkey", records: dupKey, expect: expect("ungraded", "pending", map[string]string{"b": "FAIL"})},
		{name: "ael0/unpublished_key", records: ael0Valid, publishKeys: false, expect: expect("ungraded", "pending", map[string]string{"a": "UV"})},
		{name: "ael0/bad_key_length", records: ael0Valid, badKeyFiles: map[string][]byte{fp: []byte(base64.StdEncoding.EncodeToString([]byte("short")) + "\n")}, expect: expect("ungraded", "pending", map[string]string{"a": "UV"})},
		{name: "ael0/tail_truncated_silent", records: ael0Valid[:2], expect: expect(0, "pending", map[string]string{"a": "PASS", "b": "PASS", "d": "PASS", "e": "PASS"})},
		{name: "ael1/valid", records: ael1Valid, expect: expect(1, "pending", map[string]string{"f": "PASS", "g": "PASS", "h": "PASS", "i": "PASS"})},
		{name: "ael1/seq_gap", records: seqGap, expect: expect(0, "pending", map[string]string{"g": "FAIL"})},
		{name: "ael1/heartbeat_gap", records: heartbeatGap, expect: expect(0, "pending", map[string]string{"h": "FAIL"})},
		{name: "ael1/tail_truncated", records: tailTruncated, expect: expect(0, "pending", map[string]string{"i": "FAIL"})},
		{name: "ael1/no_close", records: noClose, expect: expect(0, "pending", map[string]string{"j": "FAIL"})},
		{name: "r/valid", records: rValid, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "+R", map[string]string{"R": "PASS"})},
		{name: "r/verdict_mismatch", records: rMismatch, policies: map[string][]byte{policyHash: policyRaw}, expect: expect(1, "fail", map[string]string{"R": "FAIL"})},
		{name: "ael2/valid", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"k": "PASS", "l": "PASS", "m": "PASS"})},
		{name: "ael2/manifest_key_forgery", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": sameKeyR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/empty_classes", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2EmptyClassesExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "UV"})},
		{name: "ael2/one_side_deleted", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": oneSideR2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "FAIL"})},
		{name: "ael2/same_key", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": sameKeyR2}, recorderKeys: map[string]string{"r1": fp, "r2": fp}, keys: map[string]ed25519.PublicKey{fp: pub}, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/third_recorder_shares_key", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2, "r3": sameKeyR3}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP, "r3": fp}, keys: multiKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"l": "FAIL"})},
		{name: "ael2/third_recorder_omits_event", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2, "r3": thirdOmitR3}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP, "r3": rec3FP}, keys: threeKeys, manifestExtra: ael2Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(1, "pending", map[string]string{"m": "FAIL"})},
		{name: "ael3/valid", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(3, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "q": "PASS", "u": "PASS"})},
		{name: "ael3/bad_inclusion", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: badInclusion, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"o": "FAIL"})},
		{name: "ael3/alt_history", recorderRecords: map[string][]signedRecord{"r1": altHistoryR1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"p": "FAIL"})},
		{name: "ael3/no_logkey", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, omitKeys: map[string]bool{logFP: true}, anchors: ael3Anchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "UV"})},
		{name: "ael3/no_anchors_file", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "UV", "o": "UV", "p": "UV", "q": "UV"})},
		{name: "ael3/logkey_not_independent", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: multiKeys, anchors: ael3RecorderKeyAnchor, manifestExtra: ael3RecorderKeyExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "u": "FAIL"})},
		{name: "ael3/logkey_forgery", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": "", "r2": rec2FP}, keys: multiKeys, anchors: ael3RecorderKeyAnchor, manifestExtra: ael3LogKeyForgeryExtra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"l": "PASS", "n": "PASS", "u": "FAIL"})},
		{name: "ael3/unanchored_tail", recorderRecords: map[string][]signedRecord{"r1": ael2R1, "r2": ael2R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael3PrefixAnchor, manifestExtra: ael3Extra, coverage: "enforced-total", custody: "same-operator", expect: expect(2, "pending", map[string]string{"n": "PASS", "o": "PASS", "p": "PASS", "q": "FAIL", "u": "PASS"})},
		{name: "ael4/valid", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpValid, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(4, "+R", map[string]string{"r": "PASS", "s": "PASS", "t": "PASS", "v": "PASS", "R": "PASS"})},
		{name: "ael4/wrong_run_confirmation", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpWrongRun, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"s": "FAIL"})},
		{name: "ael4/no_counterparty_file", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"r": "UV", "s": "UV", "t": "UV"})},
		{name: "ael4/unrecorded_delivery", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpUnrecorded, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4Extra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"t": "FAIL"})},
		{name: "ael4/empty_flows", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: ael4Keys, anchors: ael4Anchor, counterparty: cpValid, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4EmptyFlowsExtra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"t": "UV"})},
		{name: "ael4/cp_key_not_independent", recorderRecords: map[string][]signedRecord{"r1": ael4R1, "r2": ael4R2}, recorderKeys: map[string]string{"r1": fp, "r2": rec2FP}, keys: anchoredKeys, anchors: ael4Anchor, counterparty: cpRecorderKey, policies: map[string][]byte{policyHash: policyRaw}, manifestExtra: ael4RecorderKeyExtra, coverage: "enforced-total", custody: "independent", expect: expect(3, "+R", map[string]string{"r": "PASS", "s": "PASS", "t": "PASS", "v": "FAIL"})},
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
	if len(c.anchors) > 0 {
		if err := os.WriteFile(filepath.Join(caseDir, "anchors.json"), c.anchors, 0o644); err != nil {
			return err
		}
	}
	if len(c.counterparty) > 0 {
		var lines []string
		for _, stmt := range c.counterparty {
			lines = append(lines, stmt.line())
		}
		if err := os.WriteFile(filepath.Join(caseDir, "counterparty.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	keys := c.keys
	if len(keys) == 0 {
		keys = map[string]ed25519.PublicKey{fp: pub}
	}
	publishKeys := c.publishKeys || c.name != "ael0/unpublished_key"
	if publishKeys {
		keyFPs := make([]string, 0, len(keys))
		for keyFP := range keys {
			keyFPs = append(keyFPs, keyFP)
		}
		sort.Strings(keyFPs)
		for _, keyFP := range keyFPs {
			if c.omitKeys[keyFP] {
				continue
			}
			raw := []byte(base64.StdEncoding.EncodeToString(keys[keyFP]) + "\n")
			if override, ok := c.badKeyFiles[keyFP]; ok {
				raw = override
			}
			if err := os.WriteFile(filepath.Join(caseDir, "keys", keyFP+".pub"), raw, 0o644); err != nil {
				return err
			}
		}
	}

	recorderRecords := c.recorderRecords
	if len(recorderRecords) == 0 {
		recorderRecords = map[string][]signedRecord{"r1": c.records}
	}
	recorderIDs := make([]string, 0, len(recorderRecords))
	for recorderID := range recorderRecords {
		recorderIDs = append(recorderIDs, recorderID)
	}
	sort.Strings(recorderIDs)
	for _, recorderID := range recorderIDs {
		var lines []string
		for _, rec := range recorderRecords[recorderID] {
			lines = append(lines, rec.line())
		}
		if err := os.WriteFile(filepath.Join(caseDir, "recorders", recorderID+".jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}

	run := "run-" + strings.ReplaceAll(strings.ReplaceAll(c.name, "/", "-"), "_", "-")
	for _, records := range recorderRecords {
		if len(records) == 0 {
			continue
		}
		var payload ael.Payload
		_ = json.Unmarshal(records[0].payload, &payload)
		if payload.Run != "" {
			run = payload.Run
			break
		}
	}

	recorderEntries := make([]any, 0, len(recorderIDs))
	for _, recorderID := range recorderIDs {
		keyFP, ok := c.recorderKeys[recorderID]
		if !ok {
			keyFP = fp
		}
		recorderEntries = append(recorderEntries, map[string]any{
			"id": recorderID, "run": run, "key": keyFP, "file": "recorders/" + recorderID + ".jsonl",
		})
	}
	coverage := c.coverage
	if coverage == "" {
		coverage = "declared-only"
	}
	custody := c.custody
	if custody == "" {
		custody = "same-process"
	}
	manifestMap := map[string]any{
		"ael_format":   1,
		"claimed_rung": claimedRung(c.expect.Grade),
		"coverage":     coverage,
		"custody":      custody,
		"retention":    map[string]any{"period_days": 30, "custody": "fixture"},
		"runs":         []any{run},
		"recorders":    recorderEntries,
	}
	for k, v := range c.manifestExtra {
		manifestMap[k] = v
	}
	manifest, err := canonicalValue(manifestMap)
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

func openNonce(ts string, hmax, htol int, nonce string) recordPlan {
	return recordPlan{typ: "open", ts: ts, extra: map[string]any{"hmax": hmax, "htol": htol, "cp_nonce": nonce}}
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

func buildAnchors(logID string, logPriv ed25519.PrivateKey, logs map[string][]signedRecord) ([]byte, error) {
	var recorderIDs []string
	for recorderID := range logs {
		recorderIDs = append(recorderIDs, recorderID)
	}
	sort.Strings(recorderIDs)
	var entries []ael.AnchorEntry
	var leaves [][]byte
	index := 0
	for _, recorderID := range recorderIDs {
		for seq, rec := range logs[recorderID] {
			leaf := merkleLeaf(rec.payload)
			leaves = append(leaves, leaf)
			entries = append(entries, ael.AnchorEntry{
				Recorder: recorderID,
				Run:      recordRun(rec),
				Seq:      seq,
				Leaf:     hex.EncodeToString(leaf),
				Index:    index,
			})
			index++
		}
	}
	root := merkleRoot(leaves)
	proofs := merkleProofs(leaves)
	for i := range entries {
		for _, node := range proofs[i] {
			entries[i].Proof = append(entries[i].Proof, hex.EncodeToString(node))
		}
	}
	headMsg, err := canonicalValue(map[string]any{"log": logID, "root": hex.EncodeToString(root), "size": len(leaves)})
	if err != nil {
		return nil, err
	}
	anchors := map[string]any{
		"log": logID,
		"tree_head": map[string]any{
			"size": len(leaves),
			"root": hex.EncodeToString(root),
			"sig":  base64.StdEncoding.EncodeToString(ed25519.Sign(logPriv, headMsg)),
		},
		"entries": anchorEntriesValue(entries),
	}
	return canonicalValue(anchors)
}

func anchorEntriesValue(entries []ael.AnchorEntry) []any {
	out := make([]any, 0, len(entries))
	for _, entry := range entries {
		proof := make([]any, 0, len(entry.Proof))
		for _, item := range entry.Proof {
			proof = append(proof, item)
		}
		out = append(out, map[string]any{
			"recorder": entry.Recorder,
			"run":      entry.Run,
			"seq":      entry.Seq,
			"leaf":     entry.Leaf,
			"index":    entry.Index,
			"proof":    proof,
		})
	}
	return out
}

func corruptFirstProof(raw []byte) ([]byte, error) {
	var anchors ael.Anchors
	if err := json.Unmarshal(raw, &anchors); err != nil {
		return nil, err
	}
	if len(anchors.Entries) == 0 || len(anchors.Entries[0].Proof) == 0 {
		return nil, fmt.Errorf("anchor has no proof to corrupt")
	}
	anchors.Entries[0].Proof[0] = strings.Repeat("f", 64)
	return canonicalValue(map[string]any{
		"log":       anchors.Log,
		"tree_head": map[string]any{"size": anchors.TreeHead.Size, "root": anchors.TreeHead.Root, "sig": anchors.TreeHead.Sig},
		"entries":   anchorEntriesValue(anchors.Entries),
	})
}

func buildCounterparty(priv ed25519.PrivateKey, run, nonce, flow, eventID string) ([]signedRecord, error) {
	raw, err := canonicalValue(map[string]any{
		"v":        1,
		"type":     "received",
		"run":      run,
		"flow":     flow,
		"nonce":    nonce,
		"received": map[string]any{"event_id": eventID},
	})
	if err != nil {
		return nil, err
	}
	return []signedRecord{{payload: raw, sig: ed25519.Sign(priv, raw)}}, nil
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

func cloneAnyMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func labeledKey(label string) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	seed := sha256.Sum256([]byte("AEL-FIXTURE-TEST-SEED-v1:" + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, fingerprint(pub)
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

func recordRun(rec signedRecord) string {
	var payload ael.Payload
	_ = json.Unmarshal(rec.payload, &payload)
	return payload.Run
}

func merkleLeaf(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	return sum[:]
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		sum := sha256.Sum256(nil)
		return sum[:]
	}
	if len(leaves) == 1 {
		return append([]byte(nil), leaves[0]...)
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	return merkleNode(merkleRoot(leaves[:split]), merkleRoot(leaves[split:]))
}

func merkleProofs(leaves [][]byte) [][][]byte {
	proofs := make([][][]byte, len(leaves))
	for i := range leaves {
		proofs[i] = merkleProof(leaves, i)
	}
	return proofs
}

func merkleProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	split := largestPowerOfTwoLessThan(len(leaves))
	if index < split {
		return append(merkleProof(leaves[:split], index), merkleRoot(leaves[split:]))
	}
	return append(merkleProof(leaves[split:], index-split), merkleRoot(leaves[:split]))
}

func merkleNode(left, right []byte) []byte {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}

func largestPowerOfTwoLessThan(n int) int {
	p := 1
	for p<<1 < n {
		p <<= 1
	}
	return p
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
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "u", "r", "s", "t", "v", "R"} {
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
