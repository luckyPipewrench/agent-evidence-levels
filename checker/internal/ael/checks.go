package ael

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const zeroPrev = "0000000000000000000000000000000000000000000000000000000000000000"

func Evaluate(art *Artifact) Result {
	checks := map[string]Outcome{}
	checks["a"] = checkSignatures(art)
	checks["b"] = checkCanonicalPayloads(art)
	checks["c"] = checkByteflipDuty(checks["a"])
	chain := checkChain(art)
	checks["d"] = chain
	checks["e"] = chain
	checks["f"] = checkOpen(art)
	checks["g"] = checkContiguous(art)
	checks["h"] = checkHeartbeat(art)
	checks["i"] = checkCloseCount(art)
	checks["j"] = checkOpenEnd(art)
	checks["k"] = checkTwoRecorders(art)
	checks["l"] = checkKeysDiffer(art)
	checks["m"] = checkCrossAudit(art)
	checks["n"] = checkTreeHead(art)
	checks["o"] = checkInclusion(art)
	checks["p"] = checkAnchorLeaves(art)
	checks["q"] = checkUnanchoredWindow(art)
	checks["r"] = checkCounterpartySignatures(art)
	checks["s"] = checkCounterpartyBinding(art)
	checks["t"] = checkCounterpartyAudit(art)
	checks["u"] = checkLogKeyIndependent(art)
	checks["v"] = checkCounterpartyKeyIndependent(art)
	rSuffix, rOutcome := checkR(art)
	checks["R"] = rOutcome

	res := Result{
		R:         rSuffix,
		Checks:    checks,
		Coverage:  art.Manifest.Coverage,
		Custody:   art.Manifest.Custody,
		Anchor:    anchorAnnotation(art),
		Retention: retentionAnnotation(art.Manifest.Retention),
	}
	if checks["j"].Status == Fail && strings.Contains(checks["j"].Message, "OPEN/ABNORMAL-END") {
		res.Open = true
		res.OpenStatus = "OPEN/ABNORMAL-END"
	}
	computeGrade(&res)
	if res.Grade >= 3 && !res.Ungraded {
		res.Anchor = "independent"
	}
	return res
}

func checkSignatures(art *Artifact) Outcome {
	records := art.AllRecords()
	if len(records) == 0 {
		return Outcome{Status: Fail, Message: "no records"}
	}
	sawUV := false
	for _, rec := range records {
		if rec.SignatureUV {
			sawUV = true
			continue
		}
		if !rec.SignatureOK {
			return Outcome{Status: Fail, Message: recordMsg(rec, rec.SignatureErr)}
		}
	}
	if sawUV {
		return Outcome{Status: UV, Message: "one or more published keys are missing"}
	}
	return Outcome{Status: Pass, Message: "all signatures verify over stored payload bytes"}
}

func checkCanonicalPayloads(art *Artifact) Outcome {
	sawUV := false
	for _, rec := range art.AllRecords() {
		if rec.SignatureUV || !rec.SignatureOK {
			sawUV = true
			continue
		}
		if !rec.CanonicalOK {
			return Outcome{Status: Fail, Message: recordMsg(rec, rec.CanonicalErr)}
		}
	}
	if sawUV {
		return Outcome{Status: UV, Message: "canonicality is checked only after signature verification"}
	}
	return Outcome{Status: Pass, Message: "all verified payloads are canonical"}
}

func checkByteflipDuty(sig Outcome) Outcome {
	if sig.Status == Pass {
		return Outcome{Status: Pass, Message: "signature check rejects byte-level changes"}
	}
	return sig
}

func checkChain(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		if len(log.Records) == 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s has no records", log.ID)}
		}
		for i, rec := range log.Records {
			if rec.ParseErr != nil || rec.LineErr != nil {
				return Outcome{Status: Fail, Message: recordMsg(rec, firstErr(rec.LineErr, rec.ParseErr))}
			}
			if rec.Payload.V != 1 {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("v=%d, want 1", rec.Payload.V))}
			}
			if rec.Payload.Recorder != log.ID {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("recorder=%q, want %q", rec.Payload.Recorder, log.ID))}
			}
			if rec.Payload.Run != log.Run {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("run=%q, want %q", rec.Payload.Run, log.Run))}
			}
			if i == 0 {
				if rec.Payload.Seq != 0 {
					return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("first seq=%d, want 0", rec.Payload.Seq))}
				}
				if rec.Payload.Prev != zeroPrev {
					return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("first prev is not zero hash"))}
				}
				continue
			}
			prev := log.Records[i-1]
			if rec.Payload.Prev != prev.Hash {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("prev=%s, want %s", rec.Payload.Prev, prev.Hash))}
			}
		}
	}
	return Outcome{Status: Pass, Message: "presented record order is hash-linked"}
}

func checkOpen(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		if len(log.Records) == 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s has no open", log.ID)}
		}
		open := log.Records[0]
		if open.Payload.Type != "open" || open.Payload.Seq != 0 {
			return Outcome{Status: Fail, Message: recordMsg(open, fmt.Errorf("first record is not open seq 0"))}
		}
		if open.Payload.HMax <= 0 {
			return Outcome{Status: Fail, Message: recordMsg(open, fmt.Errorf("hmax=%d caps at AEL-0", open.Payload.HMax))}
		}
	}
	return Outcome{Status: Pass, Message: "each recorder opens with hmax>0"}
}

func checkContiguous(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		for i, rec := range log.Records {
			if rec.ParseErr != nil || rec.LineErr != nil {
				return Outcome{Status: Fail, Message: recordMsg(rec, firstErr(rec.LineErr, rec.ParseErr))}
			}
			if rec.Payload.Seq != i {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("seq=%d, want %d", rec.Payload.Seq, i))}
			}
		}
	}
	return Outcome{Status: Pass, Message: "sequence numbers are contiguous"}
}

func checkHeartbeat(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		if len(log.Records) == 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s has no records", log.ID)}
		}
		hmax := log.Records[0].Payload.HMax
		htol := log.Records[0].Payload.HTol
		if hmax <= 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s hmax=%d; heartbeats unused", log.ID, hmax)}
		}
		limit := time.Duration(hmax+htol) * time.Second
		for i := 1; i < len(log.Records); i++ {
			prevTS, err := log.Records[i-1].Payload.Time()
			if err != nil {
				return Outcome{Status: Fail, Message: recordMsg(log.Records[i-1], err)}
			}
			curTS, err := log.Records[i].Payload.Time()
			if err != nil {
				return Outcome{Status: Fail, Message: recordMsg(log.Records[i], err)}
			}
			if curTS.Sub(prevTS) > limit {
				return Outcome{Status: Fail, Message: recordMsg(log.Records[i], fmt.Errorf("gap %s exceeds %s", curTS.Sub(prevTS), limit))}
			}
		}
	}
	return Outcome{Status: Pass, Message: "record spacing is within hmax+htol"}
}

func checkCloseCount(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		if len(log.Records) == 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s has no records", log.ID)}
		}
		closeRec := log.Records[len(log.Records)-1]
		if closeRec.Payload.Type != "close" {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s has no close", log.ID)}
		}
		for i := 0; i < len(log.Records)-1; i++ {
			if log.Records[i].Payload.Type == "close" {
				return Outcome{Status: Fail, Message: recordMsg(log.Records[i], fmt.Errorf("close is not final record"))}
			}
		}
		if closeRec.Payload.Count != len(log.Records) {
			return Outcome{Status: Fail, Message: recordMsg(closeRec, fmt.Errorf("close.count=%d, records present=%d", closeRec.Payload.Count, len(log.Records)))}
		}
		if closeRec.Payload.Count < 2 {
			return Outcome{Status: Fail, Message: recordMsg(closeRec, fmt.Errorf("close.count=%d, want at least 2", closeRec.Payload.Count))}
		}
		head := log.Records[closeRec.Payload.Count-2].Hash
		if closeRec.Payload.Head != head {
			return Outcome{Status: Fail, Message: recordMsg(closeRec, fmt.Errorf("close.head=%s, want %s", closeRec.Payload.Head, head))}
		}
	}
	return Outcome{Status: Pass, Message: "close commits to count and previous head"}
}

func checkOpenEnd(art *Artifact) Outcome {
	for _, log := range art.RecorderLogs {
		if len(log.Records) == 0 {
			continue
		}
		if log.Records[0].Payload.HMax > 0 && log.Records[len(log.Records)-1].Payload.Type != "close" {
			return Outcome{Status: Fail, Message: fmt.Sprintf("%s OPEN/ABNORMAL-END: no close record", log.ID)}
		}
	}
	return Outcome{Status: Pass, Message: "closed or not claiming AEL-1 liveness"}
}

func checkTwoRecorders(art *Artifact) Outcome {
	logs := logsForArtifactRun(art)
	if len(logs) < 2 {
		return Outcome{Status: Fail, Message: "fewer than two recorders on the run"}
	}
	for _, log := range logs {
		if out := recorderAEL1(log); out.Status != Pass {
			out.Message = fmt.Sprintf("%s is not independently AEL-1: %s", log.ID, out.Message)
			return out
		}
	}
	return Outcome{Status: Pass, Message: "all recorders independently satisfy AEL-1"}
}

func checkKeysDiffer(art *Artifact) Outcome {
	logs := logsForArtifactRun(art)
	if len(logs) < 2 {
		return Outcome{Status: UV, Message: "need two recorders to compare key custody"}
	}
	keys := map[string]string{}
	for _, log := range logs {
		key, out := verifiedRecorderKey(log)
		if out.Status != Pass {
			return out
		}
		keys[log.ID] = key
	}
	for i := 0; i < len(logs); i++ {
		for j := i + 1; j < len(logs); j++ {
			if keys[logs[i].ID] == keys[logs[j].ID] {
				return Outcome{Status: Fail, Message: fmt.Sprintf("recorders %s and %s use the same verified signing key %s", logs[i].ID, logs[j].ID, keys[logs[i].ID])}
			}
		}
	}
	return Outcome{Status: Pass, Message: "verified recorder signing keys differ"}
}

func checkCrossAudit(art *Artifact) Outcome {
	if art.Manifest.Correspondence == nil {
		return Outcome{Status: UV, Message: "no covered event classes declared; omission-detection unverifiable"}
	}
	if len(art.Manifest.Correspondence.Classes) == 0 {
		return Outcome{Status: UV, Message: "no covered event classes declared; omission-detection unverifiable"}
	}
	if art.Manifest.Correspondence.Match != "id" {
		return Outcome{Status: UV, Message: fmt.Sprintf("unsupported correspondence match %q", art.Manifest.Correspondence.Match)}
	}
	logs := logsForArtifactRun(art)
	if len(logs) < 2 {
		return Outcome{Status: UV, Message: "need two recorders for cross-audit"}
	}
	classes := stringSet(art.Manifest.Correspondence.Classes)
	covered := map[string]map[string]bool{}
	events := map[string]bool{}
	for _, log := range logs {
		covered[log.ID] = coveredEvents(log, classes)
		for id := range covered[log.ID] {
			events[id] = true
		}
	}
	for id := range events {
		var present, absent []string
		for _, log := range logs {
			if covered[log.ID][id] {
				present = append(present, log.ID)
			} else {
				absent = append(absent, log.ID)
			}
		}
		if len(absent) > 0 {
			return Outcome{Status: Fail, Message: fmt.Sprintf("one-sided event %s present on %s absent from %s", id, strings.Join(present, ","), strings.Join(absent, ","))}
		}
	}
	return Outcome{Status: Pass, Message: "covered event ids match across recorders"}
}

func checkTreeHead(art *Artifact) Outcome {
	if art.Manifest.Anchor == nil {
		return Outcome{Status: UV, Message: "manifest anchor block is absent"}
	}
	if art.AnchorsErr != nil {
		return Outcome{Status: Fail, Message: art.AnchorsErr.Error()}
	}
	if art.Anchors == nil {
		return Outcome{Status: UV, Message: "anchors.json is absent"}
	}
	pub, ok := art.Keys[strings.ToLower(art.Manifest.Anchor.LogKey)]
	if !ok {
		return Outcome{Status: UV, Message: fmt.Sprintf("missing published log key %s", art.Manifest.Anchor.LogKey)}
	}
	sig, err := base64.StdEncoding.DecodeString(art.Anchors.TreeHead.Sig)
	if err != nil {
		return Outcome{Status: Fail, Message: fmt.Sprintf("decode tree_head.sig: %v", err)}
	}
	if len(sig) != ed25519.SignatureSize {
		return Outcome{Status: Fail, Message: fmt.Sprintf("tree_head.sig length %d", len(sig))}
	}
	msg, err := Canonicalize([]byte(fmt.Sprintf(`{"log":%q,"root":%q,"size":%d}`, art.Anchors.Log, art.Anchors.TreeHead.Root, art.Anchors.TreeHead.Size)))
	if err != nil {
		return Outcome{Status: Fail, Message: fmt.Sprintf("canonical tree head: %v", err)}
	}
	if !ed25519.Verify(pub, msg, sig) {
		return Outcome{Status: Fail, Message: "tree_head.sig verification failed"}
	}
	return Outcome{Status: Pass, Message: "tree head signature verifies under log key"}
}

func checkInclusion(art *Artifact) Outcome {
	if art.Manifest.Anchor == nil {
		return Outcome{Status: UV, Message: "manifest anchor block is absent"}
	}
	if art.AnchorsErr != nil {
		return Outcome{Status: Fail, Message: art.AnchorsErr.Error()}
	}
	if art.Anchors == nil {
		return Outcome{Status: UV, Message: "anchors.json is absent"}
	}
	if len(art.Anchors.Entries) == 0 {
		return Outcome{Status: Fail, Message: "anchors.json has no inclusion entries"}
	}
	root, err := decodeHex32(art.Anchors.TreeHead.Root)
	if err != nil {
		return Outcome{Status: Fail, Message: fmt.Sprintf("tree_head.root: %v", err)}
	}
	for _, entry := range art.Anchors.Entries {
		leaf, err := decodeHex32(entry.Leaf)
		if err != nil {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor %s seq %d leaf: %v", entry.Recorder, entry.Seq, err)}
		}
		proof := make([][]byte, 0, len(entry.Proof))
		for _, item := range entry.Proof {
			node, err := decodeHex32(item)
			if err != nil {
				return Outcome{Status: Fail, Message: fmt.Sprintf("anchor %s seq %d proof: %v", entry.Recorder, entry.Seq, err)}
			}
			proof = append(proof, node)
		}
		got, err := merkleRootFromProof(leaf, entry.Index, art.Anchors.TreeHead.Size, proof)
		if err != nil {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor %s seq %d: %v", entry.Recorder, entry.Seq, err)}
		}
		if !bytes.Equal(got, root) {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor %s seq %d inclusion root mismatch", entry.Recorder, entry.Seq)}
		}
	}
	return Outcome{Status: Pass, Message: "all inclusion proofs recompute to tree head root"}
}

func checkAnchorLeaves(art *Artifact) Outcome {
	if art.Manifest.Anchor == nil {
		return Outcome{Status: UV, Message: "manifest anchor block is absent"}
	}
	if art.AnchorsErr != nil {
		return Outcome{Status: Fail, Message: art.AnchorsErr.Error()}
	}
	if art.Anchors == nil {
		return Outcome{Status: UV, Message: "anchors.json is absent"}
	}
	for _, entry := range art.Anchors.Entries {
		rec := findRecord(art, entry.Recorder, entry.Run, entry.Seq)
		if rec == nil {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor mismatch: %s seq %d is missing", entry.Recorder, entry.Seq)}
		}
		if got := merkleLeafHex(rec.PayloadRaw); got != strings.ToLower(entry.Leaf) {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor mismatch: %s seq %d leaf=%s anchored=%s", entry.Recorder, entry.Seq, got, entry.Leaf)}
		}
	}
	return Outcome{Status: Pass, Message: "anchored leaves match stored payload bytes"}
}

func checkUnanchoredWindow(art *Artifact) Outcome {
	if art.Manifest.Anchor == nil {
		return Outcome{Status: UV, Message: "manifest anchor block is absent"}
	}
	if art.AnchorsErr != nil {
		return Outcome{Status: Fail, Message: art.AnchorsErr.Error()}
	}
	if art.Anchors == nil {
		return Outcome{Status: UV, Message: "anchors.json is absent"}
	}
	latest := map[string]int{}
	for _, entry := range art.Anchors.Entries {
		if prev, ok := latest[entry.Recorder]; !ok || entry.Seq > prev {
			latest[entry.Recorder] = entry.Seq
		}
	}
	var windows []string
	for _, log := range logsForArtifactRun(art) {
		head, ok := latest[log.ID]
		if !ok {
			windows = append(windows, fmt.Sprintf("%s:all", log.ID))
			continue
		}
		for _, rec := range log.Records {
			if rec.Payload.Seq > head {
				windows = append(windows, fmt.Sprintf("%s:%d", log.ID, rec.Payload.Seq))
			}
		}
	}
	if len(windows) > 0 {
		return Outcome{Status: Fail, Message: "UNANCHORED-WINDOW " + strings.Join(windows, ",")}
	}
	return Outcome{Status: Pass, Message: "no records beyond latest anchored seq"}
}

func checkLogKeyIndependent(art *Artifact) Outcome {
	if art.Manifest.Anchor == nil {
		return Outcome{Status: UV, Message: "manifest anchor block is absent"}
	}
	logKey := strings.ToLower(art.Manifest.Anchor.LogKey)
	if logKey == "" {
		return Outcome{Status: UV, Message: "manifest anchor.log_key is absent"}
	}
	for _, log := range logsForArtifactRun(art) {
		recorderKey, out := verifiedRecorderKey(log)
		if out.Status != Pass {
			return out
		}
		if recorderKey == logKey {
			return Outcome{Status: Fail, Message: fmt.Sprintf("anchor log key %s is also recorder %s key", logKey, log.ID)}
		}
	}
	return Outcome{Status: Pass, Message: "anchor log key differs from verified recorder signing keys"}
}

func checkCounterpartySignatures(art *Artifact) Outcome {
	if art.Manifest.Counterparty == nil {
		return Outcome{Status: UV, Message: "manifest counterparty block is absent"}
	}
	if art.CounterpartyMissing {
		return Outcome{Status: UV, Message: "counterparty.jsonl is absent"}
	}
	if art.CounterpartyErr != nil {
		return Outcome{Status: Fail, Message: art.CounterpartyErr.Error()}
	}
	if _, ok := art.Keys[strings.ToLower(art.Manifest.Counterparty.Key)]; !ok {
		return Outcome{Status: UV, Message: fmt.Sprintf("missing published counterparty key %s", art.Manifest.Counterparty.Key)}
	}
	if len(art.Counterparty) == 0 {
		return Outcome{Status: Fail, Message: "no counterparty statements"}
	}
	for _, stmt := range art.Counterparty {
		if stmt.SignatureUV {
			return Outcome{Status: UV, Message: stmt.SignatureErr.Error()}
		}
		if !stmt.SignatureOK {
			return Outcome{Status: Fail, Message: counterpartyMsg(stmt, firstErr(stmt.SignatureErr, stmt.CanonicalErr))}
		}
		if !stmt.CanonicalOK {
			return Outcome{Status: Fail, Message: counterpartyMsg(stmt, stmt.CanonicalErr)}
		}
	}
	return Outcome{Status: Pass, Message: "all counterparty statements verify"}
}

func checkCounterpartyBinding(art *Artifact) Outcome {
	if art.Manifest.Counterparty == nil {
		return Outcome{Status: UV, Message: "manifest counterparty block is absent"}
	}
	if art.CounterpartyMissing {
		return Outcome{Status: UV, Message: "counterparty.jsonl is absent"}
	}
	run := artifactRun(art)
	nonce := runNonce(art, run)
	if nonce == "" {
		return Outcome{Status: Fail, Message: "run open record has no cp_nonce"}
	}
	for _, stmt := range art.Counterparty {
		if stmt.LineErr != nil || stmt.ParseErr != nil || stmt.SignatureUV || !stmt.SignatureOK {
			return Outcome{Status: UV, Message: "counterparty statements are not verified"}
		}
		if stmt.Payload.V != 1 || stmt.Payload.Type != "received" {
			return Outcome{Status: Fail, Message: counterpartyMsg(stmt, fmt.Errorf("not a v1 received statement"))}
		}
		if stmt.Payload.Run != run || stmt.Payload.Nonce != nonce {
			return Outcome{Status: Fail, Message: counterpartyMsg(stmt, fmt.Errorf("wrong-run: run=%q nonce=%q want run=%q nonce=%q", stmt.Payload.Run, stmt.Payload.Nonce, run, nonce))}
		}
	}
	return Outcome{Status: Pass, Message: "counterparty statements bind to run and nonce"}
}

func checkCounterpartyAudit(art *Artifact) Outcome {
	if art.Manifest.Counterparty == nil {
		return Outcome{Status: UV, Message: "manifest counterparty block is absent"}
	}
	if art.CounterpartyMissing {
		return Outcome{Status: UV, Message: "counterparty.jsonl is absent"}
	}
	if len(art.Manifest.Counterparty.Flows) == 0 {
		return Outcome{Status: UV, Message: "no confirmed flows declared"}
	}
	run := artifactRun(art)
	nonce := runNonce(art, run)
	if nonce == "" {
		return Outcome{Status: UV, Message: "run open record has no cp_nonce"}
	}
	flows := stringSet(art.Manifest.Counterparty.Flows)
	recorded := map[string]bool{}
	for _, rec := range art.AllRecords() {
		if rec.Payload.Type == "activity" && rec.Payload.Event != nil && rec.Payload.Event.Dir == "out" && flows[rec.Payload.Event.Class] {
			recorded[rec.Payload.Event.ID] = true
		}
	}
	confirmed := map[string]bool{}
	for _, stmt := range art.Counterparty {
		if stmt.LineErr != nil || stmt.ParseErr != nil || stmt.SignatureUV || !stmt.SignatureOK {
			return Outcome{Status: UV, Message: "counterparty statements are not verified"}
		}
		if stmt.Payload.Run != run || stmt.Payload.Nonce != nonce {
			return Outcome{Status: UV, Message: "counterparty binding failed; audit not evaluated"}
		}
		if !flows[stmt.Payload.Flow] || stmt.Payload.Received == nil {
			continue
		}
		if id := stmt.Payload.Received["event_id"]; id != "" {
			confirmed[id] = true
		}
	}
	for id := range recorded {
		if !confirmed[id] {
			return Outcome{Status: Fail, Message: "recorded-but-unconfirmed " + id}
		}
	}
	for id := range confirmed {
		if !recorded[id] {
			return Outcome{Status: Fail, Message: "confirmed-but-unrecorded " + id}
		}
	}
	return Outcome{Status: Pass, Message: "confirmed flows match recorded outbound events"}
}

func checkCounterpartyKeyIndependent(art *Artifact) Outcome {
	if art.Manifest.Counterparty == nil {
		return Outcome{Status: UV, Message: "manifest counterparty block is absent"}
	}
	counterpartyKey := strings.ToLower(art.Manifest.Counterparty.Key)
	if counterpartyKey == "" {
		return Outcome{Status: UV, Message: "manifest counterparty.key is absent"}
	}
	for _, log := range logsForArtifactRun(art) {
		recorderKey, out := verifiedRecorderKey(log)
		if out.Status != Pass {
			return out
		}
		if recorderKey == counterpartyKey {
			return Outcome{Status: Fail, Message: fmt.Sprintf("counterparty key %s is also recorder %s key", counterpartyKey, log.ID)}
		}
	}
	return Outcome{Status: Pass, Message: "counterparty key differs from verified recorder signing keys"}
}

func checkR(art *Artifact) (string, Outcome) {
	activityCount := 0
	decisionCount := 0
	for _, rec := range art.AllRecords() {
		if rec.ParseErr != nil || rec.LineErr != nil || rec.Payload.Type != "activity" {
			continue
		}
		activityCount++
		if rec.Payload.Decision == nil {
			continue
		}
		decisionCount++
		dec := rec.Payload.Decision
		pol, ok := art.Policies[dec.Policy]
		if !ok {
			if err, ok := art.PolicyLoadErrs[dec.Policy]; ok {
				return "fail", Outcome{Status: Fail, Message: fmt.Sprintf("policy %s failed to load: %v", dec.Policy, err)}
			}
			return "fail", Outcome{Status: Fail, Message: fmt.Sprintf("policy %s not found", dec.Policy)}
		}
		if pol.Hash != dec.Policy {
			return "fail", Outcome{Status: Fail, Message: fmt.Sprintf("policy hash mismatch: record=%s computed=%s", dec.Policy, pol.Hash)}
		}
		verdict, err := pol.Eval(dec.Inputs)
		if err != nil {
			return "fail", Outcome{Status: Fail, Message: recordMsg(rec, err)}
		}
		if verdict != dec.Verdict {
			return "fail", Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("decision verdict=%s, recomputed=%s", dec.Verdict, verdict))}
		}
	}
	if activityCount == 0 || decisionCount != activityCount {
		return "pending", Outcome{Status: UV, Message: "one or more activities lack replayable decisions"}
	}
	return "+R", Outcome{Status: Pass, Message: "all activity decisions replay"}
}

func computeGrade(res *Result) {
	if res.Checks["a"].Status == UV {
		res.Ungraded = true
		res.Notes = append(res.Notes, "AEL-0 capped: signature verification is UV")
		return
	}
	if !allPass(res.Checks, "a", "b", "d", "e") {
		res.Ungraded = true
		res.Notes = append(res.Notes, "AEL-0 capped: authentic ordered canonical record chain not established")
		return
	}
	res.Grade = 0
	if res.Open {
		res.Notes = append(res.Notes, "AEL-1 capped: OPEN/ABNORMAL-END")
		return
	}
	if !allPass(res.Checks, "f", "g", "h", "i") {
		res.Notes = append(res.Notes, firstCap("AEL-1 capped", res.Checks, "f", "g", "h", "i"))
		return
	}
	res.Grade = 1
	if !allPass(res.Checks, "k", "l", "m") {
		res.Notes = append(res.Notes, firstCap("AEL-2 capped", res.Checks, "k", "l", "m"))
		return
	}
	res.Grade = 2
	if !allPass(res.Checks, "n", "o", "u") {
		res.Notes = append(res.Notes, firstCap("AEL-3 capped", res.Checks, "n", "o", "u"))
		return
	}
	if !allPass(res.Checks, "p", "q") {
		res.Notes = append(res.Notes, firstCap("AEL-3 capped", res.Checks, "p", "q"))
		return
	}
	res.Grade = 3
	if !allPass(res.Checks, "r", "s", "t", "v") {
		res.Notes = append(res.Notes, firstCap("AEL-4 capped", res.Checks, "r", "s", "t", "v"))
		return
	}
	res.Grade = 4
}

func allPass(checks map[string]Outcome, ids ...string) bool {
	for _, id := range ids {
		if checks[id].Status != Pass {
			return false
		}
	}
	return true
}

func firstCap(prefix string, checks map[string]Outcome, ids ...string) string {
	for _, id := range ids {
		out := checks[id]
		if out.Status != Pass {
			return fmt.Sprintf("%s: check %s is %s (%s)", prefix, id, out.Status, out.Message)
		}
	}
	return prefix
}

func anchorAnnotation(art *Artifact) string {
	if art.Manifest.Anchor == nil {
		return "none"
	}
	if art.Manifest.Anchor.Log == "" {
		return "declared"
	}
	return art.Manifest.Anchor.Log
}

func retentionAnnotation(r Retention) string {
	if r.PeriodDays == 0 && r.Custody == "" {
		return "unknown"
	}
	return fmt.Sprintf("%dd/%s", r.PeriodDays, emptyAsUnknown(r.Custody))
}

func logsForArtifactRun(art *Artifact) []*RecorderLog {
	run := artifactRun(art)
	var logs []*RecorderLog
	for _, log := range art.RecorderLogs {
		if run == "" || log.Run == run {
			logs = append(logs, log)
		}
	}
	return logs
}

func artifactRun(art *Artifact) string {
	if len(art.Manifest.Runs) > 0 {
		return art.Manifest.Runs[0]
	}
	if len(art.RecorderLogs) > 0 {
		return art.RecorderLogs[0].Run
	}
	return ""
}

func recorderAEL1(log *RecorderLog) Outcome {
	if len(log.Records) == 0 {
		return Outcome{Status: Fail, Message: "no records"}
	}
	for i, rec := range log.Records {
		if rec.SignatureUV {
			return Outcome{Status: UV, Message: recordMsg(rec, rec.SignatureErr)}
		}
		if !rec.SignatureOK || !rec.CanonicalOK {
			return Outcome{Status: Fail, Message: recordMsg(rec, firstErr(rec.SignatureErr, rec.CanonicalErr))}
		}
		if rec.Payload.Seq != i {
			return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("seq=%d, want %d", rec.Payload.Seq, i))}
		}
		if i == 0 {
			if rec.Payload.Type != "open" || rec.Payload.Prev != zeroPrev || rec.Payload.HMax <= 0 {
				return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("invalid AEL-1 open"))}
			}
			continue
		}
		if rec.Payload.Prev != log.Records[i-1].Hash {
			return Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("prev=%s, want %s", rec.Payload.Prev, log.Records[i-1].Hash))}
		}
	}
	hmax := log.Records[0].Payload.HMax
	htol := log.Records[0].Payload.HTol
	limit := time.Duration(hmax+htol) * time.Second
	for i := 1; i < len(log.Records); i++ {
		prevTS, err := log.Records[i-1].Payload.Time()
		if err != nil {
			return Outcome{Status: Fail, Message: recordMsg(log.Records[i-1], err)}
		}
		curTS, err := log.Records[i].Payload.Time()
		if err != nil {
			return Outcome{Status: Fail, Message: recordMsg(log.Records[i], err)}
		}
		if curTS.Sub(prevTS) > limit {
			return Outcome{Status: Fail, Message: recordMsg(log.Records[i], fmt.Errorf("gap %s exceeds %s", curTS.Sub(prevTS), limit))}
		}
	}
	closeRec := log.Records[len(log.Records)-1]
	if closeRec.Payload.Type != "close" || closeRec.Payload.Count != len(log.Records) {
		return Outcome{Status: Fail, Message: recordMsg(closeRec, fmt.Errorf("invalid close count"))}
	}
	if closeRec.Payload.Count < 2 || closeRec.Payload.Head != log.Records[closeRec.Payload.Count-2].Hash {
		return Outcome{Status: Fail, Message: recordMsg(closeRec, fmt.Errorf("invalid close head"))}
	}
	return Outcome{Status: Pass}
}

func verifiedRecorderKey(log *RecorderLog) (string, Outcome) {
	if len(log.Records) == 0 {
		return "", Outcome{Status: Fail, Message: fmt.Sprintf("%s has no records; recorder signing key is not established", log.ID)}
	}
	var key string
	for _, rec := range log.Records {
		if rec.SignatureUV {
			return "", Outcome{Status: UV, Message: recordMsg(rec, rec.SignatureErr)}
		}
		if !rec.SignatureOK {
			return "", Outcome{Status: Fail, Message: recordMsg(rec, firstErr(rec.SignatureErr, fmt.Errorf("record signature is not verified")))}
		}
		recKey := strings.ToLower(rec.Payload.Key)
		if recKey == "" {
			return "", Outcome{Status: Fail, Message: recordMsg(rec, fmt.Errorf("record key fingerprint is empty"))}
		}
		if key == "" {
			key = recKey
			continue
		}
		if recKey != key {
			return "", Outcome{Status: Fail, Message: fmt.Sprintf("recorder %s records carry differing signing keys %s and %s", log.ID, key, recKey)}
		}
	}
	if log.Key != "" && strings.ToLower(log.Key) != key {
		return "", Outcome{Status: Fail, Message: fmt.Sprintf("recorder %s manifest declares key %s but records are signed by %s", log.ID, log.Key, key)}
	}
	return key, Outcome{Status: Pass}
}

func coveredEvents(log *RecorderLog, classes map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, rec := range log.Records {
		if rec.Payload.Type != "activity" || rec.Payload.Event == nil {
			continue
		}
		if classes[rec.Payload.Event.Class] {
			out[rec.Payload.Event.ID] = true
		}
	}
	return out
}

func stringSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, item := range items {
		out[item] = true
	}
	return out
}

func decodeHex32(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, err
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("got %d bytes, want %d", len(raw), sha256.Size)
	}
	return raw, nil
}

func merkleRootFromProof(leaf []byte, index, size int, proof [][]byte) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("tree size must be positive")
	}
	if index < 0 || index >= size {
		return nil, fmt.Errorf("index %d outside tree size %d", index, size)
	}
	root, used, err := merkleRootFromProofAt(leaf, index, size, proof)
	if err != nil {
		return nil, err
	}
	if used != len(proof) {
		return nil, fmt.Errorf("proof has %d extra nodes", len(proof)-used)
	}
	return root, nil
}

func merkleRootFromProofAt(leaf []byte, index, size int, proof [][]byte) ([]byte, int, error) {
	if size == 1 {
		return append([]byte(nil), leaf...), 0, nil
	}
	split := largestPowerOfTwoLessThan(size)
	if index < split {
		left, used, err := merkleRootFromProofAt(leaf, index, split, proof)
		if err != nil {
			return nil, 0, err
		}
		if used >= len(proof) {
			return nil, 0, fmt.Errorf("proof is missing right sibling")
		}
		return merkleNode(left, proof[used]), used + 1, nil
	}
	right, used, err := merkleRootFromProofAt(leaf, index-split, size-split, proof)
	if err != nil {
		return nil, 0, err
	}
	if used >= len(proof) {
		return nil, 0, fmt.Errorf("proof is missing left sibling")
	}
	return merkleNode(proof[used], right), used + 1, nil
}

func merkleLeafHex(raw []byte) string {
	sum := sha256.Sum256(append([]byte{0x00}, raw...))
	return hex.EncodeToString(sum[:])
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

func findRecord(art *Artifact, recorder, run string, seq int) *Record {
	for _, log := range art.RecorderLogs {
		if log.ID != recorder || log.Run != run {
			continue
		}
		for _, rec := range log.Records {
			if rec.Payload.Seq == seq {
				return rec
			}
		}
	}
	return nil
}

func runNonce(art *Artifact, run string) string {
	nonces := map[string]bool{}
	for _, log := range art.RecorderLogs {
		if log.Run != run || len(log.Records) == 0 {
			continue
		}
		if log.Records[0].Payload.Type == "open" && log.Records[0].Payload.CPNonce != "" {
			nonces[log.Records[0].Payload.CPNonce] = true
		}
	}
	for nonce := range nonces {
		return nonce
	}
	return ""
}

func recordMsg(rec *Record, err error) string {
	if err == nil {
		return fmt.Sprintf("%s:%d", rec.File, rec.LineNo)
	}
	return fmt.Sprintf("%s:%d: %v", rec.File, rec.LineNo, err)
}

func counterpartyMsg(stmt *CounterpartyStatement, err error) string {
	if err == nil {
		return fmt.Sprintf("%s:%d", stmt.File, stmt.LineNo)
	}
	return fmt.Sprintf("%s:%d: %v", stmt.File, stmt.LineNo, err)
}
