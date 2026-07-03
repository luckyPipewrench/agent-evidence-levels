package ael

import (
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
	for _, id := range []string{"k", "l", "m", "n", "o", "p", "q", "r", "s", "t"} {
		checks[id] = Outcome{Status: UV, Message: "not evaluated in Run 1"}
	}
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
	if !allPass(res.Checks, "n", "o") {
		res.Notes = append(res.Notes, firstCap("AEL-3 capped", res.Checks, "n", "o"))
		return
	}
	res.Grade = 3
	if !allPass(res.Checks, "r", "s", "t") {
		res.Notes = append(res.Notes, firstCap("AEL-4 capped", res.Checks, "r", "s", "t"))
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

func recordMsg(rec *Record, err error) string {
	if err == nil {
		return fmt.Sprintf("%s:%d", rec.File, rec.LineNo)
	}
	return fmt.Sprintf("%s:%d: %v", rec.File, rec.LineNo, err)
}
