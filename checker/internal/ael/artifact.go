package ael

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Manifest struct {
	AELFormat      int                `json:"ael_format"`
	Runs           []string           `json:"runs"`
	Recorders      []ManifestRecorder `json:"recorders"`
	ClaimedRung    int                `json:"claimed_rung"`
	Coverage       string             `json:"coverage"`
	Custody        string             `json:"custody"`
	Retention      Retention          `json:"retention"`
	Correspondence *Correspondence    `json:"correspondence,omitempty"`
	Anchor         *AnchorDecl        `json:"anchor,omitempty"`
	Counterparty   *CounterpartyDecl  `json:"counterparty,omitempty"`
}

type ManifestRecorder struct {
	ID   string `json:"id"`
	Run  string `json:"run"`
	Key  string `json:"key"`
	File string `json:"file"`
}

type Retention struct {
	PeriodDays int    `json:"period_days"`
	Custody    string `json:"custody"`
}

type Correspondence struct {
	Classes []string `json:"classes"`
	Match   string   `json:"match"`
}

type AnchorDecl struct {
	Log    string `json:"log"`
	LogKey string `json:"log_key"`
	File   string `json:"file"`
}

type CounterpartyDecl struct {
	File  string   `json:"file"`
	Flows []string `json:"flows"`
	Key   string   `json:"key"`
}

type Anchors struct {
	Log      string        `json:"log"`
	TreeHead TreeHead      `json:"tree_head"`
	Entries  []AnchorEntry `json:"entries"`
}

type TreeHead struct {
	Size   int    `json:"size"`
	Root   string `json:"root"`
	Sig    string `json:"sig"`
	Signed string `json:"signed"`
}

type AnchorEntry struct {
	Recorder string   `json:"recorder"`
	Run      string   `json:"run"`
	Seq      int      `json:"seq"`
	Leaf     string   `json:"leaf"`
	Index    int      `json:"index"`
	Proof    []string `json:"proof"`
}

type CounterpartyPayload struct {
	V        int               `json:"v"`
	Type     string            `json:"type"`
	Run      string            `json:"run"`
	Flow     string            `json:"flow"`
	Nonce    string            `json:"nonce"`
	Received map[string]string `json:"received,omitempty"`
	None     bool              `json:"none,omitempty"`
}

type CounterpartyStatement struct {
	Line         string
	File         string
	LineNo       int
	PayloadRaw   []byte
	Signature    []byte
	Payload      CounterpartyPayload
	LineErr      error
	ParseErr     error
	CanonicalErr error
	CanonicalOK  bool
	SchemaErr    error
	SchemaOK     bool
	SignatureOK  bool
	SignatureUV  bool
	SignatureErr error
}

type RecorderLog struct {
	ID      string
	Run     string
	Key     string
	File    string
	Records []*Record
}

type Artifact struct {
	Dir                 string
	KeysDir             string
	ManifestRaw         []byte
	Manifest            Manifest
	ManifestErr         error
	ManifestCanon       bool
	Keys                map[string]ed25519.PublicKey
	RecorderLogs        []*RecorderLog
	Anchors             *Anchors
	AnchorsRaw          []byte
	AnchorsErr          error
	Counterparty        []*CounterpartyStatement
	CounterpartyMissing bool
	CounterpartyErr     error
	Policies            map[string]*PolicyDoc
	PolicyRaw           map[string][]byte
	PolicyLoadErrs      map[string]error
}

func LoadArtifact(dir, keysDir string) (*Artifact, error) {
	art := &Artifact{
		Dir:            dir,
		KeysDir:        keysDir,
		Keys:           map[string]ed25519.PublicKey{},
		Policies:       map[string]*PolicyDoc{},
		PolicyRaw:      map[string][]byte{},
		PolicyLoadErrs: map[string]error{},
	}

	keys, err := loadKeys(keysDir)
	if err != nil {
		return nil, err
	}
	art.Keys = keys

	manifestPath := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	art.ManifestRaw = raw
	canon, err := Canonicalize(raw)
	if err != nil {
		art.ManifestErr = err
	} else {
		art.ManifestCanon = string(canon) == string(raw)
		if !art.ManifestCanon {
			art.ManifestErr = fmt.Errorf("manifest.json is not canonical")
		}
	}
	if err := json.Unmarshal(raw, &art.Manifest); err != nil {
		art.ManifestErr = err
	}
	if art.ManifestErr != nil {
		return nil, fmt.Errorf("manifest: %w", art.ManifestErr)
	}

	for _, rec := range art.Manifest.Recorders {
		log, err := loadRecorderLog(dir, rec)
		if err != nil {
			return nil, err
		}
		for _, record := range log.Records {
			record.Verify(art.Keys)
		}
		art.RecorderLogs = append(art.RecorderLogs, log)
	}

	if err := art.loadPolicies(); err != nil {
		return nil, err
	}
	art.loadAnchors()
	art.loadCounterparty()
	return art, nil
}

func loadKeys(keysDir string) (map[string]ed25519.PublicKey, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		// A missing keys directory means no keys were published out of band,
		// which is the same posture as an empty directory: nothing to verify
		// against, so dependent checks resolve to UNABLE-TO-VERIFY rather than
		// crashing. (Git does not track empty directories, so a fixture with an
		// intentionally-empty keys dir arrives here as "not found" on a fresh
		// clone.)
		if os.IsNotExist(err) {
			return map[string]ed25519.PublicKey{}, nil
		}
		return nil, fmt.Errorf("read keys dir: %w", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(keysDir, entry.Name()))
		if err != nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		if len(decoded) != ed25519.PublicKeySize {
			continue
		}
		sum := sha256.Sum256(decoded)
		fp := hex.EncodeToString(sum[:])
		nameFP := strings.TrimSuffix(entry.Name(), ".pub")
		if strings.ToLower(nameFP) != fp {
			continue
		}
		keys[fp] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

func loadRecorderLog(root string, rec ManifestRecorder) (*RecorderLog, error) {
	if rec.File == "" || filepath.IsAbs(rec.File) || strings.Contains(rec.File, "..") {
		return nil, fmt.Errorf("unsafe recorder file path %q", rec.File)
	}
	path := filepath.Join(root, rec.File)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recorder %s: %w", rec.File, err)
	}
	defer func() { _ = f.Close() }()

	log := &RecorderLog{ID: rec.ID, Run: rec.Run, Key: strings.ToLower(rec.Key), File: rec.File}
	sc := bufio.NewScanner(f)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		record, err := ParseRecordLine(line, rec.File, lineNo)
		if err != nil {
			return nil, err
		}
		log.Records = append(log.Records, record)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan recorder %s: %w", rec.File, err)
	}
	return log, nil
}

func (a *Artifact) loadPolicies() error {
	policyDir := filepath.Join(a.Dir, "policy")
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read policy dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		raw, err := os.ReadFile(filepath.Join(policyDir, entry.Name()))
		if err != nil {
			a.PolicyLoadErrs[name] = err
			continue
		}
		a.PolicyRaw[name] = raw
		pol, err := ParsePolicy(raw)
		if err != nil {
			a.PolicyLoadErrs[name] = err
			continue
		}
		a.Policies[name] = pol
	}
	return nil
}

func (a *Artifact) loadAnchors() {
	if a.Manifest.Anchor == nil {
		return
	}
	path, err := safeArtifactPath(a.Dir, a.Manifest.Anchor.File)
	if err != nil {
		a.AnchorsErr = err
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		a.AnchorsErr = err
		return
	}
	a.AnchorsRaw = raw
	canon, err := Canonicalize(raw)
	if err != nil {
		a.AnchorsErr = fmt.Errorf("anchors canonicalize: %w", err)
		return
	}
	if string(canon) != string(raw) {
		a.AnchorsErr = fmt.Errorf("anchors.json is not canonical")
		return
	}
	var anchors Anchors
	if err := json.Unmarshal(raw, &anchors); err != nil {
		a.AnchorsErr = err
		return
	}
	a.Anchors = &anchors
}

func (a *Artifact) loadCounterparty() {
	if a.Manifest.Counterparty == nil {
		return
	}
	path, err := safeArtifactPath(a.Dir, a.Manifest.Counterparty.File)
	if err != nil {
		a.CounterpartyErr = err
		return
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.CounterpartyMissing = true
			return
		}
		a.CounterpartyErr = err
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		stmt := parseCounterpartyLine(line, a.Manifest.Counterparty.File, lineNo)
		stmt.Verify(a.Keys, strings.ToLower(a.Manifest.Counterparty.Key))
		a.Counterparty = append(a.Counterparty, stmt)
	}
	if err := sc.Err(); err != nil {
		a.CounterpartyErr = fmt.Errorf("scan counterparty %s: %w", a.Manifest.Counterparty.File, err)
	}
}

func safeArtifactPath(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return "", fmt.Errorf("unsafe artifact file path %q", rel)
	}
	return filepath.Join(root, rel), nil
}

func parseCounterpartyLine(line, file string, lineNo int) *CounterpartyStatement {
	stmt := &CounterpartyStatement{Line: line, File: file, LineNo: lineNo}
	if !compactLineRE.MatchString(line) {
		stmt.LineErr = fmt.Errorf("malformed compact counterparty line")
		return stmt
	}
	parts := strings.Split(line, ".")
	payload, err := decodeCompactBase64(parts[0])
	if err != nil {
		stmt.LineErr = fmt.Errorf("decode payload: %w", err)
		return stmt
	}
	sig, err := decodeCompactBase64(parts[1])
	if err != nil {
		stmt.LineErr = fmt.Errorf("decode signature: %w", err)
		return stmt
	}
	stmt.PayloadRaw = payload
	stmt.Signature = sig
	if err := json.Unmarshal(payload, &stmt.Payload); err != nil {
		stmt.ParseErr = err
	}
	return stmt
}

func (s *CounterpartyStatement) Verify(keys map[string]ed25519.PublicKey, fp string) {
	if s.LineErr != nil || s.ParseErr != nil {
		s.SignatureErr = firstErr(s.LineErr, s.ParseErr)
		return
	}
	pub, ok := keys[strings.ToLower(fp)]
	if !ok {
		s.SignatureUV = true
		s.SignatureErr = fmt.Errorf("missing published counterparty key %s", fp)
		return
	}
	if len(s.Signature) != ed25519.SignatureSize {
		s.SignatureErr = fmt.Errorf("signature length %d", len(s.Signature))
		return
	}
	if !ed25519.Verify(pub, s.PayloadRaw, s.Signature) {
		s.SignatureErr = fmt.Errorf("counterparty signature verification failed")
		return
	}
	s.SignatureOK = true
	canon, err := Canonicalize(s.PayloadRaw)
	if err != nil {
		s.CanonicalErr = err
		return
	}
	if string(canon) != string(s.PayloadRaw) {
		s.CanonicalErr = fmt.Errorf("counterparty payload is not canonical")
		return
	}
	s.CanonicalOK = true
	if err := validateObjectSchema(s.PayloadRaw, map[string]bool{
		"v": true, "type": true, "run": true, "flow": true, "nonce": true,
		"received": true, "none": true, "ext": true,
	}, []string{"v", "type", "run", "flow", "nonce"}); err != nil {
		s.SchemaErr = err
		return
	}
	s.SchemaOK = true
}

func (a *Artifact) AllRecords() []*Record {
	var out []*Record
	for _, log := range a.RecorderLogs {
		out = append(out, log.Records...)
	}
	return out
}

func (a *Artifact) ForRun(run string) *Artifact {
	view := *a
	view.Manifest.Runs = []string{run}
	view.RecorderLogs = nil
	for _, log := range a.RecorderLogs {
		if log.Run == run {
			view.RecorderLogs = append(view.RecorderLogs, log)
		}
	}
	if a.Anchors != nil {
		anchors := *a.Anchors
		anchors.Entries = nil
		for _, entry := range a.Anchors.Entries {
			if entry.Run == run {
				anchors.Entries = append(anchors.Entries, entry)
			}
		}
		view.Anchors = &anchors
	}
	return &view
}
