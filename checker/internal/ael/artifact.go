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

type RecorderLog struct {
	ID      string
	Run     string
	Key     string
	File    string
	Records []*Record
}

type Artifact struct {
	Dir            string
	KeysDir        string
	ManifestRaw    []byte
	Manifest       Manifest
	ManifestErr    error
	ManifestCanon  bool
	Keys           map[string]ed25519.PublicKey
	RecorderLogs   []*RecorderLog
	Policies       map[string]*PolicyDoc
	PolicyRaw      map[string][]byte
	PolicyLoadErrs map[string]error
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
	}
	if err := json.Unmarshal(raw, &art.Manifest); err != nil {
		art.ManifestErr = err
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
	return art, nil
}

func loadKeys(keysDir string) (map[string]ed25519.PublicKey, error) {
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil, fmt.Errorf("read keys dir: %w", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pub") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(keysDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", entry.Name(), err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("decode key %s: %w", entry.Name(), err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %s has %d bytes, want %d", entry.Name(), len(decoded), ed25519.PublicKeySize)
		}
		sum := sha256.Sum256(decoded)
		fp := hex.EncodeToString(sum[:])
		nameFP := strings.TrimSuffix(entry.Name(), ".pub")
		if strings.ToLower(nameFP) != fp {
			return nil, fmt.Errorf("key %s fingerprint mismatch, computed %s", entry.Name(), fp)
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
	defer f.Close()

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

func (a *Artifact) AllRecords() []*Record {
	var out []*Record
	for _, log := range a.RecorderLogs {
		out = append(out, log.Records...)
	}
	return out
}
