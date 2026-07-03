package ael

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var compactLineRE = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

type Event struct {
	Class string `json:"class"`
	ID    string `json:"id"`
	Dir   string `json:"dir"`
}

type Decision struct {
	Policy    string         `json:"policy"`
	RequestFP string         `json:"request_fp"`
	Inputs    map[string]any `json:"inputs"`
	Verdict   string         `json:"verdict"`
}

type Payload struct {
	V        int       `json:"v"`
	Type     string    `json:"type"`
	Run      string    `json:"run"`
	Recorder string    `json:"recorder"`
	Key      string    `json:"key"`
	Seq      int       `json:"seq"`
	Prev     string    `json:"prev"`
	TS       string    `json:"ts"`
	HMax     int       `json:"hmax,omitempty"`
	HTol     int       `json:"htol,omitempty"`
	CPNonce  string    `json:"cp_nonce,omitempty"`
	Event    *Event    `json:"event,omitempty"`
	Decision *Decision `json:"decision,omitempty"`
	Count    int       `json:"count,omitempty"`
	Head     string    `json:"head,omitempty"`
}

func (p Payload) Time() (time.Time, error) {
	return time.Parse(time.RFC3339, p.TS)
}

type Record struct {
	Line         string
	File         string
	LineNo       int
	PayloadRaw   []byte
	Signature    []byte
	Payload      Payload
	LineErr      error
	ParseErr     error
	CanonicalErr error
	CanonicalOK  bool
	SchemaErr    error
	SchemaOK     bool
	SignatureOK  bool
	SignatureUV  bool
	SignatureErr error
	Hash         string
}

func ParseRecordLine(line, file string, lineNo int) (*Record, error) {
	rec := &Record{Line: line, File: file, LineNo: lineNo}
	if !compactLineRE.MatchString(line) {
		rec.LineErr = fmt.Errorf("malformed compact record line")
		return rec, nil
	}
	parts := strings.Split(line, ".")
	payload, err := decodeCompactBase64(parts[0])
	if err != nil {
		rec.LineErr = fmt.Errorf("decode payload: %w", err)
		return rec, nil
	}
	sig, err := decodeCompactBase64(parts[1])
	if err != nil {
		rec.LineErr = fmt.Errorf("decode signature: %w", err)
		return rec, nil
	}
	rec.PayloadRaw = payload
	rec.Signature = sig
	sum := sha256.Sum256(payload)
	rec.Hash = hex.EncodeToString(sum[:])

	if err := json.Unmarshal(payload, &rec.Payload); err != nil {
		rec.ParseErr = err
	}
	return rec, nil
}

func (r *Record) Verify(keys map[string]ed25519.PublicKey) {
	if r.LineErr != nil || r.ParseErr != nil {
		r.SignatureErr = firstErr(r.LineErr, r.ParseErr)
		return
	}
	pub, ok := keys[strings.ToLower(r.Payload.Key)]
	if !ok {
		r.SignatureUV = true
		r.SignatureErr = fmt.Errorf("missing published key %s", r.Payload.Key)
		return
	}
	if len(r.Signature) != ed25519.SignatureSize {
		r.SignatureErr = fmt.Errorf("signature length %d", len(r.Signature))
		return
	}
	if !ed25519.Verify(pub, r.PayloadRaw, r.Signature) {
		r.SignatureErr = fmt.Errorf("signature verification failed")
		return
	}
	r.SignatureOK = true

	canon, err := Canonicalize(r.PayloadRaw)
	if err != nil {
		r.CanonicalErr = err
		return
	}
	if string(canon) != string(r.PayloadRaw) {
		r.CanonicalErr = fmt.Errorf("payload is not canonical")
		return
	}
	r.CanonicalOK = true
	if err := validateRecordPayloadSchema(r.PayloadRaw, r.Payload.Type); err != nil {
		r.SchemaErr = err
		return
	}
	r.SchemaOK = true
}

func decodeCompactBase64(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, fmt.Errorf("non-canonical base64url segment")
	}
	return raw, nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
