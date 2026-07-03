package ael

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const maxSafeInteger = int64(1<<53 - 1)

// Canonicalize parses raw JSON with duplicate-key rejection and emits the
// restricted JCS form used by AEL v0.1.
func Canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	v, err := parseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing JSON data")
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON token %v", tok)
		}
		return nil, err
	}

	var out bytes.Buffer
	if err := writeCanonical(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// IsCanonical reports whether raw is accepted by Canonicalize and byte-equal to
// the canonical representation.
func IsCanonical(raw []byte) bool {
	canon, err := Canonicalize(raw)
	return err == nil && bytes.Equal(raw, canon)
}

type jsonObject map[string]any

func parseJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return parseTokenValue(dec, tok)
}

func parseTokenValue(dec *json.Decoder, tok any) (any, error) {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := jsonObject{}
			seen := map[string]struct{}{}
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := ktok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is %T, not string", ktok)
				}
				if _, dup := seen[key]; dup {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				val, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim('}') {
				return nil, fmt.Errorf("object closed by %v", end)
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				val, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(']') {
				return nil, fmt.Errorf("array closed by %v", end)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", t)
		}
	case json.Number:
		return parseCanonicalInteger(t.String())
	case string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported JSON token %T", tok)
	}
}

func parseCanonicalInteger(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty number")
	}
	if strings.ContainsAny(s, ".eE+") {
		return 0, fmt.Errorf("non-integer number %q", s)
	}
	if s == "-0" {
		return 0, errors.New("negative zero is non-canonical")
	}
	body := s
	if strings.HasPrefix(body, "-") {
		body = body[1:]
		if body == "" {
			return 0, fmt.Errorf("invalid number %q", s)
		}
	}
	if len(body) > 1 && body[0] == '0' {
		return 0, fmt.Errorf("leading zero in number %q", s)
	}
	for _, r := range body {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid integer %q", s)
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < -maxSafeInteger || n > maxSafeInteger {
		return 0, fmt.Errorf("integer %q outside safe range", s)
	}
	return n, nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		writeJSONString(out, t)
	case int:
		out.WriteString(strconv.Itoa(t))
	case int64:
		if t < -maxSafeInteger || t > maxSafeInteger {
			return fmt.Errorf("integer %d outside safe range", t)
		}
		out.WriteString(strconv.FormatInt(t, 10))
	case float64:
		if math.Trunc(t) != t || t < float64(-maxSafeInteger) || t > float64(maxSafeInteger) {
			return fmt.Errorf("non-canonical number %v", t)
		}
		out.WriteString(strconv.FormatInt(int64(t), 10))
	case []any:
		out.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		return writeCanonicalObject(out, t)
	case jsonObject:
		return writeCanonicalObject(out, map[string]any(t))
	default:
		return fmt.Errorf("unsupported canonical value %T", v)
	}
	return nil
}

func writeCanonicalObject(out *bytes.Buffer, obj map[string]any) error {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j]) < 0
	})

	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		writeJSONString(out, key)
		out.WriteByte(':')
		if err := writeCanonical(out, obj[key]); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

func compareUTF16(a, b string) int {
	ar := utf16.Encode([]rune(a))
	br := utf16.Encode([]rune(b))
	for i := 0; i < len(ar) && i < len(br); i++ {
		if ar[i] < br[i] {
			return -1
		}
		if ar[i] > br[i] {
			return 1
		}
	}
	switch {
	case len(ar) < len(br):
		return -1
	case len(ar) > len(br):
		return 1
	default:
		return 0
	}
}

func writeJSONString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '\\' && c != '"' {
				i++
				continue
			}
			out.WriteString(s[start:i])
			switch c {
			case '\\', '"':
				out.WriteByte('\\')
				out.WriteByte(c)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				out.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				out.WriteByte(hex[c>>4])
				out.WriteByte(hex[c&0x0f])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out.WriteString(s[start:i])
			out.WriteString(`\ufffd`)
			i++
			start = i
			continue
		}
		i += size
	}
	out.WriteString(s[start:])
	out.WriteByte('"')
}
