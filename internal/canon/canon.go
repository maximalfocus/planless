// Package canon produces a canonical JSON encoding and SHA-256 digests over it.
//
// Every claim about platform state in this project is a byte comparison, so the
// encoding has to be stable: object keys sorted, no HTML escaping, numbers
// preserved exactly as written, and no incidental whitespace.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Marshal encodes v as canonical JSON.
func Marshal(v any) ([]byte, error) {
	raw, err := encode(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canon: decode: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("canon: unexpected trailing content")
	}
	var out bytes.Buffer
	if err := write(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canon: encode: %w", err)
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		s, err := encodeString(t)
		if err != nil {
			return err
		}
		buf.Write(s)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			s, err := encodeString(k)
			if err != nil {
				return err
			}
			buf.Write(s)
			buf.WriteByte(':')
			if err := write(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canon: unsupported value %T", v)
	}
	return nil
}

func encodeString(s string) ([]byte, error) {
	b, err := encode(s)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(b, "\n"), nil
}

// Digest returns the SHA-256 digest of raw bytes, rendered for transcripts.
//
// A digest identifies an artifact. It says nothing about who produced it.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestOf canonically encodes v and digests the result.
func DigestOf(v any) (string, error) {
	b, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}
