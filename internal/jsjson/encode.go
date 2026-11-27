// Package jsjson encodes Go values using JSON.stringify string escaping.
package jsjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
)

func Marshal(value any) ([]byte, error) {
	// JSON.stringify emits HTML and U+2028/U+2029 literally. Do not replace
	// escaped backslashes in strings that contain a literal Unicode escape.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	data := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	var canonical bytes.Buffer
	for i := 0; i < len(data); i++ {
		if data[i] == '\\' && i+1 < len(data) {
			if bytes.HasPrefix(data[i:], []byte(`\u2028`)) {
				canonical.WriteRune('\u2028')
				i += 5
				continue
			}
			if bytes.HasPrefix(data[i:], []byte(`\u2029`)) {
				canonical.WriteRune('\u2029')
				i += 5
				continue
			}
			canonical.WriteByte(data[i])
			i++
		}
		canonical.WriteByte(data[i])
	}
	return canonical.Bytes(), nil
}

// TrimSpace applies ECMAScript whitespace rules to directory text.
func TrimSpace(s string) string {
	return strings.TrimFunc(s, IsSpace)
}

// IsSpace reports ECMAScript whitespace, which includes the byte order mark
// and excludes NEXT LINE.
func IsSpace(r rune) bool { return r == '\uFEFF' || r != '\u0085' && unicode.IsSpace(r) }

// TypeName describes a value from a JSON request for validation errors.
func TypeName(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case []any:
		return "array"
	case json.Number, float64:
		return "number"
	default:
		return "object"
	}
}

// Truthy reports whether a decoded JSON value is truthy in JavaScript: a
// non-empty string, a non-zero number, true, or any object or array.
func Truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0
	case json.Number:
		f, err := v.Float64()
		return err != nil || f != 0
	default:
		return true
	}
}
