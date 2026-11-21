// Package scimjson encodes values with the string escaping used by SCIM directory records and keys.
package scimjson

import (
	"bytes"
	"encoding/json"
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
