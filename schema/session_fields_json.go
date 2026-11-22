package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

// SessionField describes one custom session column and its application policy.
// The type is shared with plainauth.SessionField.
type SessionField = sessionfields.Field

// ReadSessionFields reads a JSON object keyed by logical field name. Definitions
// accept type, column, default, required, serverOnly and hidden. Configuration
// is validated using the same rules as session issuance and schema generation.
func ReadSessionFields(r io.Reader) (map[string]SessionField, error) {
	d := json.NewDecoder(r)
	d.UseNumber()
	if err := startFieldObject(d); err != nil {
		return nil, err
	}
	fields := make(map[string]SessionField)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string)
		if _, used := fields[name]; used {
			return nil, fmt.Errorf("duplicate session field %q", name)
		}
		field, err := readFieldDefinition(d, name)
		if err != nil {
			return nil, err
		}
		fields[name] = field
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("expected exactly one session fields JSON object")
	}
	return sessionfields.Normalize(fields)
}

func startFieldObject(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	return nil
}

func readFieldDefinition(d *json.Decoder, name string) (SessionField, error) {
	var f SessionField
	if err := startFieldObject(d); err != nil {
		return f, fmt.Errorf("session field %q: %w", name, err)
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return f, err
		}
		k := key.(string)
		if seen[k] {
			return f, fmt.Errorf("duplicate property %q on session field %q", k, name)
		}
		seen[k] = true
		value, err := d.Token()
		if err != nil {
			return f, err
		}
		switch k {
		case "type", "column":
			v, ok := value.(string)
			if !ok {
				return f, fmt.Errorf("session field %q property %q requires a string", name, k)
			}
			if k == "type" {
				f.Type = sessionfields.Type(v)
			} else {
				f.Column = v
			}
		case "required", "serverOnly", "hidden":
			v, ok := value.(bool)
			if !ok {
				return f, fmt.Errorf("session field %q property %q requires a boolean", name, k)
			}
			switch k {
			case "required":
				f.Required = v
			case "serverOnly":
				f.ServerOnly = v
			case "hidden":
				f.Hidden = v
			}
		case "default":
			if _, compound := value.(json.Delim); compound {
				return f, fmt.Errorf("session field %q requires a scalar default", name)
			}
			f.Default = value
		default:
			return f, fmt.Errorf("unknown property %q on session field %q", k, name)
		}
	}
	if _, err := d.Token(); err != nil {
		return f, err
	}
	if seen["default"] && f.Default == nil && f.Required {
		return f, fmt.Errorf("required session field %q cannot default to null", name)
	}
	return f, nil
}
