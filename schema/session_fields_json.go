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
	fields, err := readFields(r, "session")
	if err != nil {
		return nil, err
	}
	return sessionfields.Normalize(fields)
}

// ReadUserFields reads a profile declaration file, applying the same scalar,
// reserved-name and column mapping rules as configured user profiles.
func ReadUserFields(r io.Reader) (map[string]UserField, error) {
	fields, err := readFields(r, "user")
	if err != nil {
		return nil, err
	}
	return sessionfields.NormalizeUser(fields)
}

// ReadAccountFields reads field declarations for provider and credential accounts.
func ReadAccountFields(r io.Reader) (map[string]AccountField, error) {
	fields, err := readFields(r, "account")
	if err != nil {
		return nil, err
	}
	return sessionfields.NormalizeAccount(fields)
}

func readFields(r io.Reader, model string) (map[string]sessionfields.Field, error) {
	d := json.NewDecoder(r)
	d.UseNumber()
	if err := startFieldObject(d); err != nil {
		return nil, err
	}
	fields := make(map[string]sessionfields.Field)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string)
		if _, used := fields[name]; used {
			return nil, fmt.Errorf("duplicate %s field %q", model, name)
		}
		field, err := readFieldDefinition(d, model, name)
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
		return nil, fmt.Errorf("expected exactly one %s fields JSON object", model)
	}
	return fields, nil
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

func readFieldDefinition(d *json.Decoder, model, name string) (sessionfields.Field, error) {
	var f sessionfields.Field
	if err := startFieldObject(d); err != nil {
		return f, fmt.Errorf("%s field %q: %w", model, name, err)
	}
	seen := make(map[string]bool)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return f, err
		}
		k := key.(string)
		if seen[k] {
			return f, fmt.Errorf("duplicate property %q on %s field %q", k, model, name)
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
				return f, fmt.Errorf("%s field %q property %q requires a string", model, name, k)
			}
			if k == "type" {
				f.Type = sessionfields.Type(v)
			} else {
				f.Column = v
			}
		case "required", "serverOnly", "hidden":
			v, ok := value.(bool)
			if !ok {
				return f, fmt.Errorf("%s field %q property %q requires a boolean", model, name, k)
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
				return f, fmt.Errorf("%s field %q requires a scalar default", model, name)
			}
			f.Default = value
		default:
			return f, fmt.Errorf("unknown property %q on %s field %q", k, model, name)
		}
	}
	if _, err := d.Token(); err != nil {
		return f, err
	}
	if seen["default"] && f.Default == nil && f.Required {
		return f, fmt.Errorf("required %s field %q cannot default to null", model, name)
	}
	return f, nil
}
