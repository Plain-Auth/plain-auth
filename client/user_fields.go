package client

import (
	"encoding/json"
	"fmt"

	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

func profileInput(fields map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		if !sessionfields.UserNameOK(k) {
			return nil, fmt.Errorf("invalid additional user field %q", k)
		}
		out[k] = v
	}
	return out, nil
}

func (r SignUpRequest) MarshalJSON() ([]byte, error) {
	type wire SignUpRequest
	return marshalProfileInput(wire(r), r.AdditionalFields)
}

func marshalProfileInput(base any, additional map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil || len(additional) == 0 {
		return raw, err
	}
	fields, err := profileInput(additional)
	if err != nil {
		return nil, err
	}
	var standard map[string]json.RawMessage
	if err := json.Unmarshal(raw, &standard); err != nil {
		return nil, err
	}
	for k, v := range standard {
		if _, duplicate := fields[k]; duplicate {
			return nil, fmt.Errorf("additional user field %q conflicts with a request field", k)
		}
		fields[k] = v
	}
	return json.Marshal(fields)
}
