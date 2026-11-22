package client

import (
	"encoding/json"
	"fmt"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
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
	raw, err := json.Marshal(wire(r))
	if err != nil || len(r.AdditionalFields) == 0 {
		return raw, err
	}
	fields, err := profileInput(r.AdditionalFields)
	if err != nil {
		return nil, err
	}
	var standard map[string]json.RawMessage
	if err := json.Unmarshal(raw, &standard); err != nil {
		return nil, err
	}
	for k, v := range standard {
		fields[k] = v
	}
	return json.Marshal(fields)
}
