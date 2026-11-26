package sso

import (
	"encoding/json"
	"errors"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
)

// Provider field names may not shadow the built-in columns or the keys of
// provider requests and responses.
func TestProviderFieldNames(t *testing.T) {
	for _, field := range []map[string]ProviderField{
		{"domain": {Type: auth.FieldString}},
		{"type": {Type: auth.FieldString}},
		{"redirectURI": {Type: auth.FieldString}},
		{"tier": {Type: auth.FieldString, Column: "issuer"}},
	} {
		if _, err := New(Options{ProviderAdditionalFields: field}); err == nil {
			t.Fatal("a provider field shadowing a built-in key was accepted", field)
		}
	}
	if _, err := New(Options{ProviderAdditionalFields: map[string]ProviderField{"tier": {Type: auth.FieldString}}}); err != nil {
		t.Fatal("a provider field was refused", err)
	}
}

// A value of the right JSON type that the column cannot hold says why,
// instead of naming the type it already has.
func TestProviderFieldValueMessage(t *testing.T) {
	o := Options{ProviderAdditionalFields: map[string]ProviderField{"seats": {Type: auth.FieldNumber}}}
	for _, raw := range []any{1.5, json.Number("1.5")} {
		_, err := o.providerFieldInput(map[string]any{"seats": raw}, true)
		var e *auth.APIError
		if !errors.As(err, &e) || e.Status != 400 || e.Code != "VALIDATION_ERROR" || e.Message != "[body.seats] expected a signed 32-bit integer" {
			t.Fatal("a fractional number field was not refused with its reason", raw, err)
		}
	}
	_, err := o.providerFieldInput(map[string]any{"seats": "two"}, true)
	if err == nil || err.Error() != "[body.seats] Invalid input: expected number, received string" {
		t.Fatal("a mistyped number field was not refused in the body validation form", err)
	}
}
