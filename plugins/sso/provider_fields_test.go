package sso

import (
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
