package scim

import (
	"reflect"
	"strings"
	"testing"
)

func TestSCIMMultiValuedProfileLimits(t *testing.T) {
	user := func(fields map[string]any) (Profile, error) {
		fields["schemas"], fields["userName"] = []any{UserSchema}, "limits@example.test"
		return normalize(fields)
	}
	p, err := user(map[string]any{
		"phoneNumbers": []any{map[string]any{"value": " +1 555 0100 ", "type": " WORK ", "primary": "TRUE"}},
		"addresses":    []any{map[string]any{"streetAddress": "1 Main St", "locality": "London", "type": " Work ", "primary": false}},
		"entitlements": []any{map[string]any{"value": " reports ", "display": "Reports", "type": "License"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Attributes["phoneNumbers"], []any{map[string]any{"value": "+1 555 0100", "type": "work", "primary": true}}) {
		t.Fatal("phone numbers were not trimmed, typed and given a Boolean primary", p.Attributes["phoneNumbers"])
	}
	if !reflect.DeepEqual(p.Attributes["addresses"], []any{map[string]any{"streetAddress": "1 Main St", "locality": "London", "type": "work", "primary": false}}) {
		t.Fatal("an address lost a field or its explicit false primary", p.Attributes["addresses"])
	}
	if !reflect.DeepEqual(p.Attributes["entitlements"], []any{map[string]any{"value": "reports", "display": "Reports", "type": "license"}}) {
		t.Fatal("entitlements were not normalized like roles", p.Attributes["entitlements"])
	}
	eleven := make([]any, 11)
	for i := range eleven {
		eleven[i] = map[string]any{"value": "+1 555 01" + string(rune('0'+i%10))}
	}
	for _, c := range []struct {
		failure string
		fields  map[string]any
	}{
		{"eleven phone numbers were accepted", map[string]any{"phoneNumbers": eleven}},
		{"two primary phone numbers were accepted", map[string]any{"phoneNumbers": []any{map[string]any{"value": "1", "primary": true}, map[string]any{"value": "2", "primary": "true"}}}},
		{"a phone number without a value was accepted", map[string]any{"phoneNumbers": []any{map[string]any{"type": "work"}}}},
		{"a scalar phoneNumbers value was accepted", map[string]any{"phoneNumbers": "x"}},
		{"an address without an address field was accepted", map[string]any{"addresses": []any{map[string]any{"type": "work", "primary": true}}}},
		{"an overlong address country was accepted", map[string]any{"addresses": []any{map[string]any{"country": strings.Repeat("x", 257)}}}},
		{"duplicate entitlement types were accepted", map[string]any{"entitlements": []any{map[string]any{"value": "a", "type": "X"}, map[string]any{"value": "b", "type": "x"}}}},
		{"an overlong displayName was accepted", map[string]any{"displayName": strings.Repeat("😀", 1025)}},
	} {
		if _, err := user(c.fields); err == nil {
			t.Fatal(c.failure)
		}
	}
	// Limits count code points, so a name of astral characters another
	// runtime accepts is accepted here too.
	if p, err := user(map[string]any{"displayName": strings.Repeat("😀", 1024)}); err != nil || p.DisplayName != strings.Repeat("😀", 1024) {
		t.Fatal("a displayName of 1024 code points was refused", err)
	}
}
