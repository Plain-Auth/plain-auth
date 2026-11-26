package scim

import (
	"reflect"
	"strings"
	"testing"
)

func TestSCIMEnterpriseUserProfileNormalization(t *testing.T) {
	user := func(fields map[string]any) (Profile, error) {
		if _, ok := fields["schemas"]; !ok {
			fields["schemas"] = []any{UserSchema, EnterpriseUserSchema}
		}
		fields["userName"] = "boss@example.test"
		return normalize(fields)
	}
	p, err := user(map[string]any{"schemas": []any{EnterpriseUserSchema, UserSchema}})
	if err != nil || !reflect.DeepEqual(p.Attributes["schemas"], []any{UserSchema, EnterpriseUserSchema}) {
		t.Fatal("the User schema list was not reordered core first", p.Attributes["schemas"], err)
	}
	for _, schemas := range [][]any{{UserSchema, EnterpriseUserSchema, EnterpriseUserSchema}, {UserSchema, UserSchema}, {EnterpriseUserSchema}, {UserSchema, "urn:example:custom"}} {
		if _, err := user(map[string]any{"schemas": schemas}); err == nil {
			t.Fatal("an invalid User schema list was accepted", schemas)
		}
	}
	p, err = user(map[string]any{strings.ToUpper(EnterpriseUserSchema): map[string]any{"Department": "R&D", "employeeNumber": []any{" 42 "}, "unknown": "x"}})
	if err != nil || !reflect.DeepEqual(p.Attributes["enterprise"], map[string]any{"department": "R&D", "employeeNumber": "42"}) {
		t.Fatal("a differently cased Enterprise key or attribute was ignored, or a one-element value was not unwrapped", p.Attributes["enterprise"], err)
	}
	if _, err := user(map[string]any{EnterpriseUserSchema: map[string]any{"department": strings.Repeat("é", 1025)}}); err == nil {
		t.Fatal("an overlong department was accepted")
	}
	if _, err := user(map[string]any{EnterpriseUserSchema: map[string]any{"department": strings.Repeat("😀", 1024)}}); err != nil {
		t.Fatal("a department of 1024 code points was refused", err)
	}
	if _, err := user(map[string]any{EnterpriseUserSchema: map[string]any{"department": "a", "Department": "b"}}); err == nil || err.(*Error).Type != "invalidSyntax" {
		t.Fatal("an Enterprise object naming department twice was not invalidSyntax", err)
	}
	// A nested all-null value leaves the object unassigned, as another
	// runtime strips it.
	for _, extension := range []map[string]any{{"department": map[string]any{"value": nil}}, {"manager": map[string]any{"$ref": map[string]any{"x": nil}}}} {
		if p, err := user(map[string]any{"schemas": []any{UserSchema}, EnterpriseUserSchema: extension}); err != nil || p.Attributes["enterprise"] != nil {
			t.Fatal("an Enterprise object holding only nested nulls was not treated as omitted", extension, err)
		}
	}
	for _, extension := range []map[string]any{{"department": nil, "Department": nil}, {"manager": map[string]any{"value": nil, "VALUE": nil}}} {
		if _, err := user(map[string]any{"schemas": []any{UserSchema}, EnterpriseUserSchema: extension}); err == nil || err.(*Error).Type != "invalidSyntax" {
			t.Fatal("an all-null Enterprise object naming a field twice was not invalidSyntax", extension, err)
		}
	}
	if _, err := user(map[string]any{"schemas": []any{UserSchema}, EnterpriseUserSchema: map[string]any{"department": "R&D"}}); err == nil {
		t.Fatal("an Enterprise object without its schema URI was accepted")
	}
	p, err = user(map[string]any{"schemas": []any{UserSchema}, EnterpriseUserSchema: map[string]any{"department": nil, "manager": map[string]any{"value": nil, "$ref": nil}}})
	if _, stored := p.Attributes["enterprise"]; err != nil || stored {
		t.Fatal("an all-null Enterprise object was stored or needed its schema URI", p.Attributes, err)
	}
	p, err = user(map[string]any{EnterpriseUserSchema: map[string]any{"manager": map[string]any{"displayName": "Boss"}}})
	if err != nil || !reflect.DeepEqual(p.Attributes["enterprise"], map[string]any{}) {
		t.Fatal("a declared Enterprise object without fields was not stored empty", p.Attributes["enterprise"], err)
	}
	for _, c := range []struct {
		manager any
		want    map[string]any
	}{
		{"m-1", map[string]any{"value": "m-1"}},
		{[]any{map[string]any{"value": " m-2 ", "$ref": "https://directory.example.test/Users/m-2", "displayName": "Boss"}}, map[string]any{"value": "m-2", "$ref": "https://directory.example.test/Users/m-2"}},
		{map[string]any{"$ref": "https://directory.example.test/Users/m-3"}, map[string]any{"$ref": "https://directory.example.test/Users/m-3"}},
	} {
		p, err = user(map[string]any{EnterpriseUserSchema: map[string]any{"manager": c.manager}})
		if err != nil || !reflect.DeepEqual(p.Attributes["enterprise"], map[string]any{"manager": c.want}) {
			t.Fatal("a manager was not stored in its canonical form", c.manager, p.Attributes["enterprise"], err)
		}
	}
	for _, manager := range []any{"", []any{"m-1"}, []any{map[string]any{"value": "a"}, map[string]any{"value": "b"}}, map[string]any{"value": strings.Repeat("x", 257)}} {
		if _, err := user(map[string]any{EnterpriseUserSchema: map[string]any{"manager": manager}}); err == nil {
			t.Fatal("an invalid manager was accepted", manager)
		}
	}
	p, _ = user(map[string]any{EnterpriseUserSchema: map[string]any{"department": "R&D"}})
	if m := profileObject(p); m["enterprise"] != nil || !reflect.DeepEqual(m[EnterpriseUserSchema], map[string]any{"department": "R&D"}) {
		t.Fatal("the Enterprise extension was not returned under its URN", m)
	}
}
