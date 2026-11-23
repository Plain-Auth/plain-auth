package schema_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestReadUserFieldProfile(t *testing.T) {
	const input = `{"locale":{"type":"string","column":"locale_value","default":""},"flag":{"type":"boolean","required":true,"serverOnly":true,"hidden":true,"default":false},"rank":{"type":"number","default":0e-3},"memo":{"type":"string","default":null}}`
	fields, err := schema.ReadUserFields(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]plainauth.UserField{
		"locale": {Type: plainauth.FieldString, Column: "locale_value", Default: ""},
		"flag":   {Type: plainauth.FieldBoolean, Column: "flag", Default: false, Hidden: true, ServerOnly: true, Required: true},
		"rank":   {Type: plainauth.FieldNumber, Column: "rank", Default: int64(0)},
		"memo":   {Type: plainauth.FieldString, Column: "memo"},
	}
	if !reflect.DeepEqual(want, fields) {
		t.Fatalf("profile declarations: %#v", fields)
	}
	for _, bad := range []string{
		`null`, `{}` + `{}`, `{"a":null}`, `{"a":{"type":"string","extra":0}}`, `{"a":{"type":"string","hidden":0}}`,
		`{"a":{"type":"string","required":true,"default":null}}`, `{"a":{"type":"number","default":1.00000000000000001}}`,
		`{"a":{"type":"number","default":2147483648}}`, `{"a":{"type":"string","default":[]}}`, `{"a":{"type":"string","type":"string"}}`,
		`{"a":{"type":"string"},"a":{"type":"string"}}`, `{"a":{"type":"string","column":"eMaiL"}}`, `{"role":{"type":"string"}}`,
		`{"a":{"type":"boolean","column":"b"},"B":{"type":"boolean"}}`,
	} {
		if _, err := schema.ReadUserFields(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted invalid user declarations %s", bad)
		}
	}
	// The session model can attach a field called email; the user already owns that column.
	if _, err := schema.ReadSessionFields(strings.NewReader(`{"email":{"type":"string"}}`)); err != nil {
		t.Fatal(err)
	}
}
