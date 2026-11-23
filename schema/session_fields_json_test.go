package schema_test

import (
	"reflect"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestReadSessionFieldFile(t *testing.T) {
	raw := `{"locale":{"type":"string","column":"preferred_locale","required":true,"default":"en"},"count":{"type":"number","default":-2147483648,"serverOnly":true},"optIn":{"type":"boolean","default":false,"hidden":true},"note":{"type":"string","default":null}}`
	got, e := schema.ReadSessionFields(strings.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]auth.SessionField{"locale": {Type: auth.FieldString, Column: "preferred_locale", Required: true, Default: "en"}, "count": {Type: auth.FieldNumber, Column: "count", Default: int64(-2147483648), ServerOnly: true}, "optIn": {Type: auth.FieldBoolean, Column: "optIn", Default: false, Hidden: true}, "note": {Type: auth.FieldString, Column: "note"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wrong session field configuration: %#v", got)
	}
	for _, bad := range []string{"", `null`, `[]`, `{}{}`, `{"region":{}}`, `{"region":null}`, `{"region":1}`, `{"id":{"type":"string"}}`, `{"region":{"type":"text"}}`, `{"region":{"Type":"string"}}`, `{"region":{"type":"string","unknown":true}}`, `{"region":{"type":"string","required":1}}`, `{"region":{"type":"string","hidden":null}}`, `{"region":{"type":"string","column":false}}`, `{"region":{"type":"string","default":[]}}`, `{"region":{"type":"string","default":true}}`, `{"region":{"type":"string","required":true,"default":null}}`, `{"region":{"type":"number","default":2147483648}}`, `{"region":{"type":"number","default":1.5}}`, `{"region":{"type":"number","default":1.00000000000000001}}`, `{"region":{"type":"string"},"region":{"type":"boolean"}}`, `{"region":{"type":"string","type":"boolean"}}`, `{"region":{"type":"string","column":"USERID"}}`, `{"one":{"type":"string","column":"duplicate"},"two":{"type":"string","column":"DUPLICATE"}}`, `{"region":{"type":"string"}`} {
		if _, err := schema.ReadSessionFields(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted invalid field file %s", bad)
		}
	}
}
