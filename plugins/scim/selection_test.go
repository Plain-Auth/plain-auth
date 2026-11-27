package scim

import (
	"errors"
	"net/url"
	"reflect"
	"testing"
)

func TestSCIMUserResponseSelectionTree(t *testing.T) {
	resource := func() map[string]any {
		return map[string]any{
			"schemas": []any{UserSchema}, "id": "u1", "userName": "ada@example.test",
			"name":   map[string]any{"givenName": "Ada", "familyName": "King"},
			"emails": []any{map[string]any{"value": "a@example.test", "type": "work", "primary": true}, map[string]any{"value": "b@example.test", "type": "home", "primary": false}},
			"roles":  []any{map[string]any{"value": "admin"}},
			"meta":   map[string]any{"resourceType": "User"},
		}
	}
	selected := func(q url.Values) (map[string]any, error) {
		s, err := selectionQuery(q, UserSchema)
		if err != nil {
			return nil, err
		}
		return s.apply(resource()), nil
	}
	got, err := selected(url.Values{"attributes": {"name.givenName,EMAILS.value"}})
	if err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1", "name": map[string]any{"givenName": "Ada"},
		"emails": []any{map[string]any{"value": "a@example.test"}, map[string]any{"value": "b@example.test"}}}) {
		t.Fatal("a nested include selection returned the wrong fields", got, err)
	}
	got, err = selected(url.Values{"excludedAttributes": {"name.givenName,emails.type,meta"}})
	if err != nil || got["userName"] != "ada@example.test" || got["meta"] != nil || !reflect.DeepEqual(got["name"], map[string]any{"familyName": "King"}) ||
		!reflect.DeepEqual(got["emails"], []any{map[string]any{"value": "a@example.test", "primary": true}, map[string]any{"value": "b@example.test", "primary": false}}) {
		t.Fatal("a nested exclusion returned the wrong fields", got, err)
	}
	if got, err = selected(url.Values{"attributes": {"urn:ietf:params:scim:schemas:core:2.0:User:userName"}}); err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1", "userName": "ada@example.test"}) {
		t.Fatal("a core-qualified selection was not applied", got, err)
	}
	if got, err = selected(url.Values{"attributes": {"unknownThing"}}); err != nil || !reflect.DeepEqual(got, map[string]any{"schemas": []any{UserSchema}, "id": "u1"}) {
		t.Fatal("an unknown selection path was not ignored", got, err)
	}
	for _, q := range []url.Values{{"attributes": {"user Name"}}, {"attributes": {"userName,"}}, {"excludedAttributes": {"a,,b"}}, {"attributes": {"a"}, "excludedAttributes": {"b"}}} {
		if _, err := selected(q); err == nil || err.(*Error).Type != "invalidValue" {
			t.Fatal("an invalid selection was accepted", q, err)
		}
	}
	// Inner whitespace follows JavaScript: the byte order mark counts and
	// NEXT LINE does not.
	if _, err := selected(url.Values{"attributes": {"user\uFEFFName"}}); err == nil {
		t.Fatal("a selection path with an inner byte order mark was accepted")
	}
	if got, err = selected(url.Values{"attributes": {"user\u0085Name"}}); err != nil || len(got) != 2 {
		t.Fatal("a selection path with an inner NEXT LINE was refused", got, err)
	}
	if got, err = selected(url.Values{"attributes": {" "}, "excludedAttributes": {"meta"}}); err != nil || got["meta"] != nil || got["userName"] == nil {
		t.Fatal("an empty attributes parameter blocked the exclusion", got, err)
	}
	if got, err = selected(url.Values{"excludedAttributes": {"roles.value"}}); err != nil || !reflect.DeepEqual(got["roles"], []any{map[string]any{}}) {
		t.Fatal("excluding roles.value dropped role entries", got, err)
	}
	if s, _ := selectionQuery(url.Values{"attributes": {"members.value"}}, GroupSchema); !s.returns("members") || s.returns("displayName") {
		t.Fatal("a member subattribute selection did not load members alone")
	}
	if s, _ := selectionQuery(url.Values{"excludedAttributes": {"members"}}, GroupSchema); s.returns("members") || !s.returns("displayName") {
		t.Fatal("excluding members still loaded them")
	}
}

// Filters support only equality joined by "and", as another runtime does;
// every other operator is refused as invalidFilter.
func TestUnsupportedFilterOperators(t *testing.T) {
	for _, filter := range []string{`userName eq "a" or userName eq "b"`, `not (userName eq "a")`, `userName pr`, `userName ne "a"`, `meta.created gt "2026-01-01"`,
		`userName sw "a"`, `(userName eq "a")`, `userName co "a"`, `userName ew "a"`, `userName ge "a"`, `userName lt "a"`, `userName le "a"`} {
		_, err := query(url.Values{"filter": {filter}}, equality)
		var e *Error
		if !errors.As(err, &e) || e.Status != 400 || e.Type != "invalidFilter" {
			t.Fatal("an unsupported filter operator was accepted", filter, err)
		}
	}
	if q, err := query(url.Values{"filter": {`userName eq "a" and externalId eq "b"`}}, equality); err != nil || len(q.Filters) != 2 {
		t.Fatal("an and of equalities was refused", err)
	}
}

// Page parameters follow another runtime's grammar and order: startIndex
// is reported before count, a plus sign or a non-JavaScript space is
// refused, a BOM is trimmed and any safe integer is accepted.
func TestQueryPageParameters(t *testing.T) {
	for _, c := range []struct {
		values url.Values
		detail string
	}{
		{url.Values{"startIndex": {"x"}, "count": {"y"}}, "startIndex must be an integer"},
		{url.Values{"startIndex": {"+2"}}, "startIndex must be an integer"},
		{url.Values{"startIndex": {"\u00852"}}, "startIndex must be an integer"},
		{url.Values{"count": {"9007199254740992"}}, "count must be an integer"},
		{url.Values{"count": {"1.5"}}, "count must be an integer"},
	} {
		for range 20 {
			if _, err := query(c.values, equality); err == nil || err.Error() != c.detail {
				t.Fatal("a page parameter was not refused with its name", c.values, err)
			}
		}
	}
	q, err := query(url.Values{"startIndex": {"\uFEFF2"}, "count": {"4503599627370496"}}, equality)
	if err != nil || q.Offset != 1 || q.Count != 100 {
		t.Fatal("a trimmed or large safe page parameter was refused", q, err)
	}
	if q, err = query(url.Values{"startIndex": {"-5"}, "count": {"-0"}}, equality); err != nil || q.Offset != 0 || q.Count != 0 {
		t.Fatal("negative page parameters were not clamped", q, err)
	}
}
