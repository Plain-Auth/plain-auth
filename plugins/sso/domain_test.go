package sso

import (
	"errors"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestDomainVerificationNameBounds(t *testing.T) {
	opts, err := (DomainVerificationOptions{}).normalized()
	if err != nil || opts.identifier("company") != "_plain-auth-token-company" {
		t.Fatalf("default TXT owner: %v", err)
	}
	if _, err := (DomainVerificationOptions{TokenPrefix: "tenant.child"}).normalized(); err == nil {
		t.Fatal("accepted a prefix spanning multiple labels")
	}
	label := "_" + strings.Repeat("x", 59) + "-id"
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 61)
	if len(label) != 63 || len(label+"."+name) != 253 {
		t.Fatal("incorrect boundary fixture")
	}
	got, err := DomainTargets("id", label, strings.ToUpper(name))
	if err != nil || len(got) != 1 || got[0] != name {
		t.Fatal("rejected fully qualified 253-byte name", got, err)
	}
	for _, v := range []struct{ id, identifier, name, code string }{
		{"id", label, name + "d", "INVALID_DOMAIN"},
		{"id", "_" + label, name, "IDENTIFIER_TOO_LONG"},
		{"nested.id", "_tenant-nested.id", "example.org", "INVALID_VERIFICATION_IDENTIFIER"},
		{"id", "_tenant-other", "example.org", "INVALID_VERIFICATION_IDENTIFIER"},
		{"id", "_tenant-id", "example.org,https://other.example/", "INVALID_DOMAIN"},
	} {
		_, err := DomainTargets(v.id, v.identifier, v.name)
		var api *auth.APIError
		if !errors.As(err, &api) || api.Code != v.code {
			t.Errorf("%q: expected %s, got %v", v.identifier, v.code, err)
		}
	}
}
