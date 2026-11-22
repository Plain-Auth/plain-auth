package oauthprovider_test

import (
	"encoding/json"
	"reflect"
	"testing"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

func TestResourceIdentifiers(t *testing.T) {
	for _, id := range []string{"urn:example:billing", "https://api.example.test/a%2Fb?region=1", "http://localhost:8181", "custom:reports"} {
		if !op.ValidResourceIdentifier(id) {
			t.Errorf("rejected absolute resource identifier %q", id)
		}
	}
	for _, id := range []string{"", "audience", "/reports", "//api.example.test", "http://", "https://api.example.test/#", "urn:example:x#part", "https://api.example.test?q=%xy", "JavaScript:disabled", "data:example", "vbscript:disabled"} {
		if op.ValidResourceIdentifier(id) {
			t.Errorf("accepted invalid resource identifier %q", id)
		}
	}
}

func TestResourcePolicyPatch(t *testing.T) {
	for _, input := range []string{`{}`, `{"name":"","disabled":false}`, `{"allowedScopes":null}`, `{"allowedScopes":[]}`, `{"allowedScopes":["","reports:read"]}`, `{"metadata":{},"accessTokenTtl":42,"signingKeyId":null}`} {
		var p op.ResourcePatch
		if err := json.Unmarshal([]byte(input), &p); err != nil {
			t.Fatal(input, err)
		}
		output, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var in, out map[string]any
		if err := json.Unmarshal([]byte(input), &in); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(output, &out); err != nil || !reflect.DeepEqual(in, out) {
			t.Fatalf("patch round trip changed %s to %s", input, output)
		}
	}
	for _, input := range []string{`{"name":null}`, `{"disabled":null}`, `{"dpopBoundAccessTokensRequired":null}`, `{"signingAlgorithm":"HS256"}`, `{"accessTokenTtl":-1}`, `{"refreshTokenTtl":2147483648}`, `{"allowedScopes":[null]}`, `{"metadata":[]}`} {
		var p op.ResourcePatch
		if err := json.Unmarshal([]byte(input), &p); err == nil {
			r := op.Resource{Name: "Original"}
			if err := p.Apply(&r); err == nil || r.Name != "Original" {
				t.Errorf("invalid policy accepted or partially applied: %s", input)
			}
		}
	}
	for _, alg := range []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"} {
		p := op.ResourcePatch{SigningAlgorithm: op.Set(alg)}
		var r op.Resource
		if err := p.Apply(&r); err != nil || r.SigningAlgorithm == nil || *r.SigningAlgorithm != alg {
			t.Fatal("unexpected signing policy", alg, err)
		}
	}
}
