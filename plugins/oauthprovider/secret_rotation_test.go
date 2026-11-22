package oauthprovider

import (
	"encoding/json"
	"testing"
)

func TestRotatedClientWireCredential(t *testing.T) {
	for _, raw := range []string{`{"client_id":"a"}`, `{"client_secret":null}`, `{"client_secret":""}`, `{"CLIENT_SECRET":"invalid"}`, `{"client_secret":7}`} {
		var c RotatedClient
		if json.Unmarshal([]byte(raw), &c) == nil {
			t.Fatal("accepted an absent or invalid replacement credential")
		}
	}
	var c RotatedClient
	if err := json.Unmarshal([]byte(`{"client_id":"a","client_secret":"new","CLIENT_SECRET":"extension","clientSecret":"private","label":"metadata"}`), &c); err != nil {
		t.Fatal(err)
	}
	c.Extensions["client_secret"] = json.RawMessage(`"forged"`)
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if c.ClientSecret != "new" || string(wire["client_secret"]) != `"new"` || wire["clientSecret"] != nil || string(wire["label"]) != `"metadata"` {
		t.Fatal("opaque metadata overrode a reserved credential field")
	}
}
