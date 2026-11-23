package openapi_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/openapi"
)

func TestConfigurableSessionFieldSchemas(t *testing.T) {
	fields := map[string]auth.SessionField{
		"locale":     {Type: auth.FieldString, Required: true, Default: "sensitive-default", Column: "session_locale"},
		"generation": {Type: auth.FieldNumber, ServerOnly: true},
		"comment":    {Type: auth.FieldString, Hidden: true},
		"secretRank": {Type: auth.FieldNumber, Hidden: true, ServerOnly: true},
	}
	store, err := sqlstore.OpenWithSessionFields(t.Context(), "sqlite", filepath.Join(t.TempDir(), "schema.sqlite"), nil, fields)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	api, err := openapi.New(openapi.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://sessions.example.test"
	host, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Store: store, Secret: strings.Repeat("s", 40), EmailAndPassword: true, Plugins: []auth.Plugin{api}, SessionAdditionalFields: fields})
	if err != nil {
		t.Fatal(err)
	}
	wire := ssoWire{t, host, origin}
	doc := wire.decode(wire.call("GET", "/open-api/generate-schema", nil, nil, 200))
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"secretRank", "session_locale", "sensitive-default"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("public API reference included a private field detail", private)
		}
	}
	session := node(doc, "components", "schemas", "Session")
	out := node(session, "properties")
	required, _ := session["required"].([]any)
	if !slices.Contains(required, any("locale")) || out["generation"] == nil || out["comment"] != nil || node(out, "locale")["type"] != "string" {
		t.Fatal("session response fields", session)
	}
	op := node(doc, "paths", "/update-session", "post")
	in := node(op, "requestBody", "content", "application/json", "schema", "properties")
	sec, _ := op["security"].([]any)
	if len(in) != 2 || in["locale"] == nil || in["comment"] == nil || len(sec) != 1 || sec[0].(obj)["apiKeyCookie"] == nil {
		t.Fatal("session field request contract", op)
	}
	if node(op, "responses", "200", "content", "application/json", "schema", "properties", "session")["$ref"] != "#/components/schemas/Session" {
		t.Fatal("incorrect session response reference")
	}
	wire.call("POST", "/update-session", obj{"locale": "fr"}, nil, 401)
	account := wire.decode(wire.call("POST", "/sign-up/email", obj{"name": "Owner", "email": "owner@schema.test", "password": "a fixture password"}, nil, 200))
	h := http.Header{"Cookie": {host.SessionCookie(account["token"].(string), true).String()}}
	got := node(wire.decode(wire.call("POST", "/update-session", obj{"locale": "fr", "comment": "private"}, h, 200)), "session")
	if got["locale"] != "fr" || got["comment"] != nil {
		t.Fatal("live session violates documented projection")
	}
	wire.call("POST", "/update-session", obj{"locale": "ignored", "generation": 9}, h, 400)
}
