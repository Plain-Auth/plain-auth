package openapi_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/openapi"
	"github.com/Plain-Auth/plain-auth/plugins/passkey"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestPasskeyEnrollmentContract(t *testing.T) {
	ddl, err := schema.Generate("sqlite", []string{"passkey"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(t.Context(), "sqlite", ":memory:", ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, preauth := range []bool{false, true} {
		plugin, err := passkey.New(passkey.Options{RPID: "localhost", RPName: "Local", Origins: []string{"http://localhost"}, Registration: passkey.RegistrationOptions{AllowWithoutSession: preauth}})
		if err != nil {
			t.Fatal(err)
		}
		docs, err := openapi.New(openapi.Options{})
		if err != nil {
			t.Fatal(err)
		}
		a, err := auth.New(auth.Options{Store: store, BaseURL: "http://localhost", Secret: strings.Repeat("s", 48), Plugins: []auth.Plugin{plugin, docs}})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost/api/auth/open-api/generate-schema", nil))
		var document obj
		if err = json.Unmarshal(w.Body.Bytes(), &document); err != nil {
			t.Fatal(err)
		}
		for _, step := range []struct{ path, method string }{{"/passkey/generate-register-options", "get"}, {"/passkey/verify-registration", "post"}} {
			op := node(document, "paths", step.path, step.method)
			public := false
			for _, rule := range op["security"].([]any) {
				if len(rule.(obj)) == 0 {
					public = true
				}
			}
			if public != preauth {
				t.Fatal("registration access policy differs from installed plugin")
			}
		}
		verify := node(document, "paths", "/passkey/verify-registration", "post")
		create := node(verify, "requestBody", "content", "application/json", "schema", "properties", "createSession")
		if create["type"] != "boolean" || create["const"] != nil {
			t.Fatal("session creation is incorrectly excluded")
		}
	}
}
