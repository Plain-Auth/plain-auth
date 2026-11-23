package client_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/client"
	jwtplugin "github.com/Plain-Org/plain-auth/plugins/jwt"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestNativeJWTClient(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"jwt"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(ctx, "sqlite", ":memory:", ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	plugin, err := jwtplugin.New(jwtplugin.Options{})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://tokens.test"
	a, err := auth.New(auth.Options{Store: store, BaseURL: origin, Secret: "native-client-test-key-00000000000000", EmailAndPassword: true, Plugins: []auth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(origin+"/api/auth", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w.Result(), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := c.JWKS(ctx, "")
	if err != nil || len(keys.Keys) != 1 || !keys.Keys[0].IsPublic() {
		t.Fatal("anonymous discovery failed", err)
	}
	if _, err := c.JWT(ctx); err == nil {
		t.Fatal("anonymous signing accepted")
	}
	if _, err := c.SignUpEmail(ctx, client.SignUpRequest{Email: "a@example.test", Name: "A", Password: "local-test-credential"}); err != nil {
		t.Fatal(err)
	}
	token, err := c.JWT(ctx)
	if err != nil || token == "" {
		t.Fatal("client issuance failed", err)
	}
}
