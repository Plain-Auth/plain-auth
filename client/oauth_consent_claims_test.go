package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Plain-Org/plain-auth/client"
)

func TestDecideOAuthConsentWithClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims []string
		want   any
	}{
		{"original", nil, nil},
		{"decline individual claims", []string{}, map[string]any{"userinfo": map[string]any{}}},
		{"approve email", []string{"email"}, map[string]any{"userinfo": map[string]any{"email": nil}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				if r.Method != "POST" || r.URL.Path != "/api/auth/oauth2/consent" {
					t.Fatal("unexpected consent endpoint", r.URL)
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				got, present := body["claims"]
				if present != (tc.claims != nil) || !reflect.DeepEqual(got, tc.want) || body["scope"] != "openid" || body["accept"] != true || body["oauth_query"] != "signed" {
					t.Fatal("wrong consent selection", body)
				}
				out := httptest.NewRecorder()
				out.Header().Set("Content-Type", "application/json")
				_, _ = out.WriteString(`{"url":"https://app.example.test/done"}`)
				return out.Result(), nil
			})}
			c, err := client.New("https://issuer.example.test", wire)
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.DecideOAuthConsentWithClaims(t.Context(), "signed", true, []string{"openid"}, tc.claims)
			if err != nil || result != "https://app.example.test/done" {
				t.Fatal(result, err)
			}
		})
	}
}
