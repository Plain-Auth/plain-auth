package bearer_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
)

func TestBearerSessions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		require bool
	}{{"signed-only", true}, {"signed-and-raw", false}} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "http://localhost", EmailAndPassword: true, Plugins: []auth.Plugin{bearer.New(bearer.Options{RequireSignature: tc.require})}})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "/api/auth/sign-up/email", strings.NewReader(`{"name":"Ada","email":"ada@example.test","password":"test-password"}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			w.Header().Set("Access-Control-Expose-Headers", "ETag")
			a.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("signup: %s", w.Body)
			}
			var result auth.AuthResult
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			signed := w.Header().Get("Set-Auth-Token")
			if signed == "" || strings.Join(w.Header().Values("Access-Control-Expose-Headers"), ",") != "ETag,set-auth-token" {
				t.Fatal("missing response token or exposed headers")
			}
			lookup := func(token string) *auth.SessionResult {
				h := http.Header{}
				h.Set("Authorization", "Bearer "+token)
				s, err := a.GetSession(context.Background(), h)
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			if lookup(signed) == nil || (lookup(result.Token) != nil) == tc.require || lookup(signed+"X") != nil {
				t.Fatal("credential policy mismatch")
			}
			h := http.Header{"Authorization": {"bEaReR " + signed}}
			if err := a.SignOut(context.Background(), h); err != nil {
				t.Fatal(err)
			}
			if lookup(signed) != nil {
				t.Fatal("revoked bearer session still valid")
			}
		})
	}
}

func TestIssuedBearerPreservesOpaqueToken(t *testing.T) {
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	token := "imported.%2F+opaque"
	cookie := a.SessionCookie(token, true)
	headers := http.Header{}
	plugin := bearer.New(bearer.Options{RequireSignature: true})
	plugin.OnSessionCookie(auth.SessionCookieEvent{Auth: a, Header: headers, Cookie: *cookie})
	wire := headers.Get("Set-Auth-Token")
	if !strings.HasSuffix(wire, "=") || a.VerifySignedSessionToken(wire) != token {
		t.Fatal("opaque token did not survive bearer issuance")
	}
}
