package goapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// CustomSyntheticUser shapes the user returned for a sign-up with an email
// that already exists, keeping exactly a real sign-up's public fields.
func TestCustomSyntheticUser(t *testing.T) {
	off := false
	var got authn.SyntheticUser
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		DisableAutoSignIn: true,
		UserAdditionalFields: map[string]authn.UserField{
			"locale": {Type: authn.FieldString, Default: "en"},
			"note":   {Type: authn.FieldString, Hidden: true},
		},
		CustomSyntheticUser: func(u authn.SyntheticUser) map[string]any {
			got = u
			return map[string]any{"id": u.ID, "name": u.Name, "email": u.Email, "emailVerified": u.EmailVerified, "image": u.Image,
				"createdAt": u.CreatedAt, "updatedAt": u.UpdatedAt, "locale": "fr", "plan": "free", "note": "leaked"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signUp := func() map[string]any {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"email":"Ada@Example.com","password":"correct horse battery","name":"Ada"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		var body struct {
			Token any            `json:"token"`
			User  map[string]any `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Token != nil {
			t.Fatal(body, err)
		}
		return body.User
	}
	real := signUp()
	if got.ID != "" {
		t.Fatal("the hook ran for a new account")
	}
	fake := signUp()
	if got.ID == "" || got.ID == real["id"] || got.Email != "ada@example.com" || got.Name != "Ada" || got.EmailVerified || got.AdditionalFields["locale"] != "en" {
		t.Fatalf("the hook received %+v", got)
	}
	// The hook sets the values of real fields; a hidden or unknown key is dropped.
	if fake["id"] != got.ID || fake["locale"] != "fr" || fake["name"] != "Ada" {
		t.Fatal("the response is not the shaped user", fake)
	}
	for _, key := range []string{"note", "plan"} {
		if _, leaked := fake[key]; leaked {
			t.Fatal("the response kept", key, fake)
		}
	}
	if len(fake) != len(real) {
		t.Fatal("the shaped user has other fields than a real one", fake, real)
	}
}
