package goapi_test

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// userKeys returns the keys of a response's user object in wire order.
func userKeys(t *testing.T, body []byte) []string {
	t.Helper()
	var wrapper struct {
		User json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatal(err, string(body))
	}
	dec := json.NewDecoder(bytes.NewReader(wrapper.User))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for dec.More() {
		key, _ := dec.Token()
		keys = append(keys, key.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// CustomSyntheticUser shapes the user returned for a sign-up with an email
// that already exists, and the response reads exactly like a real sign-up:
// the same keys in the same order, in the same formats.
func TestCustomSyntheticUser(t *testing.T) {
	off := false
	var got authn.SyntheticUser
	var shape map[string]any
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		DisableAutoSignIn: true,
		UserAdditionalFields: map[string]authn.UserField{
			"locale": {Type: authn.FieldString, Default: "en"},
			"born":   {Type: authn.FieldDate},
			"note":   {Type: authn.FieldString, Hidden: true},
		},
		CustomSyntheticUser: func(u authn.SyntheticUser) map[string]any { got = u; return shape },
	})
	if err != nil {
		t.Fatal(err)
	}
	signUp := func(email string) (map[string]any, []byte) {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"email":"`+email+`","password":"correct horse battery","name":"Ada"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		var body struct {
			Token any            `json:"token"`
			User  map[string]any `json:"user"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Token != nil {
			t.Fatal(w.Code, w.Body)
		}
		return body.User, w.Body.Bytes()
	}
	real, realBody := signUp("Ada@Example.com")
	if got.ID != "" {
		t.Fatal("the hook ran for a new account")
	}
	// The hook sets real fields in any Go form; a hidden or unknown key is dropped.
	born := time.Date(1990, 5, 1, 12, 0, 0, 123456789, time.FixedZone("CET", 3600))
	shape = map[string]any{"locale": "fr", "born": born, "createdAt": born, "plan": "free", "note": "leaked"}
	fake, fakeBody := signUp("ada@example.com")
	if got.ID == "" || got.ID == real["id"] || got.Email != "ada@example.com" || got.Name != "Ada" || got.EmailVerified || got.AdditionalFields["locale"] != "en" {
		t.Fatalf("the hook received %+v", got)
	}
	if fake["id"] != got.ID || fake["locale"] != "fr" || fake["born"] != "1990-05-01T11:00:00.123Z" || fake["createdAt"] != "1990-05-01T11:00:00.123Z" {
		t.Fatal("the response is not the shaped user", fake)
	}
	if strings.Join(userKeys(t, fakeBody), ",") != strings.Join(userKeys(t, realBody), ",") {
		t.Fatal("the shaped user's keys differ from a real sign-up", userKeys(t, fakeBody), userKeys(t, realBody))
	}
	// Values that do not fit their field keep the generated ones.
	shape = map[string]any{"name": func() {}, "emailVerified": "yes", "locale": 5, "born": "soon", "createdAt": "now", "updatedAt": math.NaN()}
	bad, badBody := signUp("ADA@example.com")
	if bad["name"] != "Ada" || bad["emailVerified"] != false || bad["locale"] != "en" || bad["born"] != nil {
		t.Fatal("an unfit value replaced a generated one", bad)
	}
	if created, err := time.Parse(time.RFC3339Nano, bad["createdAt"].(string)); err != nil || created.Before(time.Now().Add(-time.Minute)) {
		t.Fatal("the generated timestamp was replaced", bad["createdAt"])
	}
	if strings.Join(userKeys(t, badBody), ",") != strings.Join(userKeys(t, realBody), ",") {
		t.Fatal("the response's keys changed", userKeys(t, badBody))
	}
}
