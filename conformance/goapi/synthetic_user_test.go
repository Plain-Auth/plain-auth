package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
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

// A protected duplicate sign-up returns the default role and empty ban
// fields exactly as a real sign-up does, and CustomSyntheticUser can shape
// them.
func TestSyntheticUserAdminFields(t *testing.T) {
	for name, opts := range map[string]authn.Options{"verification": {RequireEmailVerification: true}, "no-auto-sign-in": {DisableAutoSignIn: true}} {
		t.Run(name, func(t *testing.T) {
			store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"admin"}, schema.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			plugin, err := authn.NewAdmin(authn.AdminOptions{DefaultRole: "member", Roles: map[string]authn.AdminPermissions{"member": {}, "admin": {"user": {"list"}}}})
			if err != nil {
				t.Fatal(err)
			}
			var shape map[string]any
			off := false
			opts.BaseURL, opts.Store, opts.Secret, opts.EmailAndPassword, opts.RateLimit, opts.Plugins = "https://auth.example", store, strings.Repeat("s", 32), true, &off, []authn.Plugin{plugin}
			opts.CustomSyntheticUser = func(authn.SyntheticUser) map[string]any { return shape }
			if opts.RequireEmailVerification {
				opts.SendVerificationEmail = func(context.Context, authn.MailLink) error { return nil }
			}
			auth, err := authn.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signUp := func(email string) (map[string]any, []byte) {
				r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-up/email", strings.NewReader(`{"email":"`+email+`","password":"correct horse battery","name":"Grace"}`))
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
			real, realBody := signUp("grace@example.com")
			if real["role"] != "member" || real["banned"] != false || real["banReason"] != nil || real["banExpires"] != nil {
				t.Fatal("a real sign-up lost its admin fields", real)
			}
			fake, fakeBody := signUp("GRACE@example.com")
			for _, key := range []string{"role", "banned", "banReason", "banExpires"} {
				if v, ok := fake[key]; !ok || v != real[key] {
					t.Fatal("a duplicate sign-up's admin fields differ from a real sign-up", key, fake)
				}
			}
			if strings.Join(userKeys(t, fakeBody), ",") != strings.Join(userKeys(t, realBody), ",") {
				t.Fatal("the duplicate sign-up's keys differ from a real sign-up", userKeys(t, fakeBody), userKeys(t, realBody))
			}
			shape = map[string]any{"role": "user", "banned": "no"}
			if shaped, _ := signUp("Grace@Example.com"); shaped["role"] != "user" || shaped["banned"] != false {
				t.Fatal("CustomSyntheticUser did not shape the admin fields", shaped)
			}
		})
	}
}
