package goapi_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// newCredentialHost returns an instance with the admin plugin, an ID-token
// provider for accounts without a password, and counted password hashing.
func newCredentialHost(t *testing.T, hashes *atomic.Int32) sessionClient {
	t.Helper()
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"admin"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	admin, err := authn.NewAdmin(authn.AdminOptions{})
	if err != nil {
		t.Fatal(err)
	}
	provider := authn.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/authorize", TokenURL: "https://id.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
			return authn.OAuthProfile{}, errors.New("unused")
		},
		VerifyIDToken: func(_ context.Context, raw, _ string) (authn.OAuthProfile, time.Time, error) {
			return authn.OAuthProfile{Subject: raw, Email: raw + "@example.test", EmailVerified: true, Name: "Social"}, time.Now().Add(time.Hour), nil
		},
	}
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{admin}, SocialProviders: map[string]authn.OAuthProvider{"work": provider},
		PasswordHash: func(_ context.Context, password string) (string, error) {
			hashes.Add(1)
			return "plain:" + password, nil
		},
		PasswordVerify: func(_ context.Context, encoded, password string) (bool, error) {
			return encoded == "plain:"+password, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sessionClient{t, auth}
}

// Sign-in and sign-up accept the reference's address format, refuse a
// callback of the wrong type with the reference's answers, and answer an
// account without a password like an unknown address, with one hash each.
func TestEmailCredentialContract(t *testing.T) {
	var hashes atomic.Int32
	c := newCredentialHost(t, &hashes)
	signUp := func(email string, status int) {
		t.Helper()
		c.post("/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", status)
	}
	for _, email := range []string{"not-an-email", "", " a@b.co", "o'@example.test", "Kate@example.test"} {
		if code, message, _ := errorBody(t, c.post("/sign-in/email", `{"email":"`+email+`","password":"x"}`, "", 400)); code != "INVALID_EMAIL" || message != "Invalid email" {
			t.Fatalf("sign-in with %q answered %s %s", email, code, message)
		}
	}
	for _, email := range []string{"o'@example.test", "Kate@example.test"} {
		if code, message, _ := errorBody(t, c.post("/sign-up/email", `{"name":"P","email":"`+email+`","password":"`+sessionEndpointPassword+`"}`, "", 400)); code != "VALIDATION_ERROR" || message != "[body.email] Invalid email address" {
			t.Fatalf("sign-up with %q answered %s %s", email, code, message)
		}
	}
	signUp("a@b-.example", 200)
	signUp("o'reilly@example.test", 200)

	if _, message, coded := errorBody(t, c.post("/sign-in/email", `{"email":"a@b-.example","password":"x","callbackURL":5}`, "", 400)); message != "Invalid callbackURL: expected a string" || coded {
		t.Fatal("a numeric callback answered", message, coded)
	}
	if code, message, _ := errorBody(t, c.post("/sign-in/email", `{"email":"a@b-.example","password":"x","callbackURL":null}`, "", 400)); code != "VALIDATION_ERROR" || message != "[body.callbackURL] Invalid input: expected string, received null" {
		t.Fatal("a null callback answered", code, message)
	}

	c.post("/sign-in/social", `{"provider":"work","idToken":{"token":"sam","nonce":"n"}}`, "", 200)
	for _, email := range []string{"sam@example.test", "nobody@example.test"} {
		before := hashes.Load()
		if code, _, _ := errorBody(t, c.post("/sign-in/email", `{"email":"`+email+`","password":"any password at all"}`, "", 401)); code != "INVALID_EMAIL_OR_PASSWORD" {
			t.Fatal("signing in", email, "answered", code)
		}
		if n := hashes.Load() - before; n != 1 {
			t.Fatal("signing in", email, "hashed", n, "times, want 1")
		}
	}
}

// Fields a plugin stores are not the client's to set: sign-up and
// update-user refuse a value for one with FIELD_NOT_ALLOWED, and sign-up
// gives a field with a default its default instead.
func TestPluginUserFieldsRefused(t *testing.T) {
	var hashes atomic.Int32
	c := newCredentialHost(t, &hashes)
	if code, message, _ := errorBody(t, c.post("/sign-up/email", `{"name":"P","email":"ada@example.test","password":"`+sessionEndpointPassword+`","role":"admin"}`, "", 400)); code != "FIELD_NOT_ALLOWED" || message != "role is not allowed to be set" {
		t.Fatal("sign-up with a role answered", code, message)
	}
	c.post("/sign-up/email", `{"name":"P","email":"ada@example.test","password":"`+sessionEndpointPassword+`","banned":true,"role":""}`, "", 200)
	cookie, _ := c.signIn("ada@example.test")
	if c.user(cookie) != "ada@example.test" {
		t.Fatal("a sign-up that asked to be banned was banned")
	}
	// A field with a default takes it on sign-up rather than being refused.
	anonymous, err := authn.NewAnonymous(authn.AnonymousOptions{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"anonymous"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	off := false
	withAnonymous, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{anonymous}})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, withAnonymous, "POST", "/api/auth/sign-up/email", `{"name":"P","email":"anon@example.test","password":"`+sessionEndpointPassword+`","isAnonymous":true}`, sessionClient{t, withAnonymous}.headers(""), 200)
	if u, err := store.FindAccountUser(t.Context(), "anon@example.test"); err != nil || u.IsAnonymous != nil && *u.IsAnonymous {
		t.Fatal("a sign-up that asked to be anonymous was anonymous", err)
	}
	for body, field := range map[string]string{`{"name":"Renamed","role":"admin"}`: "role", `{"banned":true}`: "banned", `{"name":"Renamed","banReason":"x"}`: "banReason"} {
		if code, message, _ := errorBody(t, c.post("/update-user", body, cookie, 400)); code != "FIELD_NOT_ALLOWED" || message != field+" is not allowed to be set" {
			t.Fatal(body, "answered", code, message)
		}
	}
}

// update-user needs a session before judging the fields, answers an empty
// or unknown-only update and a missing body as the reference does, ignores
// a falsy email, and re-issues the browser-session marker.
func TestUpdateUserContract(t *testing.T) {
	var hashes atomic.Int32
	c := newCredentialHost(t, &hashes)
	c.post("/sign-up/email", `{"name":"P","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	cookie, _ := c.signIn("ada@example.test")
	for _, body := range []string{`{"email":"x@example.test"}`, `{"name":5}`} {
		if code, _, _ := errorBody(t, c.post("/update-user", body, "", 401)); code != "UNAUTHORIZED" {
			t.Fatal("an anonymous", body, "answered", code)
		}
	}
	for _, body := range []string{`{}`, `{"emailVerified":true,"unknown":1}`} {
		if _, message, coded := errorBody(t, c.post("/update-user", body, cookie, 400)); message != "No fields to update" || coded {
			t.Fatal(body, "answered", message, coded)
		}
	}
	r := serve(t, c.auth, "POST", "/api/auth/update-user", "", c.headers(cookie), 400)
	if code, message, _ := errorBody(t, r); code != "VALIDATION_ERROR" || message != "[body] Invalid input: expected record, received undefined" {
		t.Fatal("a missing body answered", code, message)
	}
	if _, message, _ := errorBody(t, c.post("/update-user", `[]`, cookie, 400)); message != "[body] Invalid input: expected record, received array" {
		t.Fatal("an array body answered", message)
	}
	if code, message, _ := errorBody(t, c.post("/update-user", `{"email":"x@example.test"}`, cookie, 400)); code != "EMAIL_CAN_NOT_BE_UPDATED" || message != "Email can not be updated" {
		t.Fatal("an email update answered", code, message)
	}
	statusBody(t, c.post("/update-user", `{"email":null,"name":"Renamed"}`, cookie, 200))

	// A browser that signed in without "remember me" keeps its marker.
	r = c.post("/sign-in/email", `{"email":"ada@example.test","password":"`+sessionEndpointPassword+`","rememberMe":false}`, "", 200)
	var browser []string
	for _, ck := range r.Cookies() {
		browser = append(browser, ck.Name+"="+ck.Value)
	}
	r = c.post("/update-user", `{"name":"Again"}`, strings.Join(browser, "; "), 200)
	marker := false
	for _, ck := range r.Cookies() {
		if strings.HasSuffix(ck.Name, "dont_remember") && ck.MaxAge >= 0 && ck.Value != "" {
			marker = true
		}
		if strings.HasSuffix(ck.Name, "session_token") && ck.MaxAge != 0 {
			t.Fatal("update-user made a browser session persistent:", ck)
		}
	}
	if !marker {
		t.Fatal("update-user did not re-issue the dont_remember marker:", r.Cookies())
	}
}
