package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// Run the user and session create after hooks for sign-ins whose store
// decides whether to create the user: social sign-in, magic links, email
// codes and phone verification. A new user fires the user hook once; a
// returning user fires only the session hook.
func TestDatabaseAfterHooksForDecidedSignIns(t *testing.T) {
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
	var magic, code, sms string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			target, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			q := target.Query()
			q.Set("code", "grant")
			q.Set("state", r.URL.Query().Get("state"))
			target.RawQuery = q.Encode()
			http.Redirect(w, r, target.String(), 302)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer provider.Close()
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"phone-number"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	magicLink, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(_ context.Context, m authn.MagicLinkMessage) error { magic = m.Token; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	emailOTP, err := authn.NewEmailOTP(authn.EmailOTPOptions{Send: func(_ context.Context, m authn.EmailOTPMessage) error { code = m.OTP; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{
		SendOTP:              func(_ context.Context, m authn.PhoneOTPMessage) error { sms = m.Code; return nil },
		SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return strings.TrimPrefix(n, "+") + "@phone.example" }, GetTempName: func(n string) string { return n }},
	})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewUnstartedServer(nil)
	base := "http://" + app.Listener.Addr().String()
	hooks := authn.DatabaseHooks{
		User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
			After: func(_ context.Context, u authn.UserRecord, c *authn.HookContext) error {
				record("user:" + c.Path + ":" + u.Email)
				return nil
			},
		}},
		Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
			After: func(ctx context.Context, s authn.SessionRecord, c *authn.HookContext) error {
				// The hook sees the stored session with the owner the store chose.
				_, owner, err := store.Session(ctx, s.Token)
				if err != nil || owner.ID != s.UserID {
					t.Error("the session hook did not see the stored owner", err)
				}
				record("session:" + c.Path)
				return nil
			},
		}},
	}
	off := false
	options := authn.Options{
		BaseURL: base, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{magicLink, emailOTP, phone},
		SocialProviders: map[string]authn.OAuthProvider{"local": {
			Config: oauth2.Config{ClientID: "local-client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
				return authn.OAuthProfile{Subject: "social-subject", Email: "social@example.com", EmailVerified: true, Name: "Social"}, nil
			},
		}},
		DatabaseHooks: hooks,
	}
	auth, err := authn.New(options)
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = auth
	app.Start()
	defer app.Close()
	browser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	post := func(client *http.Client, path string, body any) int {
		t.Helper()
		payload, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", base+"/api/auth"+path, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	get := func(client *http.Client, target string) *http.Response {
		t.Helper()
		res, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	social := func() {
		t.Helper()
		client := browser()
		payload, _ := json.Marshal(map[string]string{"provider": "local", "callbackURL": "/done"})
		req, _ := http.NewRequest("POST", base+"/api/auth/sign-in/social", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var start struct{ URL string }
		_ = json.NewDecoder(res.Body).Decode(&start)
		res.Body.Close()
		callback := get(client, start.URL).Header.Get("Location")
		if res := get(client, callback); res.StatusCode != 302 || res.Header.Get("Location") != "/done" {
			t.Fatal("social callback failed", res.StatusCode, res.Header.Get("Location"))
		}
	}

	// Social sign-in creates the user once; signing in again creates only a session.
	social()
	social()
	if got := seen(); got != "user:/callback/:id:social@example.com,session:/callback/:id,session:/callback/:id" {
		t.Fatal("unexpected social sign-in hooks", got)
	}

	// A magic link creates the user on first use.
	for range 2 {
		client := browser()
		if post(client, "/sign-in/magic-link", map[string]string{"email": "magic@example.com", "callbackURL": "/done"}) != 200 {
			t.Fatal("magic link request failed")
		}
		if res := get(client, base+"/api/auth/magic-link/verify?token="+url.QueryEscape(magic)+"&callbackURL=/done"); res.StatusCode != 302 {
			t.Fatal("magic link verification failed", res.StatusCode)
		}
	}
	if got := seen(); got != "user:/magic-link/verify:magic@example.com,session:/magic-link/verify,session:/magic-link/verify" {
		t.Fatal("unexpected magic link hooks", got)
	}

	// An email code creates the user on first sign-in.
	for range 2 {
		client := browser()
		if post(client, "/email-otp/send-verification-otp", map[string]string{"email": "code@example.com", "type": "sign-in"}) != 200 {
			t.Fatal("email code request failed")
		}
		if post(client, "/sign-in/email-otp", map[string]string{"email": "code@example.com", "otp": code}) != 200 {
			t.Fatal("email code sign-in failed")
		}
	}
	if got := seen(); got != "user:/sign-in/email-otp:code@example.com,session:/sign-in/email-otp,session:/sign-in/email-otp" {
		t.Fatal("unexpected email code hooks", got)
	}

	// Phone verification creates the user on first use.
	for range 2 {
		client := browser()
		if post(client, "/phone-number/send-otp", map[string]string{"phoneNumber": "+15550100"}) != 200 {
			t.Fatal("phone code request failed")
		}
		if post(client, "/phone-number/verify", map[string]string{"phoneNumber": "+15550100", "code": sms}) != 200 {
			t.Fatal("phone verification failed")
		}
	}
	if got := seen(); got != "user:/phone-number/verify:15550100@phone.example,session:/phone-number/verify,session:/phone-number/verify" {
		t.Fatal("unexpected phone hooks", got)
	}

	// These sign-ins do not run before hooks yet, so New refuses them.
	options.DatabaseHooks.User.Create.Before = func(context.Context, *authn.UserRecord, *authn.HookContext) error { return nil }
	if _, err := authn.New(options); err == nil || !strings.Contains(err.Error(), "social sign-in") || !strings.Contains(err.Error(), "magic-link") {
		t.Fatal("before hooks were accepted for decided sign-ins", err)
	}
}
