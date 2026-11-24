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
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// decidedSignIns serves social sign-in, magic links, email codes and phone
// verification, whose store decides whether a sign-in creates the user.
type decidedSignIns struct {
	t                 *testing.T
	base              string
	store             *sqlstore.Store
	magic, code, sms  string
	mu                sync.Mutex
	events            []string
	userBefore        func(*authn.UserRecord) error
	sessionBefore     func(*authn.SessionRecord) error
	options           authn.Options
	providerEmail     string
	errorCallbackSeen string
	// validate, when set, is the ValidateUserInfo policy.
	validate func(authn.UserInfoValidation) error
}

func newDecidedSignIns(t *testing.T, before bool) *decidedSignIns {
	t.Helper()
	d := &decidedSignIns{t: t, providerEmail: "social@example.com"}
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
	t.Cleanup(provider.Close)
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"phone-number"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	d.store = store
	magicLink, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(_ context.Context, m authn.MagicLinkMessage) error { d.magic = m.Token; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	emailOTP, err := authn.NewEmailOTP(authn.EmailOTPOptions{AutoSignInAfterVerification: true, Send: func(_ context.Context, m authn.EmailOTPMessage) error { d.code = m.OTP; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{
		SendOTP:              func(_ context.Context, m authn.PhoneOTPMessage) error { d.sms = m.Code; return nil },
		SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return strings.TrimPrefix(n, "+") + "@phone.example" }, GetTempName: func(n string) string { return n }},
	})
	if err != nil {
		t.Fatal(err)
	}
	app := httptest.NewUnstartedServer(nil)
	d.base = "http://" + app.Listener.Addr().String()
	hooks := authn.DatabaseHooks{
		User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
			After: func(_ context.Context, u authn.UserRecord, c *authn.HookContext) error {
				d.record("user:" + c.Path + ":" + u.Email + ":" + u.Name)
				return nil
			},
		}},
		Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
			After: func(ctx context.Context, s authn.SessionRecord, c *authn.HookContext) error {
				// The hook sees the stored session with the owner the store chose.
				stored, owner, err := store.Session(ctx, s.Token)
				if err != nil || owner.ID != s.UserID || stored.UserAgent != s.UserAgent {
					t.Error("the session hook did not see the stored session", err)
				}
				d.record("session:" + c.Path + ":" + s.UserAgent)
				return nil
			},
		}},
	}
	if before {
		hooks.User.Create.Before = func(_ context.Context, u *authn.UserRecord, c *authn.HookContext) error {
			d.record("user-before:" + c.Path + ":" + u.Email)
			if d.userBefore != nil {
				return d.userBefore(u)
			}
			return nil
		}
		hooks.Session.Create.Before = func(_ context.Context, s *authn.SessionRecord, c *authn.HookContext) error {
			d.record("session-before:" + c.Path)
			if d.sessionBefore != nil {
				return d.sessionBefore(s)
			}
			return nil
		}
	}
	off := false
	d.options = authn.Options{
		BaseURL: d.base, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{magicLink, emailOTP, phone},
		SocialProviders: map[string]authn.OAuthProvider{"local": {
			AllowVerifiedEmailLink: true,
			Config:                 oauth2.Config{ClientID: "local-client", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"}},
			Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
				return authn.OAuthProfile{Subject: "subject-" + d.providerEmail, Email: d.providerEmail, EmailVerified: true, Name: "Social",
					Data: map[string]any{"email": d.providerEmail, "hd": "example.com"}}, nil
			},
		}},
		DatabaseHooks: hooks,
		ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
			if d.validate == nil {
				return nil
			}
			d.record("validate:" + string(v.Action) + ":" + v.Method + ":" + v.User.Email)
			return d.validate(v)
		},
	}
	auth, err := authn.New(d.options)
	if err != nil {
		t.Fatal(err)
	}
	app.Config.Handler = auth
	app.Start()
	t.Cleanup(app.Close)
	return d
}

func (d *decidedSignIns) record(e string) { d.mu.Lock(); d.events = append(d.events, e); d.mu.Unlock() }

func (d *decidedSignIns) seen() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := strings.Join(d.events, ",")
	d.events = nil
	return s
}

func (d *decidedSignIns) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (d *decidedSignIns) post(client *http.Client, path string, body any) (int, map[string]any) {
	d.t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", d.base+"/api/auth"+path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", d.base)
	res, err := client.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func (d *decidedSignIns) get(client *http.Client, target string) *http.Response {
	d.t.Helper()
	res, err := client.Get(target)
	if err != nil {
		d.t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// social signs in through the provider and returns the final redirect target.
func (d *decidedSignIns) social() string {
	d.t.Helper()
	client := d.browser()
	payload, _ := json.Marshal(map[string]string{"provider": "local", "callbackURL": "/done", "errorCallbackURL": "/failed"})
	req, _ := http.NewRequest("POST", d.base+"/api/auth/sign-in/social", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", d.base)
	res, err := client.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	var start struct{ URL string }
	_ = json.NewDecoder(res.Body).Decode(&start)
	res.Body.Close()
	callback := d.get(client, start.URL).Header.Get("Location")
	return d.get(client, callback).Header.Get("Location")
}

func (d *decidedSignIns) magicLink(email string) string {
	d.t.Helper()
	client := d.browser()
	if status, _ := d.post(client, "/sign-in/magic-link", map[string]string{"email": email, "callbackURL": "/done", "errorCallbackURL": "/failed"}); status != 200 {
		d.t.Fatal("magic link request failed", status)
	}
	return d.get(client, d.base+"/api/auth/magic-link/verify?token="+url.QueryEscape(d.magic)+"&callbackURL=/done&errorCallbackURL=/failed").Header.Get("Location")
}

// magicLinkJSON verifies a magic link without a callback and returns its JSON answer.
func (d *decidedSignIns) magicLinkJSON(email string) map[string]any {
	d.t.Helper()
	client := d.browser()
	if status, _ := d.post(client, "/sign-in/magic-link", map[string]string{"email": email}); status != 200 {
		d.t.Fatal("magic link request failed", status)
	}
	res, err := client.Get(d.base + "/api/auth/magic-link/verify?token=" + url.QueryEscape(d.magic))
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

// verifyEmail proves an address with a code, which signs the browser in.
func (d *decidedSignIns) verifyEmail(email string) int {
	d.t.Helper()
	client := d.browser()
	if status, _ := d.post(client, "/email-otp/send-verification-otp", map[string]string{"email": email, "type": "email-verification"}); status != 200 {
		d.t.Fatal("verification code request failed", status)
	}
	status, _ := d.post(client, "/email-otp/verify-email", map[string]string{"email": email, "otp": d.code})
	return status
}

func (d *decidedSignIns) emailCode(email string) (int, map[string]any) {
	d.t.Helper()
	client := d.browser()
	if status, _ := d.post(client, "/email-otp/send-verification-otp", map[string]string{"email": email, "type": "sign-in"}); status != 200 {
		d.t.Fatal("email code request failed", status)
	}
	return d.post(client, "/sign-in/email-otp", map[string]string{"email": email, "otp": d.code})
}

func (d *decidedSignIns) phone(number string) (int, map[string]any) {
	d.t.Helper()
	client := d.browser()
	if status, _ := d.post(client, "/phone-number/send-otp", map[string]string{"phoneNumber": number}); status != 200 {
		d.t.Fatal("phone code request failed", status)
	}
	return d.post(client, "/phone-number/verify", map[string]string{"phoneNumber": number, "code": d.sms})
}

// Run the user and session create after hooks for sign-ins whose store
// decides whether to create the user: social sign-in, magic links, email
// codes and phone verification. A new user fires the user hook once; a
// returning user fires only the session hook.
func TestDatabaseAfterHooksForDecidedSignIns(t *testing.T) {
	d := newDecidedSignIns(t, false)

	// Social sign-in creates the user once; signing in again creates only a session.
	d.social()
	d.social()
	if got := d.seen(); got != "user:/callback/:id:social@example.com:Social,session:/callback/:id:Go-http-client/1.1,session:/callback/:id:Go-http-client/1.1" {
		t.Fatal("unexpected social sign-in hooks", got)
	}
	// A magic link creates the user on first use.
	d.magicLink("magic@example.com")
	d.magicLink("magic@example.com")
	if got := d.seen(); got != "user:/magic-link/verify:magic@example.com:,session:/magic-link/verify:Go-http-client/1.1,session:/magic-link/verify:Go-http-client/1.1" {
		t.Fatal("unexpected magic link hooks", got)
	}
	// An email code creates the user on first sign-in.
	d.emailCode("code@example.com")
	d.emailCode("code@example.com")
	if got := d.seen(); got != "user:/sign-in/email-otp:code@example.com:,session:/sign-in/email-otp:Go-http-client/1.1,session:/sign-in/email-otp:Go-http-client/1.1" {
		t.Fatal("unexpected email code hooks", got)
	}
	// Phone verification creates the user on first use.
	d.phone("+15550100")
	d.phone("+15550100")
	if got := d.seen(); got != "user:/phone-number/verify:15550100@phone.example:+15550100,session:/phone-number/verify:Go-http-client/1.1,session:/phone-number/verify:Go-http-client/1.1" {
		t.Fatal("unexpected phone hooks", got)
	}
}

// Run the create before hooks for those sign-ins outside the store's
// transaction: they see only new users, their edits are stored, a skip
// stores nothing, and a user created while the hooks ran is signed in.
func TestDatabaseBeforeHooksForDecidedSignIns(t *testing.T) {
	d := newDecidedSignIns(t, true)
	d.userBefore = func(u *authn.UserRecord) error { u.Name = strings.ToUpper(u.Email); return nil }
	d.sessionBefore = func(s *authn.SessionRecord) error { s.UserAgent = "hooked"; return nil }

	// The hooks edit the new user and session; a returning user runs only the session hooks.
	if got := d.social(); got != "/done" {
		t.Fatal("social sign-in failed", got)
	}
	d.social()
	if got := d.seen(); got != "user-before:/callback/:id:social@example.com,session-before:/callback/:id,user:/callback/:id:social@example.com:SOCIAL@EXAMPLE.COM,session:/callback/:id:hooked,session-before:/callback/:id,session:/callback/:id:hooked" {
		t.Fatal("unexpected social hooks", got)
	}
	d.magicLink("magic@example.com")
	if status, _ := d.emailCode("code@example.com"); status != 200 {
		t.Fatal("email code sign-in failed", status)
	}
	if status, _ := d.phone("+15550100"); status != 200 {
		t.Fatal("phone verification failed", status)
	}
	if got := d.seen(); got != "user-before:/magic-link/verify:magic@example.com,session-before:/magic-link/verify,user:/magic-link/verify:magic@example.com:MAGIC@EXAMPLE.COM,session:/magic-link/verify:hooked,"+
		"user-before:/sign-in/email-otp:code@example.com,session-before:/sign-in/email-otp,user:/sign-in/email-otp:code@example.com:CODE@EXAMPLE.COM,session:/sign-in/email-otp:hooked,"+
		"user-before:/phone-number/verify:15550100@phone.example,session-before:/phone-number/verify,user:/phone-number/verify:15550100@phone.example:15550100@PHONE.EXAMPLE,session:/phone-number/verify:hooked" {
		t.Fatal("unexpected hooks for magic links, email codes and phone", got)
	}

	// The JSON answer of a magic link returns the session as the hooks left it.
	if out := d.magicLinkJSON("magic@example.com"); out["session"].(map[string]any)["userAgent"] != "hooked" {
		t.Fatal("the magic link answered with the session before its hooks ran", out)
	}
	// Verifying an email with a code signs in through the session hooks.
	if status := d.verifyEmail("code@example.com"); status != 200 {
		t.Fatal("email verification failed", status)
	}
	if got := d.seen(); got != "session-before:/magic-link/verify,session:/magic-link/verify:hooked,session-before:/email-otp/verify-email,session:/email-otp/verify-email:hooked" {
		t.Fatal("unexpected verification sign-in hooks", got)
	}

	// The store decides the email and its verification, so a hook may not change them.
	d.userBefore = func(u *authn.UserRecord) error { u.EmailVerified = !u.EmailVerified; return nil }
	d.providerEmail = "flipped@example.com"
	if got := d.social(); got != "" {
		t.Fatal("a verification edit was accepted", got)
	}
	// A magic link answers a hook's refusal by redirecting to the error callback.
	d.userBefore = func(*authn.UserRecord) error {
		return &authn.APIError{Status: 403, Code: "SIGN_UP_CLOSED", Message: "Sign-up is closed"}
	}
	if got := d.magicLink("closed@example.com"); !strings.Contains(got, "error=SIGN_UP_CLOSED") || !strings.Contains(got, "error_description=Sign-up+is+closed") {
		t.Fatal("a refused magic link did not redirect to the error callback", got)
	}
	d.seen()

	// A skipped user stores nothing, with each sign-in's usual error.
	d.userBefore = func(*authn.UserRecord) error { return authn.ErrSkipWrite }
	d.providerEmail = "skipped@example.com"
	if got := d.social(); !strings.Contains(got, "error=unable_to_create_user") {
		t.Fatal("a skipped social user did not fail the sign-in", got)
	}
	if got := d.magicLink("skipped@example.com"); !strings.Contains(got, "error=failed_to_create_user") {
		t.Fatal("a skipped magic link user did not fail the sign-in", got)
	}
	if status, out := d.emailCode("skipped@example.com"); status != 500 || out["code"] != "FAILED_TO_CREATE_USER" {
		t.Fatal("a skipped email code user did not fail the sign-in", status, out)
	}
	if status, out := d.phone("+15550111"); status != 500 || out["code"] != "FAILED_TO_CREATE_USER" {
		t.Fatal("a skipped phone user did not fail the sign-in", status, out)
	}
	for _, email := range []string{"skipped@example.com", "15550111@phone.example"} {
		if _, err := d.store.FindAccountUser(t.Context(), email); err == nil {
			t.Fatal("a skipped sign-in stored its user", email)
		}
	}
	d.userBefore = nil
	d.sessionBefore = func(*authn.SessionRecord) error { return authn.ErrSkipWrite }
	if got := d.magicLink("magic@example.com"); !strings.Contains(got, "error=failed_to_create_session") {
		t.Fatal("a skipped magic link session did not fail the sign-in", got)
	}
	d.sessionBefore = nil
	d.seen()

	// A user stored while the hooks run is signed in instead of being created again.
	d.userBefore = func(u *authn.UserRecord) error {
		now := time.Now().UTC().Truncate(time.Millisecond)
		return d.store.CreateUser(t.Context(), authn.User{ID: "racer", Name: "Racer", Email: u.Email, EmailVerified: true, CreatedAt: now, UpdatedAt: now}, "", nil)
	}
	if got := d.magicLink("race@example.com"); !strings.HasSuffix(got, "/done") {
		t.Fatal("the raced sign-in failed", got)
	}
	d.userBefore = nil
	if got := d.seen(); got != "user-before:/magic-link/verify:race@example.com,session-before:/magic-link/verify,session-before:/magic-link/verify,session:/magic-link/verify:Go-http-client/1.1" {
		t.Fatal("unexpected raced sign-in hooks", got)
	}
	sessions, _ := d.store.ListSessions(t.Context(), "racer")
	if len(sessions) != 1 {
		t.Fatal("the raced sign-in did not sign in the stored user", len(sessions))
	}
}
