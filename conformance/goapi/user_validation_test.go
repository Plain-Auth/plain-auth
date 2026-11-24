package goapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/scim"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// validationRecorder keeps the checks a ValidateUserInfo callback receives.
type validationRecorder struct {
	mu     sync.Mutex
	checks []authn.UserInfoValidation
	order  []string
}

func (v *validationRecorder) add(check authn.UserInfoValidation) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checks = append(v.checks, check)
	v.order = append(v.order, "validate:"+check.Method)
}

func (v *validationRecorder) last(t *testing.T) authn.UserInfoValidation {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.checks) == 0 {
		t.Fatal("ValidateUserInfo did not run")
	}
	return v.checks[len(v.checks)-1]
}

func postJSON(t *testing.T, h http.Handler, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
	r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// ValidateUserInfo admits or refuses email sign-ups before the user create
// hooks, sees the request without its body, and keeps protected sign-ups
// private.
func TestValidateUserInfoSignUp(t *testing.T) {
	for _, protected := range []bool{false, true} {
		rec := &validationRecorder{}
		off := false
		store := memory.New()
		auth, err := authn.New(authn.Options{
			BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
			DisableAutoSignIn:    protected,
			UserAdditionalFields: map[string]authn.UserField{"plan": {Type: authn.FieldString}},
			ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
				rec.add(v)
				if !strings.HasSuffix(v.User.Email, "@company.example") {
					return &authn.APIError{Status: 400, Code: "email_not_allowed", Message: "Only company emails are allowed"}
				}
				return nil
			},
			DatabaseHooks: authn.DatabaseHooks{User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
				Before: func(_ context.Context, _ *authn.UserRecord, _ *authn.HookContext) error {
					rec.mu.Lock()
					rec.order = append(rec.order, "before-create")
					rec.mu.Unlock()
					return nil
				},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		status, _ := postJSON(t, auth, "/sign-up/email", `{"email":"Ada@Company.example","password":"correct horse battery","name":"Ada","plan":"pro"}`)
		if status != 200 {
			t.Fatal("an admitted sign-up failed", status)
		}
		check := rec.last(t)
		if check.Action != authn.UserInfoCreateUser || check.Method != "email-password" || check.User.Email != "ada@company.example" || check.User.Name != "Ada" || check.User.Fields["plan"] != "pro" {
			t.Fatalf("the check was %+v", check)
		}
		if check.Request == nil || check.Request.Header.Get("Origin") != "https://auth.example" || check.Request.ContentLength != 0 || check.Request.Body != http.NoBody {
			t.Fatal("the check did not get a body-free copy of the request")
		}
		if strings.Join(rec.order, ",") != "validate:email-password,before-create" {
			t.Fatal("the gate did not run before the user create hooks", rec.order)
		}
		status, body := postJSON(t, auth, "/sign-up/email", `{"email":"eve@else.example","password":"correct horse battery","name":"Eve"}`)
		if protected {
			// A protected sign-up answers a refusal like an existing email.
			if user, _ := body["user"].(map[string]any); status != 200 || body["token"] != nil || user["email"] != "eve@else.example" {
				t.Fatal("a protected refusal was not private", status, body)
			}
		} else if status != 403 || body["code"] != "email_not_allowed" || body["message"] != "Only company emails are allowed" {
			t.Fatal("the refusal was not a 403 with the app's code", status, body)
		}
		if _, err := store.FindAccountUser(t.Context(), "eve@else.example"); !errors.Is(err, authn.ErrNotFound) {
			t.Fatal("a refused sign-up stored a user", err)
		}
	}
}

// Refusals always answer 403; anything but an APIError with a code fails
// closed as validation_failed, and a check without a source is refused.
func TestValidateUserInfoResults(t *testing.T) {
	var result func() error
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Logger:           slog.New(slog.DiscardHandler),
		ValidateUserInfo: func(context.Context, authn.UserInfoValidation) error { return result() },
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		result        func() error
		code, message string
	}{
		{func() error { return &authn.APIError{Status: 400, Code: "blocked", Message: "Blocked"} }, "blocked", "Blocked"},
		{func() error { return &authn.APIError{Code: "blocked"} }, "blocked", "blocked"},
		{func() error { return &authn.APIError{Status: 403, Message: "no code"} }, "validation_failed", "User validation failed"},
		{func() error { return errors.New("database down") }, "validation_failed", "User validation failed"},
		{func() error { panic("boom") }, "validation_failed", "User validation failed"},
	} {
		result = tc.result
		status, body := postJSON(t, auth, "/sign-up/email", `{"email":"user`+string(rune('a'+i))+`@example.com","password":"correct horse battery","name":"User"}`)
		if status != 403 || body["code"] != tc.code || body["message"] != tc.message {
			t.Errorf("case %d: got %d %v", i, status, body)
		}
	}
	result = func() error { return nil }
	for _, tc := range []struct{ method, provider string }{{"", ""}, {"oauth", ""}, {"sso-saml", ""}} {
		err := auth.ValidateUserInfo(t.Context(), authn.UserInfoValidation{Action: authn.UserInfoCreateUser, Method: tc.method, Provider: tc.provider})
		var api *authn.APIError
		if !errors.As(err, &api) || api.Status != 403 || api.Code != "validation_source_missing" {
			t.Errorf("method %q without a provider: %v", tc.method, err)
		}
	}
	if err := auth.ValidateUserInfo(t.Context(), authn.UserInfoValidation{Action: authn.UserInfoCreateUser, Method: "plugin"}); err != nil {
		t.Fatal("an admitted direct check failed", err)
	}
}

// Anonymous, phone and administrator bootstrap users go through the gate.
func TestValidateUserInfoOtherCreators(t *testing.T) {
	rec := &validationRecorder{}
	refuse := map[string]bool{}
	var sms string
	anonymous, err := authn.NewAnonymous(authn.AnonymousOptions{})
	if err != nil {
		t.Fatal(err)
	}
	phone, err := authn.NewPhoneNumber(authn.PhoneNumberOptions{
		SendOTP:              func(_ context.Context, m authn.PhoneOTPMessage) error { sms = m.Code; return nil },
		SignUpOnVerification: &authn.PhoneSignUpOptions{GetTempEmail: func(n string) string { return strings.TrimPrefix(n, "+") + "@phone.example" }},
	})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{anonymous, phone},
		ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
			rec.add(v)
			if refuse[v.Method] {
				return &authn.APIError{Code: v.Method + "_blocked", Message: "Not allowed"}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	refuse["anonymous"] = true
	if status, body := postJSON(t, auth, "/sign-in/anonymous", `{}`); status != 403 || body["code"] != "anonymous_blocked" {
		t.Fatal("an anonymous refusal was not a 403", status, body)
	}
	refuse["anonymous"] = false
	if status, _ := postJSON(t, auth, "/sign-in/anonymous", `{}`); status != 200 {
		t.Fatal("an admitted anonymous sign-in failed", status)
	}
	if check := rec.last(t); check.Action != authn.UserInfoCreateUser || check.Method != "anonymous" || check.User.IsAnonymous == nil || !*check.User.IsAnonymous {
		t.Fatalf("the anonymous check was %+v", check)
	}
	verify := func() (int, map[string]any) {
		if status, _ := postJSON(t, auth, "/phone-number/send-otp", `{"phoneNumber":"+15550100"}`); status != 200 {
			t.Fatal("phone code request failed", status)
		}
		return postJSON(t, auth, "/phone-number/verify", `{"phoneNumber":"+15550100","code":"`+sms+`"}`)
	}
	refuse["phone-number"] = true
	if status, body := verify(); status != 403 || body["code"] != "phone-number_blocked" {
		t.Fatal("a phone refusal was not a 403", status, body)
	}
	check := rec.last(t)
	if check.Method != "phone-number" || check.User.Email != "15550100@phone.example" || check.User.PhoneNumberFields == nil ||
		*check.User.PhoneNumber != "+15550100" || !*check.User.PhoneNumberVerified {
		t.Fatalf("the phone check was %+v", check)
	}
	refuse["phone-number"] = false
	// The refusal spent the code, so it cannot be replayed once admitted.
	if status, _ := postJSON(t, auth, "/phone-number/verify", `{"phoneNumber":"+15550100","code":"`+sms+`"}`); status == 200 {
		t.Fatal("a refused phone code was accepted again")
	}
	if status, _ := verify(); status != 200 {
		t.Fatal("an admitted phone sign-up failed", status)
	}
	// Bootstrapping an administrator needs a SQL store.
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admins, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32),
		ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
			rec.add(v)
			return &authn.APIError{Code: "admin_blocked", Message: "Not allowed"}
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admins.BootstrapAdmin(t.Context(), "Root", "root@example.com", "correct horse battery"); err == nil {
		t.Fatal("a refused administrator was created")
	}
	if check := rec.last(t); check.Method != "admin" || check.User.Email != "root@example.com" || check.Request != nil {
		t.Fatalf("the bootstrap check was %+v", check)
	}
}

// New refuses ValidateUserInfo next to flows that do not run it yet.
func TestValidateUserInfoRefusedForUncoveredFlows(t *testing.T) {
	magicLink, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(context.Context, authn.MagicLinkMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), Plugins: []authn.Plugin{magicLink},
		ValidateUserInfo: func(context.Context, authn.UserInfoValidation) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "magic-link") {
		t.Fatal("ValidateUserInfo was accepted next to magic links", err)
	}
}

// The SCIM handler refuses a host with ValidateUserInfo, which it does not
// run yet.
func TestValidateUserInfoRefusedBySCIM(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	host, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32),
		ValidateUserInfo: func(context.Context, authn.UserInfoValidation) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = scim.New(host, scim.Options{Store: store, VerifyBearerToken: func(context.Context, scim.BearerInput) (*scim.BearerVerification, error) { return nil, nil }})
	if err == nil || !strings.Contains(err.Error(), "ValidateUserInfo") {
		t.Fatal("the SCIM handler accepted a host with ValidateUserInfo", err)
	}
}

// Sign-ins the store decides run the gate between a dry run and the real
// one: social sign-in checks creation, a later sign-in and an email link
// with the provider's fresh profile, and magic links and email codes check
// only new users. Refusals leave nothing behind and render on each path.
func TestValidateUserInfoDecidedSignIns(t *testing.T) {
	d := newDecidedSignIns(t, false)
	var checks []authn.UserInfoValidation
	refuse := ""
	d.validate = func(v authn.UserInfoValidation) error {
		checks = append(checks, v)
		if refuse != "" && v.Method == refuse {
			return &authn.APIError{Code: refuse + "_blocked", Message: "Only company users are allowed"}
		}
		return nil
	}
	refuse = "oauth"
	if got := d.social(); got != "/failed?error=oauth_blocked&error_description=Only+company+users+are+allowed" {
		t.Fatal("a refused social sign-up did not return to the error callback", got)
	}
	if _, err := d.store.FindAccountUser(t.Context(), "social@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a refused social sign-up stored a user", err)
	}
	check := checks[len(checks)-1]
	if check.Action != authn.UserInfoCreateUser || check.Provider != "local" || check.Profile["hd"] != "example.com" || check.User.Name != "Social" || check.Request == nil {
		t.Fatalf("the social check was %+v", check)
	}
	refuse = ""
	if got := d.social(); got != "/done" {
		t.Fatal("an admitted social sign-up failed", got)
	}
	// A returning provider user is checked again with the fresh profile.
	refuse = "oauth"
	if got := d.social(); !strings.HasPrefix(got, "/failed?error=oauth_blocked") {
		t.Fatal("a refused returning social sign-in signed in", got)
	}
	if check := checks[len(checks)-1]; check.Action != authn.UserInfoSignIn || check.User.ID == "" || check.User.Email != "social@example.com" {
		t.Fatalf("the returning check was %+v", check)
	}
	// A new identity reaching an existing user by email is a link.
	refuse = ""
	d.providerEmail = "magic@example.com"
	if got := d.magicLink("magic@example.com"); got != d.base+"/done" {
		t.Fatal("an admitted magic link failed", got)
	}
	if check := checks[len(checks)-1]; check.Action != authn.UserInfoCreateUser || check.Method != "magic-link" {
		t.Fatalf("the magic link check was %+v", check)
	}
	// The magic link verified the address, so the provider may link to it.
	before := len(checks)
	if got := d.social(); got != "/done" {
		t.Fatal("an email link failed", got)
	}
	if len(checks) != before+1 || checks[before].Action != authn.UserInfoLinkAccount {
		t.Fatalf("the email link was not checked as a link: %+v", checks[before:])
	}
	// A returning magic-link user is not checked again.
	before = len(checks)
	if got := d.magicLink("magic@example.com"); got != d.base+"/done" || len(checks) != before {
		t.Fatal("a returning magic link was checked", got, len(checks)-before)
	}
	refuse = "magic-link"
	if got := d.magicLink("new@example.com"); got != d.base+"/failed?error=magic-link_blocked&error_description=Only+company+users+are+allowed" {
		t.Fatal("a refused magic link signed in", got)
	}
	refuse = "email-otp"
	if status, body := d.emailCode("code@example.com"); status != 403 || body["code"] != "email-otp_blocked" {
		t.Fatal("a refused email code signed in", status, body)
	}
	if _, err := d.store.FindAccountUser(t.Context(), "code@example.com"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a refused email code stored a user", err)
	}
}

// ID-token sign-ups and explicit links run the gate; a refused link leaves
// the identity unlinked.
func TestValidateUserInfoIDTokenLinks(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var checks []authn.UserInfoValidation
	refuse := map[authn.UserInfoAction]bool{}
	p := authn.OAuthProvider{
		Config: oauth2.Config{ClientID: "mobile", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (authn.OAuthProfile, error) {
			return authn.OAuthProfile{}, errors.New("unused")
		},
		VerifyIDToken: func(_ context.Context, raw, _ string) (authn.OAuthProfile, time.Time, error) {
			claims := strings.Split(raw, "|")
			return authn.OAuthProfile{Subject: claims[0], Email: claims[1], EmailVerified: true, Name: "Owner", Data: map[string]any{"sub": claims[0], "level": 7}}, time.Now().Add(time.Hour), nil
		},
	}
	host := httptest.NewUnstartedServer(nil)
	base := "http://" + host.Listener.Addr().String()
	node, err := authn.New(authn.Options{Store: store, Secret: strings.Repeat("s", 40), BaseURL: base, EmailAndPassword: true, RateLimit: new(bool),
		SocialProviders: map[string]authn.OAuthProvider{"mobile": p},
		ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
			checks = append(checks, v)
			if refuse[v.Action] {
				return &authn.APIError{Code: string(v.Action) + "_blocked", Message: "Not allowed"}
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	host.Config.Handler = node
	host.Start()
	defer host.Close()
	newClient := func() *client.Client {
		c, err := client.New(base, &http.Client{})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	token := func(raw string) client.SocialSignInRequest {
		return client.SocialSignInRequest{Provider: "mobile", IDToken: &client.SocialIDToken{Token: raw, Nonce: "nonce"}}
	}
	code := func(err error) string {
		var api *authn.APIError
		if errors.As(err, &api) && api.Status == 403 {
			return api.Code
		}
		return ""
	}
	refuse[authn.UserInfoCreateUser] = true
	if _, err := newClient().SignInSocial(t.Context(), token("one|owner@example.test")); code(err) != "create-user_blocked" {
		t.Fatal("a refused ID-token sign-up signed in", err)
	}
	// Profile numbers are json.Number on every path.
	if check := checks[len(checks)-1]; check.Method != "oauth" || check.Provider != "mobile" || check.Profile["sub"] != "one" || check.Profile["level"] != json.Number("7") {
		t.Fatalf("the ID-token check was %+v", check)
	}
	refuse[authn.UserInfoCreateUser] = false
	owner := newClient()
	created, err := owner.SignInSocial(t.Context(), token("one|owner@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	refuse[authn.UserInfoLinkAccount] = true
	if _, err := owner.LinkSocial(t.Context(), token("two|owner@example.test")); code(err) != "link-account_blocked" {
		t.Fatal("a refused link succeeded", err)
	}
	if check := checks[len(checks)-1]; check.Action != authn.UserInfoLinkAccount || check.User.ID != created.User.ID || check.Profile["sub"] != "two" {
		t.Fatalf("the link check was %+v", check)
	}
	accounts, err := owner.ListAccounts(t.Context())
	if err != nil || len(accounts) != 1 {
		t.Fatal("a refused link left an account", accounts, err)
	}
}

// A plugin's enterprise flow whose completion commits without the login
// plan is refused rather than signed in past the gate.
func TestValidateUserInfoUnplannedEnterpriseFlow(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	calls := 0
	plugin := authn.Plugin{ID: "acme", Endpoints: []authn.Endpoint{{Method: "GET", Path: "/acme/callback", Handler: func(c authn.EndpointContext) (any, error) {
		profile := authn.OAuthProfile{Subject: "employee", Email: "employee@acme.example", Name: "Employee", EmailVerified: true}
		return c.CompleteEnterpriseFlow(authn.OAuthFlow{Provider: "acme", CallbackURL: "/home"}, "sso-oidc", profile, authn.OAuthTokens{}, false,
			func(ctx context.Context, _, _ string, _ authn.OAuthTokens, u authn.User, s authn.StoredSession, _ authn.OAuthLoginOptions) (authn.User, bool, error) {
				// This completion stores the user itself and never commits a plan.
				s.UserID = u.ID
				return u, true, store.CreateUser(ctx, u, "", &s)
			})
	}}}}
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), RateLimit: new(bool), Plugins: []authn.Plugin{plugin},
		ValidateUserInfo: func(context.Context, authn.UserInfoValidation) error { calls++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	auth.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example/api/auth/acme/callback", nil))
	if w.Code != 403 || strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=") || calls != 0 {
		t.Fatal("an unplanned enterprise sign-in got past the gate", w.Code, w.Header().Values("Set-Cookie"), calls)
	}
}

// POST /admin/create-user runs the gate outside the transaction, after the
// actor's permission and the email check, and stores nothing on a refusal.
func TestValidateUserInfoAdminCreate(t *testing.T) {
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"admin"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	admin, err := authn.NewAdmin(authn.AdminOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var checks []authn.UserInfoValidation
	off := false
	auth, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{admin},
		ValidateUserInfo: func(_ context.Context, v authn.UserInfoValidation) error {
			checks = append(checks, v)
			if v.Method == "admin" && strings.HasSuffix(v.User.Email, "@else.example") {
				return &authn.APIError{Code: "admin_create_blocked", Message: "Not allowed"}
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.BootstrapAdmin(t.Context(), "Root", "root@example.com", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	signIn := func(email string) string {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/sign-in/email", strings.NewReader(`{"email":"`+email+`","password":"correct horse battery"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		for _, c := range w.Result().Cookies() {
			if strings.Contains(c.Name, "session_token") {
				return c.Name + "=" + c.Value
			}
		}
		t.Fatal("sign-in failed", w.Code, w.Body)
		return ""
	}
	create := func(cookie, email string) (int, map[string]any) {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth/admin/create-user", strings.NewReader(`{"email":"`+email+`","password":"correct horse battery","name":"New"}`))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}, "Cookie": {cookie}}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	root := signIn("root@example.com")
	before := len(checks)
	if status, body := create(root, "eve@else.example"); status != 403 || body["code"] != "admin_create_blocked" {
		t.Fatal("a refused administrative user was not a 403", status, body)
	}
	if check := checks[len(checks)-1]; check.Method != "admin" || check.Action != authn.UserInfoCreateUser || check.User.Email != "eve@else.example" || check.Request == nil {
		t.Fatalf("the admin check was %+v", check)
	}
	if _, err := store.FindAccountUser(t.Context(), "eve@else.example"); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("a refused administrative user was stored", err)
	}
	if status, _ := create(root, "ada@example.com"); status != 200 {
		t.Fatal("an admitted administrative user failed", status)
	}
	// An existing email and a caller without permission never reach the gate.
	calls := len(checks)
	if status, _ := create(root, "ada@example.com"); status != 400 || len(checks) != calls {
		t.Fatal("an existing email reached the gate", status, len(checks)-calls)
	}
	if status, _ := create(signIn("ada@example.com"), "bob@example.com"); status != 403 || len(checks) != calls {
		t.Fatal("a caller without permission reached the gate", status, len(checks)-calls)
	}
	if len(checks) <= before {
		t.Fatal("the gate never ran for administrative users")
	}
}
