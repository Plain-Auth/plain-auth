package pwnedpassword_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/pwnedpassword"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func digest(password string) string {
	sum := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
func response(status int, text string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(text))}
}

func TestRangeProtocol(t *testing.T) {
	const sample = "local fixture 🔑"
	hash := digest(sample)
	for _, tc := range []struct {
		name, body  string
		status      int
		found, fail bool
	}{
		{"positive lowercase CRLF", strings.ToLower(hash[5:]) + ":42\r\n", 200, true, false},
		{"different suffix", strings.Repeat("A", 35) + ":42\n", 200, false, false},
		{"padding", hash[5:] + ":0\n", 200, false, false},
		{"empty count", hash[5:] + ":\n", 200, false, true},
		{"leading zero", hash[5:] + ":01\n", 200, false, true},
		{"negative count", hash[5:] + ":-1\n", 200, false, true},
		{"oversize count", hash[5:] + ":9007199254740992\n", 200, false, true},
		{"oversize response", strings.Repeat("x", 1<<20+1), 200, false, true},
		{"service unavailable", "private service diagnostic", 503, false, true},
		{"service redirect", "", 302, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := pwnedpassword.IsPasswordCompromised(t.Context(), sample, transport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != "https://api.pwnedpasswords.com/range/"+hash[:5] || r.Method != "GET" || r.Body != nil || r.Header.Get("Add-Padding") != "true" || r.Header.Get("User-Agent") == "" || len(r.Header) != 2 {
					t.Fatalf("invalid range request: %s %s", r.Method, r.URL.Path)
				}
				res := response(tc.status, tc.body)
				if tc.status == 302 {
					res.Header.Set("Location", "https://redirect.example.test/other")
				}
				return res, nil
			}))
			if calls != 1 || got != tc.found || (err != nil) != tc.fail {
				t.Fatalf("got %t, %v (%d requests)", got, err, calls)
			}
			if tc.fail {
				var api *authn.APIError
				if !errors.As(err, &api) || api.Status != 500 || strings.Contains(api.Message, "private service diagnostic") {
					t.Fatal("service errors must fail closed without exposing diagnostics")
				}
			}
		})
	}
	_, err := pwnedpassword.IsPasswordCompromised(t.Context(), sample, transport(func(*http.Request) (*http.Response, error) { return nil, errors.New("private network diagnostic") }))
	if err == nil || strings.Contains(err.Error(), "private network diagnostic") {
		t.Fatal("transport error disclosure")
	}
	emptyHash := digest("")
	found, err := pwnedpassword.IsPasswordCompromised(t.Context(), "", transport(func(*http.Request) (*http.Response, error) { return response(200, emptyHash[5:]+":1"), nil }))
	if err != nil || !found {
		t.Fatal("standalone check for an empty password")
	}
}

func TestCredentialSettingPaths(t *testing.T) {
	const safe = "local clean sample"
	const blocked = "local blocked sample"
	breach := digest(blocked)
	calls := 0
	available := true
	fake := transport(func(r *http.Request) (*http.Response, error) {
		calls++
		if !available {
			return response(503, "local service unavailable"), nil
		}
		if r.URL.Path == "/range/"+breach[:5] {
			return response(200, breach[5:]+":2\n"), nil
		}
		return response(200, strings.Repeat("A", 35)+":3\n"), nil
	})
	var reset authn.MailLink
	off := false
	store := memory.New()
	opts := authn.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("q", 32), EmailAndPassword: true, RateLimit: &off, SendResetPassword: func(_ context.Context, m authn.MailLink) error { reset = m; return nil }}
	opts.Plugins = []authn.Plugin{pwnedpassword.New(pwnedpassword.Options{Transport: fake, CustomPasswordCompromisedMessage: "Choose a new sample"})}
	a, err := authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	reg := authn.SignUpInput{Name: "Sample", Email: "local@example.test", Password: blocked}
	denied := func(err error) {
		t.Helper()
		var e *authn.APIError
		if !errors.As(err, &e) || e.Status != 400 || e.Code != "PASSWORD_COMPROMISED" || e.Message != "Choose a new sample" {
			t.Fatalf("unexpected breach rejection: %v", err)
		}
	}
	_, err = a.SignUpEmail(ctx, reg, authn.RequestMeta{})
	denied(err)
	if _, _, err := store.Credential(ctx, reg.Email); !errors.Is(err, authn.ErrNotFound) {
		t.Fatal("rejected registration created an account")
	}
	reg.Password = safe
	available = false
	_, err = a.SignUpEmail(ctx, reg, authn.RequestMeta{})
	var failure *authn.APIError
	if !errors.As(err, &failure) || failure.Status != 500 {
		t.Fatal("unavailable range service allowed registration")
	}
	available = true
	registered, err := a.SignUpEmail(ctx, reg, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	cookie := a.SessionCookie(registered.Token, true)
	headers := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
	_, err = a.ChangePassword(ctx, headers, authn.ChangePasswordInput{CurrentPassword: safe, NewPassword: blocked}, authn.RequestMeta{})
	denied(err)
	post := func(path string, body map[string]string, authorized bool) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "https://auth.example.test/api/auth"+path, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example.test")
		if authorized {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	for _, route := range []string{"/sign-up/email", "/change-password"} {
		body := map[string]string{"name": "User", "email": "second@example.test", "password": blocked}
		if route == "/change-password" {
			body = map[string]string{"currentPassword": safe, "newPassword": blocked}
		}
		w := post(route, body, route == "/change-password")
		if w.Code != 400 || !strings.Contains(w.Body.String(), "PASSWORD_COMPROMISED") {
			t.Fatalf("%s failed to apply policy: %d", route, w.Code)
		}
	}
	if err := a.RequestPasswordReset(ctx, reg.Email, ""); err != nil || reset.Token == "" {
		t.Fatal("missing local reset token")
	}
	denied(a.ResetPassword(ctx, reset.Token, blocked))
	w := post("/reset-password", map[string]string{"token": reset.Token, "newPassword": blocked}, false)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "PASSWORD_COMPROMISED") {
		t.Fatal("HTTP reset failed to apply policy")
	}
	prior := calls
	_, err = a.SignInEmail(ctx, authn.SignInInput{Email: reg.Email, Password: safe}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	w = post("/sign-in/email", map[string]string{"email": reg.Email, "password": safe}, false)
	if w.Code != 200 || calls != prior {
		t.Fatal("verification of an existing credential contacted the range service")
	}
	if err := a.ResetPassword(ctx, reset.Token, "a new locally safe sample"); err != nil {
		t.Fatal("rejected reset consumed the proof")
	}
	opts.Plugins = []authn.Plugin{pwnedpassword.New(pwnedpassword.Options{Transport: fake, Paths: []string{"/set-password"}, CustomPasswordCompromisedMessage: "Choose a new sample"})}
	a, err = authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	denied(a.SetPassword(ctx, headers, blocked))
}

func TestPluginOptions(t *testing.T) {
	on, off := true, false
	calls := 0
	const sample = "a local sample"
	hash := digest(sample)
	fake := transport(func(*http.Request) (*http.Response, error) { calls++; return response(200, hash[5:]+":1"), nil })
	for _, path := range []string{"/sign-up/email", "/change-password", "/reset-password", "/email-otp/reset-password", "/phone-number/reset-password", "/admin/create-user", "/admin/set-user-password"} {
		p := pwnedpassword.New(pwnedpassword.Options{Transport: fake})
		if err := p.OnValidateNewPassword(t.Context(), path, sample); err == nil {
			t.Errorf("missing default screening route %s", path)
		}
	}
	for _, tc := range []struct {
		name, path string
		opts       pwnedpassword.Options
		reject     bool
	}{
		{"enabled by default", "/sign-up/email", pwnedpassword.Options{}, true},
		{"disabled", "/sign-up/email", pwnedpassword.Options{Enabled: &off}, false},
		{"empty path list", "/sign-up/email", pwnedpassword.Options{Paths: []string{}}, false},
		{"custom path", "/custom/set", pwnedpassword.Options{Paths: []string{"/custom/set"}}, true},
		{"enabled with custom path and message", "/custom/set", pwnedpassword.Options{Enabled: &on, Paths: []string{"/custom/set"}, CustomPasswordCompromisedMessage: "Choose another password"}, true},
		{"replaced defaults", "/sign-up/email", pwnedpassword.Options{Paths: []string{"/custom/set"}}, false},
		{"native initial credential outside defaults", "/set-password", pwnedpassword.Options{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Transport = fake
			p := pwnedpassword.New(tc.opts)
			before := calls
			var err error
			if p.OnValidateNewPassword != nil {
				err = p.OnValidateNewPassword(t.Context(), tc.path, sample)
			}
			if (err != nil) != tc.reject || (calls != before) != tc.reject {
				t.Fatalf("route selection: %v (%d requests)", err, calls-before)
			}
			if tc.reject {
				want := tc.opts.CustomPasswordCompromisedMessage
				if want == "" {
					want = "The password you entered has been compromised. Please choose a different password."
				}
				var api *authn.APIError
				if !errors.As(err, &api) || api.Status != http.StatusBadRequest || api.Code != "PASSWORD_COMPROMISED" || api.Message != want {
					t.Fatalf("password policy returned %v, expected PASSWORD_COMPROMISED with message %q", err, want)
				}
			}
		})
	}
}
