package stonewrit

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var configEnvNames = []string{"AUTH_ENV", "AUTH_SECRET", "AUTH_SECRETS", "AUTH_URL", "AUTH_TRUSTED_ORIGINS"}

func cleanConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range configEnvNames {
		t.Setenv(key, "")
	}
}

func TestEnvironmentPrecedence(t *testing.T) {
	cleanConfigEnv(t)
	t.Setenv("AUTH_SECRET", strings.Repeat("a", 32))
	t.Setenv("AUTH_URL", "https://auth.test/v1/login")
	t.Setenv("AUTH_TRUSTED_ORIGINS", "https://one.test, https://two.test")
	initial := []string{"https://app.test"}
	a, err := New(Options{Store: &refreshFixture{}, TrustedOrigins: initial})
	if err != nil {
		t.Fatal(err)
	}
	if a.opts.Secret != strings.Repeat("a", 32) || a.opts.BaseURL != "https://auth.test" || a.BasePath() != "/v1/login" || len(a.opts.TrustedOrigins) != 3 {
		t.Fatal("environment configuration not resolved")
	}
	if !a.trustedURL("https://two.test/done", true) || !a.sessionCookie("credential", true).Secure {
		t.Fatal("settings did not reach auth handler")
	}
	explicit := Options{Store: &refreshFixture{}, Secret: strings.Repeat("c", 32), BaseURL: "https://app.test", BasePath: "/login"}
	other, err := New(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if other.opts.BaseURL != explicit.BaseURL || other.opts.Secret != explicit.Secret || other.BasePath() != explicit.BasePath {
		t.Fatal("explicit scalar options lost precedence")
	}
}

func TestEnvironmentIsolation(t *testing.T) {
	cleanConfigEnv(t)
	external := "https://external.example.org"
	for _, key := range []string{"BETTER_AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL", "NEXT_PUBLIC_AUTH_URL", "NEXTAUTH_URL", "VERCEL_URL"} {
		t.Setenv(key, external)
	}
	t.Setenv("BETTER_AUTH_SECRET", strings.Repeat("x", 32))
	t.Setenv("BETTER_AUTH_SECRETS", "9:"+strings.Repeat("y", 32))
	t.Setenv("BETTER_AUTH_TRUSTED_ORIGINS", external)
	t.Setenv("NODE_ENV", "production")
	t.Setenv("TEST", "true")
	opts := Options{Store: &refreshFixture{}}
	if _, err := New(opts); err == nil {
		t.Fatal("external settings supplied startup credentials")
	}
	t.Setenv("AUTH_SECRET", strings.Repeat("z", 32))
	if _, err := New(opts); err == nil {
		t.Fatal("external settings supplied the public origin")
	}
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("AUTH_URL", "http://auth.example.org")
	if _, err := New(opts); err == nil {
		t.Fatal("external settings supplied the signing key")
	}
	t.Setenv("AUTH_SECRET", strings.Repeat("z", 32))
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if a.opts.Secret != strings.Repeat("z", 32) || len(a.opts.Secrets) != 0 || a.opts.BaseURL != "http://auth.example.org" || a.trustedURL(external, false) || a.opts.RateLimit != nil || a.opts.ErrorRedirectURL != "" {
		t.Fatal("external settings changed server configuration")
	}
}

func TestEnvironmentRotation(t *testing.T) {
	cleanConfigEnv(t)
	t.Setenv("AUTH_URL", "https://auth.test")
	old, newKey := strings.Repeat("a", 32), strings.Repeat("b", 32)
	t.Setenv("AUTH_SECRET", old)
	opts := Options{Store: &refreshFixture{}}
	before, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	oldCookie := before.SessionCookie("session", true)
	t.Setenv("AUTH_SECRETS", "2:"+newKey+",1:"+old)
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if a.VerifySignedSessionToken(oldCookie.Value) != "session" || before.VerifySignedSessionToken(a.SessionCookie("session", true).Value) != "" {
		t.Fatal("key rotation failed")
	}
	r := httptest.NewRequest("GET", "/", nil)
	marker := before.sessionCookie("true", false)
	marker.Name = strings.TrimSuffix(marker.Name, "session_token") + "dont_remember"
	r.AddCookie(marker)
	if !a.dontRemember(r) {
		t.Fatal("short-lived session marker lost across rotation")
	}
	opts.Secrets = []VersionedSecret{{2, newKey}}
	removed, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if removed.VerifySignedSessionToken(oldCookie.Value) != "" {
		t.Fatal("retired key still accepted")
	}
	for _, raw := range []string{"x:" + old, "1:" + old + ",1:" + newKey, "1:short", "2:", "-1:" + old} {
		t.Setenv("AUTH_SECRETS", raw)
		if _, err := New(Options{Store: &refreshFixture{}}); err == nil || strings.Contains(err.Error(), old) {
			t.Fatal("invalid settings accepted or leaked")
		}
	}
}

func TestEnvironmentRateLimit(t *testing.T) {
	cleanConfigEnv(t)
	t.Setenv("AUTH_URL", "http://auth.test")
	t.Setenv("AUTH_SECRET", strings.Repeat("a", 32))
	t.Setenv("AUTH_ENV", "production")
	a, err := New(Options{Store: &refreshFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	if a.opts.RateLimit == nil || !*a.opts.RateLimit {
		t.Fatal("production rate limiter disabled")
	}
	off := false
	a, err = New(Options{Store: &refreshFixture{}, RateLimit: &off})
	if err != nil || *a.opts.RateLimit {
		t.Fatal("explicit limiter override lost")
	}
}

func TestRetainedKeyVerifiesEmailProof(t *testing.T) {
	cleanConfigEnv(t)
	old, next := strings.Repeat("x", 32), strings.Repeat("y", 32)
	opts := Options{Store: &refreshFixture{}, BaseURL: "http://localhost", Secret: old}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	err = a.sendEmailProof(context.Background(), User{ID: "tester", Email: "person@example.test"}, "", "", "/", func(_ context.Context, m MailLink) error { raw = m.Token; return nil })
	if err != nil {
		t.Fatal(err)
	}
	opts.Secrets = []VersionedSecret{{2, next}, {1, old}}
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := b.parseEmailProof(raw)
	if err != nil || proof.UserID != "tester" {
		t.Fatal(proof.UserID, err)
	}
	opts.Secrets = opts.Secrets[:1]
	b, err = New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.parseEmailProof(raw); err == nil {
		t.Fatal("retired verification key accepted")
	}
}

func TestSigningKeyListPrecedence(t *testing.T) {
	cleanConfigEnv(t)
	envListKey := strings.Repeat("e", 32)
	optionListKey := strings.Repeat("o", 32)
	t.Setenv("AUTH_SECRETS", "1:"+envListKey)
	t.Setenv("AUTH_SECRET", strings.Repeat("s", 32))
	for _, tc := range []struct {
		name    string
		secrets []VersionedSecret
		want    string
	}{
		{"environment list overrides the explicit scalar", nil, envListKey},
		{"explicit list overrides the environment list", []VersionedSecret{{Version: 2, Value: optionListKey}}, optionListKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(Options{Store: &refreshFixture{}, BaseURL: "http://localhost", Secret: strings.Repeat("x", 32), Secrets: tc.secrets})
			if err != nil {
				t.Fatal(err)
			}
			want := url.QueryEscape("test." + signCookieValue("test", tc.want))
			if a.SessionCookie("test", true).Value != want {
				t.Fatal("session cookie used a lower-priority signing key")
			}
		})
	}
}
