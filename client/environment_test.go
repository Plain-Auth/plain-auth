package client_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nabuhadba/go-better-auth/client"
)

type environmentTransport func(*http.Request) (*http.Response, error)

func (f environmentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientEnvironmentURL(t *testing.T) {
	names := []string{"BETTER_AUTH_URL", "AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL", "NEXT_PUBLIC_AUTH_URL", "NEXTAUTH_URL", "VERCEL_URL"}
	for _, name := range names {
		t.Setenv(name, "")
	}
	cases := []struct {
		name, argument string
		env            map[string]string
		want           string
	}{
		{"explicit", "https://host.example.org", map[string]string{"AUTH_URL": "https://ignore.example.org"}, "https://host.example.org/api/auth/get-session"},
		{"compat precedence", "", map[string]string{"BETTER_AUTH_URL": "https://a.example.org", "AUTH_URL": "https://b.example.org"}, "https://a.example.org/api/auth/get-session"},
		{"common before client", "", map[string]string{"AUTH_URL": "https://host.example.org/custom", "NEXT_PUBLIC_AUTH_URL": "https://ignore.example.org"}, "https://host.example.org/custom/get-session"},
		{"public client before legacy", "", map[string]string{"NEXT_PUBLIC_AUTH_URL": "https://root.example.org/", "NEXTAUTH_URL": "https://ignore.example.org"}, "https://root.example.org/get-session"},
		{"legacy before deployment", "", map[string]string{"NEXTAUTH_URL": "http://next.example.org/router/", "VERCEL_URL": "ignore.example.org"}, "http://next.example.org/router/get-session"},
		{"deployment inferred HTTPS", "", map[string]string{"BASE_URL": "/", "VERCEL_URL": "v.example.org/staging/"}, "https://v.example.org/api/auth/get-session"},
		{"deployment protocol and port", "", map[string]string{"VERCEL_URL": "http://localhost:1000/root?q=abc"}, "http://localhost:1000/api/auth/get-session"},
		{"no origin", "", nil, ""},
		{"relative mount alone", "", map[string]string{"BASE_URL": "/"}, ""},
		{"non-http client alias", "", map[string]string{"NEXTAUTH_URL": "ftp://remote.example.org"}, ""},
	}
	for _, alias := range names[:7] {
		t.Run("common "+alias, func(t *testing.T) {
			t.Setenv(alias, "https://common.example.org")
			checkEnvironmentClient(t, "", "https://common.example.org/api/auth/get-session")
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			checkEnvironmentClient(t, tc.argument, tc.want)
		})
	}
}

func checkEnvironmentClient(t *testing.T, argument, want string) {
	t.Helper()
	var target string
	h := &http.Client{Transport: environmentTransport(func(r *http.Request) (*http.Response, error) {
		target = r.URL.String()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader("null"))}, nil
	})}
	c, err := client.New(argument, h)
	if want == "" {
		if err == nil {
			t.Fatal("expected invalid client URL")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if target != want {
		t.Errorf("request URL %q, want %q", target, want)
	}
}
