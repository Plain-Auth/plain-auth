package client_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth/client"
)

type environmentTransport func(*http.Request) (*http.Response, error)

func (f environmentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientEnvironmentURL(t *testing.T) {
	t.Setenv("AUTH_URL", "")
	for _, name := range []string{"APP_URL", "PUBLIC_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL", "NEXT_PUBLIC_AUTH_URL", "NEXTAUTH_URL", "VERCEL_URL"} {
		t.Setenv(name, "https://external.example.org/unrelated")
	}
	checkEnvironmentClient(t, "", "")
	t.Setenv("AUTH_URL", "https://auth.example.org")
	checkEnvironmentClient(t, "", "https://auth.example.org/api/auth/get-session")
	t.Setenv("AUTH_URL", "https://auth.example.org/mounted")
	checkEnvironmentClient(t, "", "https://auth.example.org/mounted/get-session")
	checkEnvironmentClient(t, "https://explicit.example.org/login", "https://explicit.example.org/login/get-session")
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
