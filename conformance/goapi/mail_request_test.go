package goapi_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// Give mail senders a body-free copy of the HTTP request that caused the
// mail, and none for a direct Go call.
func TestMailSendersReceiveTheRequest(t *testing.T) {
	var reset, verify authn.MailLink
	off := false
	auth, err := authn.New(authn.Options{
		BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		SendResetPassword:     func(_ context.Context, m authn.MailLink) error { reset = m; return nil },
		SendVerificationEmail: func(_ context.Context, m authn.MailLink) error { verify = m; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := auth.SignUpEmail(t.Context(), authn.SignUpInput{Email: "ada@example.com", Password: "correct horse battery", Name: "Ada"}, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, body string, cookie *http.Cookie) {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header = http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}, "X-Request-Id": {"req-42"}}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		auth.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body)
		}
	}
	check := func(name string, m authn.MailLink) {
		t.Helper()
		if m.Request == nil || m.Request.Header.Get("X-Request-Id") != "req-42" || m.Request.URL.Path == "" {
			t.Fatal(name, "mail lacks the request", m.Request)
		}
		if data, _ := io.ReadAll(m.Request.Body); len(data) != 0 {
			t.Fatal(name, "mail request kept its body")
		}
	}

	post("/request-password-reset", `{"email":"ada@example.com","redirectTo":"/reset"}`, nil)
	check("reset", reset)
	post("/send-verification-email", `{"email":"ada@example.com"}`, auth.SessionCookie(account.Token, false))
	check("verification", verify)

	// A direct Go call has no request.
	if err := auth.RequestPasswordReset(t.Context(), "ada@example.com", "/reset"); err != nil {
		t.Fatal(err)
	}
	if reset.Request != nil {
		t.Fatal("a Go call passed a request to the mail sender")
	}
}
