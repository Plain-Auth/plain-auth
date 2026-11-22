package plainauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

func TestAccountRecoveryAndProfile(t *testing.T) {
	off := false
	var reset, verify []authn.MailLink
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off, RevokeSessionsOnPasswordReset: true,
		SendResetPassword:     func(_ context.Context, m authn.MailLink) error { reset = append(reset, m); return nil },
		SendVerificationEmail: func(_ context.Context, m authn.MailLink) error { verify = append(verify, m); return nil },
	})
	empty := http.Header{"Content-Type": {"application/json"}, "Origin": {"https://auth.example"}}
	signed := empty.Clone()
	const email = "account@example.test"
	register := serve(t, auth, "POST", "/api/auth/sign-up/email", `{"name":"Person","email":"account@example.test","password":"correct password"}`, empty, 200)
	cookie := register.Cookies()[0]
	signed.Set("Cookie", cookie.Name+"="+cookie.Value)
	post := func(path, body string, h http.Header, status int) *http.Response {
		t.Helper()
		return serve(t, auth, "POST", "/api/auth/"+path, body, h, status)
	}
	post("verify-password", `{"password":"incorrect"}`, signed, 400)
	post("verify-password", `{"password":"correct password"}`, signed, 200)
	post("update-user", `{"name":"New Name","image":"https://app.example/image.png"}`, signed, 200)
	session, err := auth.GetSession(t.Context(), signed)
	if err != nil || session == nil || session.User.Name != "New Name" || session.User.Image == nil {
		t.Fatalf("profile update failed: %+v %v", session, err)
	}
	post("update-user", `{"image":null}`, signed, 200)
	post("update-user", `{"email":"alternate@example.test"}`, signed, 400)
	post("send-verification-email", `{"email":"other@example.test"}`, signed, 400)
	post("send-verification-email", `{"email":"account@example.test","callbackURL":"/welcome"}`, signed, 200)
	if len(verify) != 1 || verify[0].User.Email != email {
		t.Fatal("verification delivery did not reach the account owner")
	}
	v, err := url.Parse(verify[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	if got := serve(t, auth, "GET", v.RequestURI(), "", nil, 302).Header.Get("Location"); got != "/welcome" {
		t.Fatalf("unexpected confirmation location: %q", got)
	}
	serve(t, auth, "GET", v.RequestURI(), "", nil, 302)
	session, err = auth.GetSession(t.Context(), signed)
	if err != nil || session == nil || !session.User.EmailVerified || session.User.Image != nil {
		t.Fatalf("verification not reflected in session: %+v %v", session, err)
	}
	post("send-verification-email", `{"email":"account@example.test"}`, signed, 400)
	post("change-password", `{"currentPassword":"incorrect","newPassword":"replaced password"}`, signed, 400)
	change := post("change-password", `{"currentPassword":"correct password","newPassword":"replaced password","revokeOtherSessions":true}`, signed, 200)
	if len(change.Cookies()) == 0 {
		t.Fatal("missing replacement session")
	}
	post("verify-password", `{"password":"replaced password"}`, signed, 401)
	cookie = change.Cookies()[0]
	signed.Set("Cookie", cookie.Name+"="+cookie.Value)
	post("verify-password", `{"password":"replaced password"}`, signed, 200)
	missing := post("request-password-reset", `{"email":"missing@example.test"}`, empty, 200)
	present := post("request-password-reset", `{"email":"account@example.test","redirectTo":"/choose?theme=light"}`, empty, 200)
	a, _ := io.ReadAll(missing.Body)
	b, _ := io.ReadAll(present.Body)
	if string(a) != string(b) || len(reset) != 1 {
		t.Fatalf("unexpected reset response or deliveries %q %q, %d", a, b, len(reset))
	}
	resetURL, err := url.Parse(reset[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	dest := serve(t, auth, "GET", resetURL.RequestURI(), "", nil, 302).Header.Get("Location")
	redirect, err := url.Parse(dest)
	if err != nil || redirect.Query().Get("token") != reset[0].Token || redirect.Query().Get("theme") != "light" {
		t.Fatalf("unexpected reset redirect %s", dest)
	}
	data, _ := json.Marshal(map[string]string{"newPassword": "too", "token": reset[0].Token})
	post("reset-password", string(data), empty, 400)
	data, _ = json.Marshal(map[string]string{"newPassword": "recovered password", "token": reset[0].Token})
	post("reset-password", string(data), empty, 200)
	post("reset-password", string(data), empty, 400)
	post("verify-password", `{"password":"recovered password"}`, signed, 401)
	post("sign-in/email", `{"email":"account@example.test","password":"recovered password"}`, empty, 200)
}

func TestOneWinnerForResetAndExpiredLinks(t *testing.T) {
	off := false
	var link authn.MailLink
	auth := newHTTPAuth(t, authn.Options{BaseURL: "http://auth.example", RateLimit: &off, SendResetPassword: func(_ context.Context, m authn.MailLink) error { link = m; return nil }})
	ctx := t.Context()
	input := authn.SignUpInput{Name: "Example", Email: "race@example.test", Password: "initial password"}
	_, err := auth.SignUpEmail(ctx, input, authn.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if err = auth.RequestPasswordReset(ctx, input.Email, "/"); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, password := range []string{"first changed password", "second changed password"} {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- auth.ResetPassword(ctx, link.Token, password) }()
	}
	wg.Wait()
	close(errs)
	var successes, spent int
	for err := range errs {
		var apiErr *authn.APIError
		switch {
		case err == nil:
			successes++
		case errors.As(err, &apiErr) && apiErr.Code == "INVALID_TOKEN":
			spent++
		default:
			t.Fatalf("unexpected result %v", err)
		}
	}
	if successes != 1 || spent != 1 {
		t.Fatalf("successful resets %d, consumed token results %d", successes, spent)
	}

	expiring := newHTTPAuth(t, authn.Options{BaseURL: "http://auth.example", RateLimit: &off, PasswordResetTokenTTL: time.Nanosecond, SendResetPassword: func(_ context.Context, m authn.MailLink) error { link = m; return nil }})
	if _, err = expiring.SignUpEmail(ctx, input, authn.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if err = expiring.RequestPasswordReset(ctx, input.Email, "/"); err != nil {
		t.Fatal(err)
	}
	var apiErr *authn.APIError
	if err = expiring.ResetPassword(ctx, link.Token, "changed after expiry"); !errors.As(err, &apiErr) || apiErr.Code != "INVALID_TOKEN" {
		t.Fatalf("expired reset link: %v", err)
	}
}

func TestMailFeatureDefaultsAndCallbackTrust(t *testing.T) {
	off := false
	auth := newHTTPAuth(t, authn.Options{BaseURL: "https://auth.example", RateLimit: &off})
	h := http.Header{"Content-Type": {"application/json"}}
	for _, c := range []struct{ path, code string }{{"send-verification-email", "VERIFICATION_EMAIL_NOT_ENABLED"}, {"request-password-reset", "RESET_PASSWORD_DISABLED"}} {
		res := serve(t, auth, "POST", "/api/auth/"+c.path, `{"email":"example@test.example"}`, h, 400)
		body, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(body), c.code) {
			t.Errorf("expected %s: %s", c.code, body)
		}
	}
	serve(t, auth, "GET", "/api/auth/verify-email?token=test&callbackURL=https://another.example", "", nil, 403)
	serve(t, auth, "GET", "/api/auth/reset-password/test?callbackURL=https://another.example", "", nil, 403)
}
