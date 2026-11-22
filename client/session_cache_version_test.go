package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	"github.com/Stonewrit/stonewrit-auth/client"
)

func TestClientSessionCacheVersionAcrossInstances(t *testing.T) {
	for _, strategy := range []auth.SessionCookieCacheStrategy{auth.SessionCacheCompact, auth.SessionCacheJWT, auth.SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) {
			const origin = "https://client.example.test"
			store := memory.New()
			revision := "r1"
			opts := auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true,
				SessionCookieCache: &auth.SessionCookieCacheOptions{Strategy: strategy, VersionFor: func(_ context.Context, session auth.Session, user auth.User) (string, error) {
					if revision == "" {
						return "", errors.New("private version source error")
					}
					return revision + "/" + session.ID + "/" + user.ID, nil
				}}}
			first, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			second, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			selected := first
			c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				selected.ServeHTTP(w, r)
				return w.Result(), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			account, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Original", Email: "user@example.test", Password: "local-version-client"})
			if err != nil {
				t.Fatal(err)
			}
			current := "Live"
			if err := store.UpdateProfile(ctx, account.User.ID, auth.ProfileUpdate{Name: &current}, time.Now()); err != nil {
				t.Fatal(err)
			}
			selected = second
			readName := func(want string) {
				t.Helper()
				data, err := c.GetSession(ctx)
				if err != nil || data == nil || data.User.Name != want {
					t.Fatal("unexpected browser session", data, err)
				}
			}
			readName("Original")
			revision = "r2"
			readName("Live")
			selected = first
			if err := store.DeleteSession(ctx, *account.Token); err != nil {
				t.Fatal(err)
			}
			readName("Live")
			revision = ""
			_, err = c.GetSession(ctx)
			var public *auth.APIError
			if !errors.As(err, &public) || public.Code != "FAILED_TO_GET_SESSION" {
				t.Fatal("private version source returned no typed client error", err)
			}
			real, err := client.GetSessionViewWithOptions[auth.SessionResult](ctx, c, client.SessionReadOptions{DisableCookieCache: true, DisableRefresh: true})
			if err != nil || real != nil {
				t.Fatal("forced store read returned a revoked session", real, err)
			}
		})
	}
}

// A private registration has no authenticated session to version. Host account
// observers should still see the persisted owner and a metadata-only request.
func TestSessionCacheVersionWithPrivateSignupAndPasswordRecovery(t *testing.T) {
	const origin = "https://client.example.test"
	const email = "owner@example.test"
	store := memory.New()
	versions, duplicates, resets := 0, 0, 0
	var ownerID, resetToken string
	opts := auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("s", 32),
		DisableAutoSignIn: true, EmailAndPassword: true, RevokeSessionsOnPasswordReset: true,
		SessionCookieCache: &auth.SessionCookieCacheOptions{
			Strategy: auth.SessionCacheJWE,
			VersionFor: func(_ context.Context, session auth.Session, user auth.User) (string, error) {
				versions++
				if user.ID != ownerID || session.UserID != ownerID {
					return "", errors.New("unexpected version callback owner")
				}
				return "own-session", nil
			},
		},
		OnExistingUserSignUp: func(_ context.Context, user auth.User, r *http.Request) error {
			duplicates++
			if user.ID != ownerID || user.Name != "Stored" || r == nil || r.URL.Path != "/api/auth/sign-up/email" || r.Body != http.NoBody || r.GetBody != nil {
				t.Fatal("private registration observer saw an unexpected owner or request")
			}
			return errors.New("private delivery failure")
		},
		SendResetPassword: func(_ context.Context, message auth.MailLink) error { resetToken = message.Token; return nil },
		OnPasswordReset: func(_ context.Context, user auth.User, r *http.Request) error {
			resets++
			if user.ID != ownerID || r == nil || r.URL.Path != "/api/auth/reset-password" || r.Body != http.NoBody || r.GetBody != nil {
				t.Fatal("password reset observer saw an unexpected owner or request")
			}
			return nil
		},
	}
	selected, err := auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	var issued []*http.Cookie
	c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		selected.ServeHTTP(w, r)
		response := w.Result()
		issued = response.Cookies()
		return response, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	registered, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Stored", Email: email, Password: "original-password"})
	if err != nil || registered.Token != nil || len(issued) != 0 {
		t.Fatal("protected registration issued credentials", err)
	}
	ownerID = registered.User.ID
	again := client.SignUpRequest{Name: "Submitted", Email: email, Password: "duplicate-password"}
	synthetic, err := c.SignUpEmail(ctx, again)
	if err != nil || synthetic.Token != nil || synthetic.User.Name != "Submitted" || synthetic.User.ID == ownerID || duplicates != 1 || versions != 0 || len(issued) != 0 {
		t.Fatal("protected duplicate registration leaked account information or invoked the cache", err)
	}
	opts.DisableAutoSignIn = false
	selected, err = auth.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SignUpEmail(ctx, again)
	var public *auth.APIError
	if !errors.As(err, &public) || public.Code != "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" || versions != 0 || duplicates != 1 || len(issued) != 0 {
		t.Fatal("ordinary duplicate signup unexpectedly invoked a host callback or issued credentials", err)
	}
	if err := c.RequestPasswordReset(ctx, email, "/recover"); err != nil || resetToken == "" {
		t.Fatal("reset invitation missing", err)
	}
	if err := c.ResetPassword(ctx, resetToken, "replacement-password"); err != nil || resets != 1 || versions != 0 || len(issued) != 0 {
		t.Fatal("password reset unexpectedly invoked cache versioning or issued credentials", err)
	}
	if err := c.ResetPassword(ctx, resetToken, "different-password"); err == nil || resets != 1 {
		t.Fatal("consumed reset replayed")
	}
	login, err := c.SignInEmail(ctx, client.SignInRequest{Email: email, Password: "replacement-password"})
	if err != nil || login.User.ID != ownerID || versions != 1 || duplicates != 1 {
		t.Fatal("recovered owner could not acquire its first versioned session", err)
	}
}
