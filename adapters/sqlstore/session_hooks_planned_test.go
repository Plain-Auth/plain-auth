package sqlstore

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/Plain-Org/plain-auth/schema"
)

// Run the session create hooks for sessions a store issues inside its own
// transaction: two-factor sign-in and verification, device grants and the
// sign-in after an email link, on three engines.
func TestSessionHooksForFactorDeviceAndVerification(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"two-factor", "device-authorization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			skip := false
			device, err := auth.NewDeviceAuthorization(auth.DeviceAuthorizationOptions{ValidateClient: func(_ context.Context, id string) (bool, error) { return id == "tv", nil }})
			must(err)
			var mail auth.MailLink
			off := false
			host, err := auth.New(auth.Options{
				BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
				AutoSignInAfterVerification: true,
				SendVerificationEmail:       func(_ context.Context, m auth.MailLink) error { mail = m; return nil },
				Plugins:                     []auth.Plugin{twofactor.New(twofactor.Options{Issuer: "Hooks"}), device},
				DatabaseHooks: auth.DatabaseHooks{Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
					Before: func(_ context.Context, s *auth.SessionRecord, c *auth.HookContext) error {
						record("before:" + c.Path)
						s.UserAgent = "hooked"
						if skip {
							return auth.ErrSkipWrite
						}
						return nil
					},
					After: func(ctx context.Context, s auth.SessionRecord, c *auth.HookContext) error {
						stored, _, err := store.Session(ctx, s.Token)
						if err != nil || stored.UserAgent != "hooked" {
							t.Error("the after hook did not see the hooked session", err)
						}
						record("after:" + c.Path)
						return nil
					},
				}}},
			})
			must(err)
			send := func(method, path, body, media string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Origin", "https://auth.example")
				if media != "" {
					r.Header.Set("Content-Type", media)
				}
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			cookie := func(w *httptest.ResponseRecorder, suffix string) *http.Cookie {
				for _, c := range w.Result().Cookies() {
					if strings.HasSuffix(c.Name, suffix) && c.MaxAge >= 0 && c.Value != "" {
						return c
					}
				}
				t.Fatal("missing cookie", suffix, w.Header().Values("Set-Cookie"))
				return nil
			}
			const jsonType = "application/json"
			signIn := `{"email":"ada@example.com","password":"correct horse battery"}`
			w := send("POST", "/sign-up/email", `{"email":"ada@example.com","password":"correct horse battery","name":"Ada"}`, jsonType)
			if w.Code != 200 {
				t.Fatal("sign-up failed", w.Code, w.Body)
			}
			seen()

			// With two-factor enabled for the instance, a password sign-in issues its session in the factor transaction.
			w = send("POST", "/sign-in/email", signIn, jsonType)
			if w.Code != 200 || seen() != "before:/sign-in/email,after:/sign-in/email" {
				t.Fatal("unexpected factor sign-in hooks", w.Code, w.Body)
			}
			session := cookie(w, "session_token")
			skip = true
			if w = send("POST", "/sign-in/email", signIn, jsonType); w.Code != 401 || !strings.Contains(w.Body.String(), "FAILED_TO_CREATE_SESSION") {
				t.Fatal("a skipped factor sign-in was not refused", w.Code, w.Body)
			}
			skip = false
			seen()

			// After enrolling an authenticator, the sign-in issues a challenge and the verification issues the session.
			w = send("POST", "/two-factor/enable", `{"password":"correct horse battery"}`, jsonType, session)
			var setup struct{ TOTPURI string }
			must(json.Unmarshal(w.Body.Bytes(), &setup))
			u, _ := url.Parse(setup.TOTPURI)
			secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
			must(err)
			code, err := host.GenerateTOTP(string(secret))
			must(err)
			if w = send("POST", "/two-factor/verify-totp", `{"code":"`+code+`"}`, jsonType, session); w.Code != 200 {
				t.Fatal("enrollment failed", w.Code, w.Body)
			}
			// Enrollment rotates the session through the hooks too.
			if got := seen(); !strings.Contains(got, "before:/two-factor/") || strings.Count(got, "before:") != strings.Count(got, "after:") {
				t.Fatal("unexpected enrollment hooks", got)
			}
			w = send("POST", "/sign-in/email", signIn, jsonType)
			if !strings.Contains(w.Body.String(), "twoFactorRedirect") || seen() != "" {
				t.Fatal("a factor challenge issued a session", w.Body)
			}
			challenge := cookie(w, "two_factor")
			time.Sleep(time.Second) // a fresh code for the next TOTP window is not reused
			code, err = host.GenerateTOTP(string(secret))
			must(err)
			if w = send("POST", "/two-factor/verify-totp", `{"code":"`+code+`"}`, jsonType, challenge); w.Code != 200 {
				t.Fatal("factor verification failed", w.Code, w.Body)
			}
			if got := seen(); got != "before:/two-factor/verify-totp,after:/two-factor/verify-totp" {
				t.Fatal("unexpected factor verification hooks", got)
			}
			session = cookie(w, "session_token")

			// An approved device grant issues its session through the hooks.
			const form = "application/x-www-form-urlencoded"
			w = send("POST", "/device/code", "client_id=tv", form)
			var grant struct{ DeviceCode, UserCode string }
			var raw map[string]any
			must(json.Unmarshal(w.Body.Bytes(), &raw))
			grant.DeviceCode, _ = raw["device_code"].(string)
			grant.UserCode, _ = raw["user_code"].(string)
			send("GET", "/device?user_code="+url.QueryEscape(grant.UserCode), "", "", session)
			if w = send("POST", "/device/approve", `{"userCode":"`+grant.UserCode+`"}`, jsonType, session); w.Code != 200 {
				t.Fatal("device approval failed", w.Code, w.Body)
			}
			seen()
			w = send("POST", "/device/token", url.Values{"grant_type": {auth.DeviceGrantType}, "device_code": {grant.DeviceCode}, "client_id": {"tv"}}.Encode(), form)
			if w.Code != 200 || seen() != "before:/device/token,after:/device/token" {
				t.Fatal("unexpected device grant hooks", w.Code, w.Body)
			}

			// Opening an email verification link in a fresh browser signs it in through the hooks.
			if w = send("POST", "/sign-up/email", `{"email":"grace@example.com","password":"correct horse battery","name":"Grace"}`, jsonType); w.Code != 200 {
				t.Fatal("sign-up failed", w.Code, w.Body)
			}
			must(host.SendVerificationEmail(ctx, http.Header{"Cookie": {cookie(w, "session_token").String()}}, "grace@example.com", "/done"))
			seen()
			if w = send("GET", "/verify-email?token="+url.QueryEscape(mail.Token)+"&callbackURL=/done", "", ""); w.Code != 302 {
				t.Fatal("verification failed", w.Code, w.Body)
			}
			if got := seen(); got != "before:/verify-email,after:/verify-email" {
				t.Fatal("unexpected verification sign-in hooks", got)
			}
		})
	}
}
