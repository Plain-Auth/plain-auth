package sqlstore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/emailotp"
)

// A rotate resend, the default, mails and stores a new code with a fresh
// attempt budget, and the earlier code is refused, for plain and encrypted
// storage.
func TestEmailOTPRotatesResentCodes(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				s, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				store = s
			}
			for name, options := range map[string]emailotp.Options{"plain": {}, "encrypted": {StoreOTP: "encrypted", ResendStrategy: "rotate"}} {
				t.Run(name, func(t *testing.T) {
					email := "rotate-" + name + "@example.test"
					var mu sync.Mutex
					var sent []string
					n := 0
					options.GenerateOTP = func(context.Context, string, auth.EmailOTPPurpose) (string, error) {
						mu.Lock()
						defer mu.Unlock()
						n++
						return fmt.Sprintf("%06d", n), nil
					}
					options.Send = func(_ context.Context, m emailotp.Message) error {
						mu.Lock()
						defer mu.Unlock()
						sent = append(sent, m.OTP)
						return nil
					}
					p, err := emailotp.New(options)
					if err != nil {
						t.Fatal(err)
					}
					const origin = "https://rotate.example.test"
					off := false
					a, err := auth.New(auth.Options{Store: store, Secret: "local-email-otp-test-key-0000000000000", BaseURL: origin, RateLimit: &off, Plugins: []auth.Plugin{p}})
					if err != nil {
						t.Fatal(err)
					}
					call := func(path string, body map[string]any) *httptest.ResponseRecorder {
						raw, _ := json.Marshal(body)
						r := httptest.NewRequest("POST", origin+"/api/auth"+path, strings.NewReader(string(raw)))
						r.Header.Set("Content-Type", "application/json")
						r.Header.Set("Origin", origin)
						w := httptest.NewRecorder()
						a.ServeHTTP(w, r)
						return w
					}
					last := func() string {
						mu.Lock()
						defer mu.Unlock()
						return sent[len(sent)-1]
					}
					wrong := func() {
						t.Helper()
						if w := call("/sign-in/email-otp", map[string]any{"email": email, "otp": "999999"}); w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_OTP") {
							t.Fatal("a wrong code answered", w.Code, w.Body)
						}
					}
					if w := call("/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"}); w.Code != 200 {
						t.Fatal("send", w.Code, w.Body)
					}
					first := last()
					wrong()
					if w := call("/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"}); w.Code != 200 {
						t.Fatal("resend", w.Code, w.Body)
					}
					second := last()
					stored, err := a.ReadEmailOTP(ctx, email, auth.OTPSignIn)
					if err != nil || len(sent) != 2 || second == first || stored == nil || *stored != second {
						t.Fatal("a rotate resend did not mail and store a new code", err)
					}
					if w := call("/sign-in/email-otp", map[string]any{"email": email, "otp": first}); w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_OTP") {
						t.Fatal("a rotate resend left the earlier code usable:", w.Code)
					}
					wrong()
					if w := call("/sign-in/email-otp", map[string]any{"email": email, "otp": second}); w.Code != 200 || len(w.Result().Cookies()) == 0 {
						t.Fatal("after a rotate resend the new code did not sign in with a fresh attempt budget:", w.Code, w.Body)
					}
				})
			}
		})
	}
}
