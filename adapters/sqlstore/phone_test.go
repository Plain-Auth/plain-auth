package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/phonenumber"
	"github.com/Plain-Org/plain-auth/schema"
)

func phoneStores(t *testing.T, dialect string) (auth.Store, auth.Store) {
	t.Helper()
	if dialect == "memory" {
		s := memory.New()
		return s, s
	}
	ddl, err := schema.Generate(dialect, []string{"phone-number"})
	if err != nil {
		t.Fatal(err)
	}
	dsn := organizationTestDSN(t, dialect)
	open := func() auth.Store {
		s, err := OpenWithSchema(t.Context(), dialect, dsn, ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	return open(), open()
}

func phoneError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var p *auth.APIError
	if !errors.As(err, &p) || p.Status != status || p.Code != code {
		t.Fatalf("expected %d %s, got %v", status, code, err)
	}
}

func TestPhoneNumberProof(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, peer := phoneStores(t, dialect)
			var sms phonenumber.Message
			p, err := phonenumber.New(phonenumber.Options{SendOTP: func(_ context.Context, m phonenumber.Message) error { sms = m; return nil }, Validate: func(_ context.Context, n string) (bool, error) { return strings.HasPrefix(n, "+"), nil }})
			if err != nil {
				t.Fatal(err)
			}
			off := false
			newAuth := func(s auth.Store) *auth.Auth {
				a, err := auth.New(auth.Options{Plugins: []auth.Plugin{p}, Store: s, Secret: strings.Repeat("s", 48), BaseURL: "https://phone.example.test", RateLimit: &off})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a, b := newAuth(store), newAuth(peer)
			number := "+12025550101"
			phoneError(t, a.SendPhoneNumberOTP(ctx, "invalid"), 400, "INVALID_PHONE_NUMBER")
			if sms.Code != "" {
				t.Fatal("invalid number was delivered")
			}
			server := httptest.NewServer(a)
			defer server.Close()
			sdk, err := client.New(server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = sdk.SendPhoneNumberOTP(ctx, number); err != nil {
				t.Fatal(err)
			}
			if sms.PhoneNumber != number || sms.Purpose != auth.PhoneVerify || !regexp.MustCompile(`^[0-9]{6}$`).MatchString(sms.Code) {
				t.Fatal("invalid SMS delivery")
			}
			if db, ok := store.(*Store); ok {
				var value string
				if err := db.db.QueryRowContext(ctx, db.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "phone-number-otp-"+number).Scan(&value); err != nil || value != sms.Code+":0" {
					t.Fatal("canonical verification row mismatch", err)
				}
			}
			for range 3 {
				phoneError(t, b.ConsumePhoneNumberOTP(ctx, number, "incorrect"), 400, "INVALID_OTP")
			}
			phoneError(t, a.ConsumePhoneNumberOTP(ctx, number, sms.Code), 403, "TOO_MANY_ATTEMPTS")
			phoneError(t, a.ConsumePhoneNumberOTP(ctx, number, sms.Code), 400, "OTP_NOT_FOUND")
			if err := b.SendPhoneNumberOTP(ctx, number); err != nil {
				t.Fatal(err)
			}
			code := sms.Code
			var wg sync.WaitGroup
			results := make(chan error, 12)
			for i := range 12 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					worker := a
					if i%2 != 0 {
						worker = b
					}
					results <- worker.ConsumePhoneNumberOTP(ctx, number, code)
				}()
			}
			wg.Wait()
			close(results)
			wins := 0
			for err := range results {
				if err == nil {
					wins++
				} else {
					phoneError(t, err, 400, "OTP_NOT_FOUND")
				}
			}
			if wins != 1 {
				t.Fatalf("phone OTP was consumed %d times", wins)
			}
			put := func(id, code string, purpose auth.PhoneOTPPurpose, expires time.Time) {
				t.Helper()
				e := store.(auth.PhoneNumberStore).SavePhoneOTP(ctx, auth.PhoneOTPRecord{ID: id, PhoneNumber: number, Code: code, Purpose: purpose, CreatedAt: time.Now().UTC(), ExpiresAt: expires})
				if e != nil {
					t.Fatal(e)
				}
			}
			put("old", "111111", auth.PhoneVerify, time.Now().Add(time.Minute))
			put("new", "222222", auth.PhoneVerify, time.Now().Add(time.Minute))
			put("reset", "333333", auth.PhonePasswordReset, time.Now().Add(time.Minute))
			phoneError(t, b.ConsumePhoneNumberOTP(ctx, number, "111111"), 400, "INVALID_OTP")
			phoneError(t, b.ConsumePhoneNumberOTP(ctx, number, "333333"), 400, "INVALID_OTP")
			if err := b.ConsumePhoneNumberOTP(ctx, number, "222222"); err != nil {
				t.Fatal(err)
			}
			put("expired", "444444", auth.PhoneVerify, time.Now().Add(-time.Second))
			phoneError(t, b.ConsumePhoneNumberOTP(ctx, number, "444444"), 400, "OTP_EXPIRED")
			phoneError(t, b.ConsumePhoneNumberOTP(ctx, number, "444444"), 400, "OTP_NOT_FOUND")
			r := httptest.NewRequest(http.MethodPost, "/api/auth/phone-number/consume-otp", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Fatal("native consume exposed over HTTP", w.Code)
			}
		})
	}
}
