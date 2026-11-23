package authtest_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/authtest"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/emailotp"
	"github.com/Plain-Org/plain-auth/plugins/phonenumber"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestFactories(t *testing.T) {
	user := authtest.NewUser()
	if user.Name != "Test User" || !user.EmailVerified || user.ID == "" || user.CreatedAt.IsZero() || !user.CreatedAt.Equal(user.UpdatedAt) || !regexp.MustCompile(`^test-[a-z0-9]{8}@example\.com$`).MatchString(user.Email) {
		t.Fatal("user defaults", user)
	}
	other := authtest.NewUser()
	user.EmailVerified = false
	if user.ID == other.ID || user.Email == other.Email || !other.EmailVerified {
		t.Fatal("fixtures not independent")
	}
	org := authtest.NewOrganization("Cloud   Team")
	if org.Name != "Cloud   Team" || !regexp.MustCompile(`^cloud-team-[a-z0-9]{4}$`).MatchString(org.Slug) || org.ID == "" || org.CreatedAt.IsZero() {
		t.Fatal("organization defaults", org)
	}
	if other := authtest.NewOrganization(""); other.Name != "Test Organization" || other.ID == org.ID {
		t.Fatal(other)
	}
}

func TestCapturedProofs(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var proofs, separate authtest.OTPRecorder
	var emailCalls, phoneCalls int
	mail, err := emailotp.New(emailotp.Options{StoreOTP: "hashed", Send: proofs.Email(func(ctx context.Context, m auth.EmailOTPMessage) error {
		code, ok := proofs.Get(m.Email)
		if !ok || code != m.OTP {
			return errors.New("mail delivery did not preserve its code")
		}
		emailCalls++
		return nil
	})})
	must(err)
	phone, err := phonenumber.New(phonenumber.Options{SendOTP: proofs.Phone(func(ctx context.Context, m auth.PhoneOTPMessage) error {
		code, ok := proofs.Get(m.PhoneNumber)
		if !ok || code != m.Code {
			return errors.New("SMS delivery did not preserve its code")
		}
		phoneCalls++
		return nil
	}), SendPasswordResetOTP: proofs.Phone(nil)})
	must(err)
	ddl, err := schema.Generate("sqlite", []string{"phone-number"})
	must(err)
	store, err := sqlstore.OpenWithSchema(ctx, "sqlite", filepath.Join(t.TempDir(), "auth.db"), ddl)
	must(err)
	defer store.Close()
	server := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + server.Listener.Addr().String()
	node, err := auth.New(auth.Options{BaseURL: baseURL, Secret: strings.Repeat("s", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{mail, phone}})
	must(err)
	server.Config.Handler = node
	server.Start()
	defer server.Close()
	c, err := client.New(baseURL, &http.Client{})
	must(err)
	const mailbox, number = "fixture@example.test", "+12025550189"
	_, err = c.SignUpEmail(ctx, client.SignUpRequest{Name: "Fixture", Email: mailbox, Password: "local test password"})
	must(err)
	must(c.SendEmailOTP(ctx, mailbox, emailotp.VerifyEmail))
	code, ok := proofs.Get(mailbox)
	if !ok || code == "" {
		t.Fatal("missing issued email OTP")
	}
	verified, err := c.VerifyEmailOTP(ctx, mailbox, code)
	must(err)
	if !verified.EmailVerified {
		t.Fatal("email proof failed")
	}
	must(c.SendPhoneNumberOTP(ctx, number))
	code, ok = proofs.Get(number)
	if !ok || code == "" {
		t.Fatal("missing SMS OTP")
	}
	phoneResult, err := c.VerifyPhoneNumber(ctx, auth.PhoneVerificationInput{PhoneNumber: number, Code: code, UpdatePhoneNumber: true, DisableSession: true})
	must(err)
	if !phoneResult.Status || phoneResult.User.ID != verified.ID {
		t.Fatal("phone proof changed owner")
	}
	if emailCalls != 1 || phoneCalls != 1 {
		t.Fatalf("email %d, SMS %d", emailCalls, phoneCalls)
	}
	if _, ok := separate.Get(mailbox); ok {
		t.Fatal("test servers shared OTPs")
	}
	proofs.Clear()
	for _, address := range []string{mailbox, number} {
		if _, ok := proofs.Get(address); ok {
			t.Fatal("clear retained an OTP")
		}
	}
}

func TestRecorderConcurrencyAndDeliveryErrors(t *testing.T) {
	var r authtest.OTPRecorder
	want := errors.New("delivery failed")
	send := r.Email(func(context.Context, auth.EmailOTPMessage) error { return want })
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			err := send(t.Context(), auth.EmailOTPMessage{Email: "a@example.test", OTP: "100001"})
			if !errors.Is(err, want) {
				t.Errorf("delivery error became %v", err)
			}
			r.Get("a@example.test")
			r.Clear()
		})
	}
	wg.Wait()
	for _, code := range []string{"100002", "100003"} {
		if err := send(t.Context(), auth.EmailOTPMessage{Email: "a@example.test", OTP: code}); !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	if code, ok := r.Get("a@example.test"); !ok || code != "100003" {
		t.Fatal("missing latest issued code")
	}
}
