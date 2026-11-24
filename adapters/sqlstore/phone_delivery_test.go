package sqlstore

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

// Over HTTP a failed phone code delivery is logged: an unverified sign-in
// still answers 401 and a reset request succeeds. Direct calls return the
// sender's error.
func TestPhoneDeliveryFailuresAreLogged(t *testing.T) {
	ctx := t.Context()
	failure := errors.New("private sms credentials")
	ddl, err := schema.Generate("sqlite", []string{"phone-number"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sends := 0
	phone, err := auth.NewPhoneNumber(auth.PhoneNumberOptions{RequireVerification: true,
		SendOTP:              func(context.Context, auth.PhoneOTPMessage) error { sends++; return failure },
		SendPasswordResetOTP: func(context.Context, auth.PhoneOTPMessage) error { sends++; return failure }})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	node, err := auth.New(auth.Options{Store: db, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true, RateLimit: new(bool), Plugins: []auth.Plugin{phone},
		Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	const number, password = "+15555550100", "a phone test password"
	created, err := node.SignUpEmail(ctx, auth.SignUpInput{Name: "Phone", Email: "phone@example.org", Password: password}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, db.bind(`UPDATE "user" SET "phoneNumber"=?, "phoneNumberVerified"=?, "updatedAt"=? WHERE "id"=?`), number, false, db.date(time.Now()), created.User.ID); err != nil {
		t.Fatal(err)
	}
	call := func(path, body string) (int, string) {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if status, body := call("/sign-in/phone-number", `{"phoneNumber":"`+number+`","password":"`+password+`"}`); status != 401 || !strings.Contains(body, "PHONE_NUMBER_NOT_VERIFIED") || sends != 1 {
		t.Fatal("an unverified phone sign-in answered", status, body, sends)
	}
	if _, err := node.SignInPhoneNumber(ctx, number, password, auth.RequestMeta{}); !errors.Is(err, failure) {
		t.Fatal("a direct phone sign-in returned", err)
	}
	// A reset code goes only to a verified number.
	if _, err := db.db.ExecContext(ctx, db.bind(`UPDATE "user" SET "phoneNumberVerified"=? WHERE "id"=?`), true, created.User.ID); err != nil {
		t.Fatal(err)
	}
	if status, body := call("/phone-number/request-password-reset", `{"phoneNumber":"`+number+`"}`); status != 200 || sends != 3 {
		t.Fatal("a phone reset request answered", status, body, sends)
	}
	out := logs.String()
	if !strings.Contains(out, "Could not deliver phone verification code") || !strings.Contains(out, "Could not deliver phone password reset code") || strings.Contains(out, "private") || strings.Contains(out, number) {
		t.Fatal("the phone delivery failures were logged as", out)
	}
	if err := node.RequestPhonePasswordReset(ctx, number); !errors.Is(err, failure) {
		t.Fatal("a direct phone reset request returned", err)
	}
}
