package goapi_test

import (
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/authtest"
)

// With OverrideDefaultEmailVerification, the plugin's
// SendVerificationOnSignUp sends the sign-up code, as it says, and a core
// SendVerificationOnSignUp set to false conflicts with it in New.
func TestEmailOTPSignUpCodeWithOverride(t *testing.T) {
	ctx := t.Context()
	build := func(core *bool, plugin bool) (*authn.Auth, *authtest.OTPRecorder, error) {
		recorder := new(authtest.OTPRecorder)
		codes, err := authn.NewEmailOTP(authn.EmailOTPOptions{OverrideDefaultEmailVerification: true, SendVerificationOnSignUp: plugin, Send: recorder.Email(nil)})
		if err != nil {
			t.Fatal(err)
		}
		off := false
		a, err := authn.New(authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
			SendVerificationOnSignUp: core, Plugins: []authn.Plugin{codes}})
		return a, recorder, err
	}
	signUp := func(a *authn.Auth, email string) {
		t.Helper()
		if _, err := a.SignUpEmail(ctx, authn.SignUpInput{Name: "otp", Email: email, Password: "local fixture password"}, authn.RequestMeta{}); err != nil {
			t.Fatal(err)
		}
	}
	// The plugin option alone sends the code.
	a, recorder, err := build(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	signUp(a, "plugin@example.test")
	code, ok := recorder.Get("plugin@example.test")
	if !ok || code == "" {
		t.Fatal("the plugin's SendVerificationOnSignUp sent no code with the override on")
	}
	if _, err := a.VerifyEmailOTP(ctx, "plugin@example.test", code); err != nil {
		t.Fatal("the sign-up code did not verify the address", err)
	}
	// Neither option sends nothing, as before.
	a, recorder, err = build(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	signUp(a, "neither@example.test")
	if _, ok := recorder.Get("neither@example.test"); ok {
		t.Fatal("a sign-up code was sent without either option")
	}
	// A core option set to false conflicts with the plugin's.
	no := false
	if _, _, err := build(&no, true); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatal("New accepted conflicting sign-up verification options", err)
	}
}
