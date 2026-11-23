package sqlstore

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/siwe"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestSIWEContactPromotionWithConfiguredFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			users := map[string]auth.UserField{
				"locale":      {Type: auth.FieldString, Column: "preferred_locale"},
				"privateNote": {Type: auth.FieldString, Hidden: true, ServerOnly: true},
			}
			devices := map[string]auth.SessionField{"device": {Type: auth.FieldString, Required: true, Default: "browser"}}
			store, err := OpenWithAdditionalFields(ctx, dialect, dsn, []string{"siwe"}, schema.AdditionalFields{User: users, Session: devices})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			replica, err := OpenWithAdditionalFields(ctx, dialect, dsn, []string{"siwe"}, schema.AdditionalFields{User: users, Session: devices})
			if err != nil {
				t.Fatal(err)
			}
			defer replica.Close()
			const domain = "wallet.example.test"
			plugin, err := siwe.New(siwe.Options{Domain: domain, RequireEmail: true})
			if err != nil {
				t.Fatal(err)
			}
			httpServer := httptest.NewUnstartedServer(nil)
			off := false
			opts := auth.Options{Store: store, Secret: strings.Repeat("s", 40), BaseURL: "http://" + httpServer.Listener.Addr().String(), RateLimit: &off, UserAdditionalFields: users, SessionAdditionalFields: devices, Plugins: []auth.Plugin{plugin, emailOTPFieldPlugin(t, false)}}
			host, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			httpServer.Config.Handler = host
			httpServer.Start()
			defer httpServer.Close()
			browser, err := client.New(opts.BaseURL, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			const email = "mailbox@wallet-fields.test"
			signer := freshWallet(t)
			message := func(chain int64) string {
				t.Helper()
				nonce, err := browser.SIWENonce(ctx)
				if err != nil {
					t.Fatal(err)
				}
				return walletMessage(signer.address, domain, nonce, chain)
			}
			text := message(1)
			wallet, err := browser.VerifySIWEWithEmail(ctx, text, signer.sign(text), email)
			if err != nil {
				t.Fatal(err)
			}
			if err := host.UpdateTrustedUserFields(ctx, wallet.User.ID, map[string]any{"locale": "fr", "privateNote": "mailbox record"}); err != nil {
				t.Fatal(err)
			}
			if _, err := browser.UpdateSession(ctx, map[string]any{"device": "old-wallet-device"}); err != nil {
				t.Fatal(err)
			}

			// This node cannot populate a required session column. The failure is
			// inside the transaction that clears the old wallet and consumes the OTP.
			opts.Store = replica
			opts.SessionAdditionalFields = map[string]auth.SessionField{"device": {Type: auth.FieldString, Required: true}}
			broken, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := broken.CreateEmailOTP(ctx, email, auth.OTPSignIn)
			if err != nil {
				t.Fatal(err)
			}
			in := auth.EmailOTPSignInInput{Email: email, OTP: proof, AdditionalFields: map[string]any{"locale": "overwritten", "privateNote": "forged"}}
			if result, err := broken.SignInEmailOTP(ctx, in, auth.RequestMeta{}); err == nil || result.Token != "" {
				t.Fatal("an incomplete session committed mailbox promotion", result, err)
			}
			before, err := browser.GetSession(ctx)
			if err != nil || before == nil || before.User.EmailVerified || before.Session.Token != wallet.Token {
				t.Fatal("rolled back mailbox promotion changed wallet access", before, err)
			}
			if device, _ := before.Session.AdditionalField("device"); device != "old-wallet-device" {
				t.Fatal("old session changed during rollback", device)
			}
			if owner, err := replica.WalletOwner(ctx, signer.address); err != nil || owner != wallet.User.ID {
				t.Fatal("rolled back mailbox promotion detached wallet", owner, err)
			}
			checkUserField(t, before.User, "locale", "fr")

			opts.SessionAdditionalFields = devices
			repaired, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := repaired.SignInEmailOTP(ctx, in, auth.RequestMeta{})
			if err != nil || recovered.User.ID != wallet.User.ID || !recovered.User.EmailVerified || recovered.Token == "" || recovered.Token == wallet.Token {
				t.Fatal("could not finish rolled-back proof", recovered, err)
			}
			checkUserField(t, recovered.User, "locale", "fr")
			if _, ok := recovered.User.AdditionalField("privateNote"); ok {
				t.Fatal("hidden profile field in mailbox response")
			}
			var private string
			if err := replica.db.QueryRowContext(ctx, replica.bind(`SELECT "privateNote" FROM "user" WHERE "id"=?`), wallet.User.ID).Scan(&private); err != nil || private != "mailbox record" {
				t.Fatal("hidden mailbox profile overwritten", private, err)
			}
			current, err := repaired.GetSession(ctx, http.Header{"Cookie": {repaired.SessionCookie(recovered.Token, true).String()}})
			if err != nil || current == nil {
				t.Fatal(err)
			}
			if got, ok := current.Session.AdditionalField("device"); !ok || got != "browser" {
				t.Fatal("mailbox session inherited a wallet device field", got)
			}
			if _, _, err := replica.Session(ctx, wallet.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("old wallet session survived promotion", err)
			}
			if owner, err := store.WalletOwner(ctx, signer.address); err != nil || owner != "" {
				t.Fatal("wallet link survived verified mailbox sign-in", owner, err)
			}
			_, err = repaired.SignInEmailOTP(ctx, in, auth.RequestMeta{})
			checkUserFieldError(t, err, "INVALID_OTP")
		})
	}
}
