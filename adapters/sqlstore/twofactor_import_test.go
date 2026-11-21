package sqlstore

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestImportedAuthenticatorAcrossSQLServers(t *testing.T) {
	const canonical = "JBSWY3DPEHPK3PXP"
	opts := twofactor.Options{Issuer: "Imported accounts", TOTP: twofactor.TOTPOptions{Digits: 8, Period: 45 * time.Second}}
	withFactorDatabases(t, opts, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		password := "local-import-fixture-password"
		email := strings.ToLower(rand.Text()) + "@example.test"
		account, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Name: "Existing account", Email: email, Password: password}, auth.RequestMeta{})
		must(err)
		id := account.User.ID
		otherID := strings.ToLower(id)
		if otherID == id {
			otherID = strings.ToUpper(id)
		}
		if otherID == id {
			otherID += "-missing"
		}
		if err := h.first.ImportTOTP(ctx, otherID, canonical); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("case-changed owner ID: %v", err)
		}
		if err := h.first.ImportTOTP(ctx, id, "invalid seed"); err == nil {
			t.Fatal("invalid import succeeded")
		}
		_, _, err = h.store.Session(ctx, account.Token)
		must(err)
		result := make(chan error, 2)
		start := make(chan struct{})
		for _, node := range []*auth.Auth{h.first, h.second} {
			go func() {
				<-start
				result <- node.ImportTOTP(ctx, id, strings.ToLower(canonical))
			}()
		}
		close(start)
		a, b := <-result, <-result
		if a != nil {
			a, b = b, a
		}
		must(a)
		var conflict *auth.APIError
		if !errors.As(b, &conflict) || conflict.Status != 409 {
			t.Fatalf("concurrent imports did not preserve the first enrollment: %v", b)
		}
		if _, _, err := h.store.Session(ctx, account.Token); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("pre-import session survived: %v", err)
		}
		codes, err := h.second.ViewBackupCodes(ctx, id)
		must(err)
		if len(codes) != 0 {
			t.Fatal("unexpected recovery codes on import")
		}
		var stored string
		must(h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "secret" FROM "twoFactor" WHERE "userId"=?`), id).Scan(&stored))
		if !strings.HasPrefix(stored, "authn.v1.") || strings.Contains(strings.ToUpper(stored), canonical) {
			t.Fatal("imported material was not stored in the local encrypted envelope")
		}
		login := map[string]string{"email": email, "password": password}
		first := h.cookie(h.request(h.first, "sign-in/email", login, 200), "two_factor")
		second := h.cookie(h.request(h.second, "sign-in/email", login, 200), "two_factor")
		code, err := totp.GenerateCodeCustom(canonical, time.Now(), totp.ValidateOpts{Period: 45, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA1})
		must(err)
		loginResult := h.request(h.second, "two-factor/verify-totp", map[string]string{"code": code}, 200, first)
		session := h.cookie(loginResult, "session_token")
		h.request(h.first, "two-factor/verify-totp", map[string]string{"code": code}, 401, second)
		resp := h.request(h.first, "two-factor/get-totp-uri", map[string]string{"password": password}, 200, session)
		var uri struct {
			URL string `json:"totpURI"`
		}
		must(json.NewDecoder(resp.Body).Decode(&uri))
		u, err := url.Parse(uri.URL)
		must(err)
		if q := u.Query(); q.Get("secret") != canonical || q.Get("digits") != "8" || q.Get("period") != "45" {
			t.Fatal("imported authenticator URI lost the external key, digit count or period")
		}
		h.request(h.first, "two-factor/import-totp", map[string]string{}, 404, session)

		pending, err := h.first.SignUpEmail(ctx, auth.SignUpInput{Name: "Pending enrollment", Email: strings.ToLower(rand.Text()) + "@example.test", Password: password}, auth.RequestMeta{})
		must(err)
		originalSession := h.first.SessionCookie(pending.Token, true)
		h.request(h.first, "two-factor/enable", map[string]string{"password": password}, 200, originalSession)
		err = h.second.ImportTOTP(ctx, pending.User.ID, canonical)
		if !errors.As(err, &conflict) || conflict.Status != 409 {
			t.Fatalf("import replaced a pending enrollment: %v", err)
		}
		_, _, err = h.store.Session(ctx, pending.Token)
		must(err)
	})
}
