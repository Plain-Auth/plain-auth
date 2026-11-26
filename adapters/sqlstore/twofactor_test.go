package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/pquerna/otp/totp"
)

func TestTwoFactorAcrossAuthInstances(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "twofactor.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_FACTOR_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires dedicated, disposable two-factor database")
				}
			}
			ctx := t.Context()
			baseline, err := schema.Generate(dialect, []string{"two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, dsn, baseline)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			otherStore, err := OpenWithSchema(ctx, dialect, dsn, baseline)
			if err != nil {
				t.Fatal(err)
			}
			defer otherStore.Close()
			off := false
			options := auth.Options{Store: store, BaseURL: "https://auth.example", Secret: "test-only-selected-config-key-at-least-32", EmailAndPassword: true, RateLimit: &off, Plugins: []auth.Plugin{twofactor.New(twofactor.Options{Issuer: "Example"})}}
			var reset auth.MailLink
			options.SendResetPassword = func(_ context.Context, link auth.MailLink) error { reset = link; return nil }
			first, err := auth.New(options)
			if err != nil {
				t.Fatal(err)
			}
			options.Store = otherStore
			second, err := auth.New(options)
			if err != nil {
				t.Fatal(err)
			}
			options.Plugins = nil
			otherStore.factorSchema = false // Simulate a credential server started before the profile migration.
			bare, err := auth.New(options)
			if err != nil {
				t.Fatal(err)
			}
			email := strings.ToLower(rand.Text()) + "@example.test"
			login := auth.SignInInput{Email: email, Password: "long sign in password"}
			reg, err := first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Name: "Test", Password: login.Password}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, q := range []string{`DELETE FROM "verification" WHERE "value"=?`, `DELETE FROM "twoFactor" WHERE "userId"=?`, `DELETE FROM "session" WHERE "userId"=?`, `DELETE FROM "account" WHERE "userId"=?`, `DELETE FROM "user" WHERE "id"=?`} {
					_, _ = store.db.ExecContext(context.Background(), store.bind(q), reg.User.ID)
				}
			}()
			firstCookie := first.SessionCookie(reg.Token, true)
			request := func(instance *auth.Auth, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "https://auth.example/api/auth/"+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", "https://auth.example")
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				instance.ServeHTTP(w, r)
				return w
			}
			check := func(w *httptest.ResponseRecorder, status int) {
				t.Helper()
				if w.Code != status {
					t.Fatalf("wanted %d got %d: %s", status, w.Code, w.Body.String())
				}
			}
			getCookie := func(w *httptest.ResponseRecorder, suffix string) *http.Cookie {
				t.Helper()
				for _, c := range w.Result().Cookies() {
					if strings.HasSuffix(c.Name, suffix) && c.MaxAge >= 0 {
						return c
					}
				}
				t.Fatalf("response lacks cookie %s", suffix)
				return nil
			}
			pwBody := `{"password":"long sign in password"}`
			check(request(first, "two-factor/enable", `{"password":"wrong"}`, firstCookie), 400)
			enroll := request(first, "two-factor/enable", pwBody, firstCookie)
			check(enroll, 200)
			var enrollment struct {
				TotpURI     string
				BackupCodes []string
			}
			if err = json.Unmarshal(enroll.Body.Bytes(), &enrollment); err != nil {
				t.Fatal(err)
			}
			uri, err := url.Parse(enrollment.TotpURI)
			if err != nil || uri.Scheme != "otpauth" || uri.Query().Get("issuer") != "Example" || len(enrollment.BackupCodes) != 10 {
				t.Fatal("invalid provisioning material")
			}
			uriResponse := request(first, "two-factor/get-totp-uri", pwBody, firstCookie)
			check(uriResponse, 200)
			var reread struct{ TotpURI string }
			if err := json.Unmarshal(uriResponse.Body.Bytes(), &reread); err != nil || reread.TotpURI != enrollment.TotpURI {
				t.Fatal("provisioning URI changed")
			}
			secret := uri.Query().Get("secret")
			code, err := totp.GenerateCode(secret, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			var ciphertext, codes string
			if err = store.db.QueryRowContext(ctx, store.bind(`SELECT "secret","backupCodes" FROM "twoFactor" WHERE "userId"=?`), reg.User.ID).Scan(&ciphertext, &codes); err != nil || strings.Contains(ciphertext, secret) || strings.Contains(codes, enrollment.BackupCodes[0]) {
				t.Fatal("unprotected factor material")
			}
			activated := request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), firstCookie)
			check(activated, 200)
			if view, err := second.ViewBackupCodes(ctx, reg.User.ID); err != nil || !slices.Equal(view, enrollment.BackupCodes) {
				t.Fatal("default encrypted backup codes did not read back through ViewBackupCodes", err)
			}
			management := getCookie(activated, ".session_token")
			// Direct callers and even an instance opened without factor middleware
			// must not mint sessions for an enrolled account after a password alone.
			direct, err := first.SignInEmail(ctx, login, auth.RequestMeta{})
			if err != nil || direct.Challenge == nil || direct.Token != "" {
				t.Fatalf("native password sign-in bypassed the challenge: %v", err)
			}
			_, hash, err := store.Credential(ctx, email)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.ChangeCredentialForSession(ctx, reg.User.ID, hash, hash, nil, reg.Token, time.Now()); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("credential change used a revoked session: %v", err)
			}
			nativeChallenge := first.TwoFactorChallengeCookie(*direct.Challenge)
			h := http.Header{"Cookie": {nativeChallenge.Name + "=" + nativeChallenge.Value}}
			if session, err := second.GetSession(ctx, h); err != nil || session != nil {
				t.Fatal("challenge authenticated a session")
			}
			if r, err := bare.SignInEmail(ctx, login, auth.RequestMeta{}); err == nil || r.Token != "" {
				t.Fatal("instance without factor middleware minted a session")
			}
			challenge := func() *http.Cookie {
				raw, _ := json.Marshal(map[string]string{"email": email, "password": login.Password})
				w := request(first, "sign-in/email", string(raw))
				check(w, 200)
				var body struct {
					TwoFactorRedirect bool
					Token             string
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || !body.TwoFactorRedirect || body.Token != "" {
					t.Fatalf("incorrect challenge result: %s", w.Body)
				}
				return getCookie(w, ".two_factor")
			}
			// One challenge and one backup code have a single transactional winner.
			ch := challenge()
			payload := fmt.Sprintf(`{"code":%q}`, enrollment.BackupCodes[0])
			results := make(chan int, 2)
			var wg sync.WaitGroup
			for _, instance := range []*auth.Auth{first, second} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results <- request(instance, "two-factor/verify-backup-code", payload, ch).Code
				}()
			}
			wg.Wait()
			close(results)
			ok, denied := 0, 0
			for status := range results {
				switch status {
				case 200:
					ok++
				case 401:
					denied++
				default:
					t.Fatalf("unexpected concurrent proof status: %d", status)
				}
			}
			if ok != 1 || denied != 1 {
				t.Fatalf("challenge consumption winners=%d denied=%d", ok, denied)
			}
			check(request(second, "two-factor/verify-backup-code", payload, challenge()), 401)
			verified := request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), nativeChallenge)
			check(verified, 200)
			check(request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), nativeChallenge), 401)
			check(request(first, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), challenge()), 401)
			replacement := request(first, "two-factor/generate-backup-codes", pwBody, management)
			check(replacement, 200)
			var replaced struct{ BackupCodes []string }
			if err := json.Unmarshal(replacement.Body.Bytes(), &replaced); err != nil || len(replaced.BackupCodes) != 10 {
				t.Fatal("backup regeneration failed")
			}
			check(request(second, "two-factor/verify-backup-code", fmt.Sprintf(`{"code":%q}`, enrollment.BackupCodes[1]), challenge()), 401)
			proofOnly := challenge()
			suppressed := request(second, "two-factor/verify-backup-code", fmt.Sprintf(`{"code":%q,"disableSession":true}`, replaced.BackupCodes[0]), proofOnly)
			check(suppressed, 200)
			if strings.Contains(suppressed.Body.String(), `"token":`) {
				t.Fatal("suppressed login returned credentials")
			}
			for _, c := range suppressed.Result().Cookies() {
				if strings.HasSuffix(c.Name, ".session_token") && c.MaxAge >= 0 {
					t.Fatal("suppressed login issued a cookie")
				}
			}
			check(request(first, "two-factor/verify-backup-code", fmt.Sprintf(`{"code":%q}`, replaced.BackupCodes[1]), proofOnly), 401)
			preReset := challenge()
			if err := first.RequestPasswordReset(ctx, email, ""); err != nil {
				t.Fatal(err)
			}
			login.Password = "password replaced via mail"
			pwBody = `{"password":"password replaced via mail"}`
			if err := second.ResetPassword(ctx, reset.Token, login.Password); err != nil {
				t.Fatal(err)
			}
			check(request(first, "two-factor/verify-backup-code", fmt.Sprintf(`{"code":%q}`, replaced.BackupCodes[1]), preReset), 401)
			resetProof := request(first, "two-factor/verify-backup-code", fmt.Sprintf(`{"code":%q}`, replaced.BackupCodes[1]), challenge())
			check(resetProof, 200)
			management = getCookie(resetProof, ".session_token")
			expired := challenge()
			id := first.VerifySignedSessionToken(expired.Value)
			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier" IN (?,?)`), store.date(time.Now().Add(-time.Hour)), id, "2fa-attempts-"+id); err != nil {
				t.Fatal(err)
			}
			check(request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), expired), 401)
			spent := challenge()
			for range 5 {
				check(request(second, "two-factor/verify-totp", `{"code":"invalid"}`, spent), 401)
			}
			check(request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), spent), 401)
			locked := challenge()
			for range 5 {
				check(request(second, "two-factor/verify-totp", `{"code":"invalid"}`, locked), 401)
			}
			check(request(second, "two-factor/verify-totp", fmt.Sprintf(`{"code":%q}`, code), challenge()), 429)
			check(request(first, "two-factor/disable", `{"password":"wrong"}`, management), 400)
			check(request(first, "two-factor/disable", pwBody, management), 200)
			result, err := second.SignInEmail(ctx, login, auth.RequestMeta{})
			if err != nil || result.Challenge != nil || result.Token == "" {
				t.Fatalf("disabled factor still gated credential: %v", err)
			}
			if _, _, err = store.Session(ctx, reg.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("original pre-enrollment session is still active")
			}
		})
	}
}
