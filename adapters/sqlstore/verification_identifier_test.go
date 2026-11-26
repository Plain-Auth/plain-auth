package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
)

// With StoreVerificationIdentifier, reset, deletion, magic and one-time links
// keep their purpose prefix and store a hash of the whole identifier in place
// of the token. Each redeems once with its token and never with its stored
// value, deleting the user still removes its links, and a link of each kind
// issued under one setting is refused under another.
func TestStoreVerificationIdentifier(t *testing.T) {
	b64 := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	hexOf := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var mu sync.Mutex
			mailed := map[string]string{}
			var hashed []string
			keep := func(kind, token string) error {
				mu.Lock()
				defer mu.Unlock()
				mailed[kind] = token
				return nil
			}
			last := func(kind string) string {
				mu.Lock()
				defer mu.Unlock()
				return mailed[kind]
			}
			hexHash := func(_ context.Context, identifier string) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				hashed = append(hashed, identifier)
				return hexOf(identifier), nil
			}
			newAuth := func(storage auth.VerificationIdentifierStorage, overrides map[string]auth.VerificationIdentifierStorage) *auth.Auth {
				t.Helper()
				magic, err := auth.NewMagicLink(auth.MagicLinkOptions{HashTokens: true, Send: func(_ context.Context, m auth.MagicLinkMessage) error { return keep("magic", m.Token) }})
				if err != nil {
					t.Fatal(err)
				}
				transfers, err := auth.NewOneTimeToken(auth.OneTimeTokenOptions{})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{Store: store, BaseURL: "https://auth.example", Secret: strings.Repeat("s", 40), RateLimit: &off, EmailAndPassword: true, DeleteUserEnabled: true,
					SendResetPassword:             func(_ context.Context, l auth.MailLink) error { return keep("reset", l.Token) },
					SendDeleteAccountVerification: func(_ context.Context, l auth.MailLink) error { return keep("delete", l.Token) },
					Plugins:                       []auth.Plugin{magic, transfers}, StoreVerificationIdentifier: storage, StoreVerificationIdentifierOverrides: overrides})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			serve := func(a *auth.Auth, method, path, body, cookie string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
				r.Header.Set("Origin", "https://auth.example")
				if body != "" {
					r.Header.Set("Content-Type", "application/json")
				}
				if cookie != "" {
					r.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				return w
			}
			expect := func(w *httptest.ResponseRecorder, status int, what string) {
				t.Helper()
				if w.Code != status {
					t.Fatalf("%s answered %d, want %d: %s", what, w.Code, status, w.Body.String())
				}
			}
			// identifiers returns every verification identifier with its value.
			identifiers := func() map[string]string {
				t.Helper()
				rows, err := store.db.QueryContext(ctx, store.bind(`SELECT "identifier","value" FROM "verification"`))
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				out := map[string]string{}
				for rows.Next() {
					var identifier, value string
					if err := rows.Scan(&identifier, &value); err != nil {
						t.Fatal(err)
					}
					out[identifier] = value
				}
				if err := rows.Err(); err != nil {
					t.Fatal(err)
				}
				return out
			}
			// stored checks that the one record for a token sits at identifier
			// and that no identifier holds the token itself when it is hashed.
			stored := func(identifier, prefix, token string) {
				t.Helper()
				all := identifiers()
				if _, ok := all[identifier]; !ok {
					t.Fatalf("no record at %q", identifier)
				}
				if identifier == prefix+token {
					return
				}
				for id := range all {
					if strings.Contains(id, token) {
						t.Fatalf("%q holds the token", id)
					}
				}
			}
			gone := func(identifier string) {
				t.Helper()
				if _, ok := identifiers()[identifier]; ok {
					t.Fatalf("%q is still stored", identifier)
				}
			}
			signUp := func(a *auth.Auth) (email, cookie string) {
				t.Helper()
				email = strings.ToLower(rand.Text()[:12]) + "@example.test"
				r, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: email, Password: "initial password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				c := a.SessionCookie(r.Token, true)
				return email, c.Name + "=" + c.Value
			}
			// exercise runs each covered flow and checks that its record is
			// stored at key(prefix, token) and redeems once, with the token only.
			exercise := func(a *auth.Auth, key func(prefix, token string) string) {
				t.Helper()
				email, cookie := signUp(a)
				part := func(prefix, token string) string { return strings.TrimPrefix(key(prefix, token), prefix) }

				expect(serve(a, "POST", "/request-password-reset", `{"email":"`+email+`"}`, ""), 200, "the reset request")
				reset := last("reset")
				stored(key("reset-password:", reset), "reset-password:", reset)
				w := serve(a, "GET", "/reset-password/"+reset+"?callbackURL=/done", "", "")
				if u, err := url.Parse(w.Header().Get("Location")); w.Code != 302 || err != nil || u.Query().Get("token") != reset {
					t.Fatal("the reset link redirected to", w.Code, w.Header().Get("Location"))
				}
				if p := part("reset-password:", reset); p != reset {
					expect(serve(a, "POST", "/reset-password", `{"token":"`+p+`","newPassword":"another password"}`, ""), 400, "a reset with the stored value")
				}
				expect(serve(a, "POST", "/reset-password", `{"token":"`+reset+`","newPassword":"another password"}`, ""), 200, "the reset")
				expect(serve(a, "POST", "/reset-password", `{"token":"`+reset+`","newPassword":"third password"}`, ""), 400, "a replayed reset")
				gone(key("reset-password:", reset))

				w = serve(a, "GET", "/one-time-token/generate", "", cookie)
				expect(w, 200, "the one-time token request")
				var issued struct{ Token string }
				if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.Token == "" {
					t.Fatal("no one-time token:", w.Body.String())
				}
				stored(key("one-time-token:", issued.Token), "one-time-token:", issued.Token)
				if p := part("one-time-token:", issued.Token); p != issued.Token {
					expect(serve(a, "POST", "/one-time-token/verify", `{"token":"`+p+`"}`, ""), 400, "a transfer with the stored value")
				}
				expect(serve(a, "POST", "/one-time-token/verify", `{"token":"`+issued.Token+`"}`, ""), 200, "the transfer")
				expect(serve(a, "POST", "/one-time-token/verify", `{"token":"`+issued.Token+`"}`, ""), 400, "a replayed transfer")

				expect(serve(a, "POST", "/sign-in/magic-link", `{"email":"`+email+`"}`, ""), 200, "the magic link request")
				magic := last("magic")
				stored(key("magic-link:", b64(magic)), "magic-link:", b64(magic))
				verify := func(token string) *httptest.ResponseRecorder {
					return serve(a, "GET", "/magic-link/verify?"+url.Values{"token": {token}, "callbackURL": {"/done"}}.Encode(), "", "")
				}
				if to := verify(part("magic-link:", b64(magic))).Header().Get("Location"); !strings.Contains(to, "error=INVALID_TOKEN") {
					t.Fatal("a magic link with the stored value redirected to", to)
				}
				stored(key("magic-link:", b64(magic)), "magic-link:", b64(magic))
				// Proving the mailbox ends the sign-up's session, so the
				// deletion below uses the magic link's.
				w = verify(magic)
				if to := w.Header().Get("Location"); strings.Contains(to, "error") || len(w.Result().Cookies()) == 0 {
					t.Fatal("the magic link redirected to", to)
				}
				cookie = w.Result().Cookies()[0].Name + "=" + w.Result().Cookies()[0].Value
				if to := verify(magic).Header().Get("Location"); !strings.Contains(to, "error=INVALID_TOKEN") {
					t.Fatal("a replayed magic link redirected to", to)
				}
				gone(key("magic-link:", b64(magic)))

				// A live reset link is removed with the user it belongs to.
				expect(serve(a, "POST", "/request-password-reset", `{"email":"`+email+`"}`, ""), 200, "the second reset request")
				standing := key("reset-password:", last("reset"))
				expect(serve(a, "POST", "/delete-user", `{"callbackURL":"/done"}`, cookie), 200, "the deletion request")
				deletion := last("delete")
				stored(key("delete-account-", deletion), "delete-account-", deletion)
				if p := part("delete-account-", deletion); p != deletion {
					expect(serve(a, "GET", "/delete-user/callback?token="+url.QueryEscape(p), "", cookie), 404, "a deletion with the stored value")
				}
				expect(serve(a, "GET", "/delete-user/callback?token="+deletion, "", cookie), 200, "the deletion")
				gone(key("delete-account-", deletion))
				gone(standing)
				if _, err := store.FindAccountUser(ctx, email); err == nil {
					t.Fatal("the user was not deleted")
				}
			}

			// The helpers above fail the engine's test, so each mode is logged.
			t.Log("plain")
			exercise(newAuth(auth.VerificationIdentifierStorage{}, nil), func(prefix, token string) string { return prefix + token })
			t.Log("hashed")
			exercise(newAuth(auth.VerificationIdentifierStorage{Hashed: true}, nil), func(prefix, token string) string { return prefix + b64(prefix+token) })
			t.Log("custom hash with overrides")
			custom := newAuth(auth.VerificationIdentifierStorage{Hash: hexHash}, map[string]auth.VerificationIdentifierStorage{"reset": {Hashed: true}, "one-time-token": {}})
			exercise(custom, func(prefix, token string) string {
				switch prefix {
				case "reset-password:":
					return prefix + b64(prefix+token)
				case "one-time-token:":
					return prefix + token
				}
				return prefix + hexOf(prefix+token)
			})
			mu.Lock()
			for _, identifier := range hashed {
				if !strings.HasPrefix(identifier, "magic-link:") && !strings.HasPrefix(identifier, "delete-account-") {
					t.Error("the hash received", identifier)
				}
			}
			if len(hashed) == 0 {
				t.Error("the hash never ran")
			}
			mu.Unlock()
			t.Log("switch")
			plain, hashedAuth := newAuth(auth.VerificationIdentifierStorage{}, nil), newAuth(auth.VerificationIdentifierStorage{Hashed: true}, nil)
			for _, pair := range [][2]*auth.Auth{{plain, hashedAuth}, {hashedAuth, plain}} {
				issuer, other := pair[0], pair[1]
				email, cookie := signUp(issuer)
				expect(serve(issuer, "POST", "/request-password-reset", `{"email":"`+email+`"}`, ""), 200, "the reset request")
				expect(serve(other, "POST", "/reset-password", `{"token":"`+last("reset")+`","newPassword":"another password"}`, ""), 400, "a reset under another setting")
				w := serve(issuer, "GET", "/one-time-token/generate", "", cookie)
				var issued struct{ Token string }
				if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.Token == "" {
					t.Fatal("no one-time token:", w.Body.String())
				}
				expect(serve(other, "POST", "/one-time-token/verify", `{"token":"`+issued.Token+`"}`, ""), 400, "a transfer under another setting")
				expect(serve(issuer, "POST", "/delete-user", `{"callbackURL":"/done"}`, cookie), 200, "the deletion request")
				expect(serve(other, "GET", "/delete-user/callback?token="+last("delete"), "", cookie), 404, "a deletion under another setting")
				expect(serve(issuer, "POST", "/sign-in/magic-link", `{"email":"`+email+`"}`, ""), 200, "the magic link request")
				if to := serve(other, "GET", "/magic-link/verify?"+url.Values{"token": {last("magic")}, "callbackURL": {"/done"}}.Encode(), "", "").Header().Get("Location"); !strings.Contains(to, "error=INVALID_TOKEN") {
					t.Fatal("a magic link under another setting redirected to", to)
				}
			}
		})
	}
}
