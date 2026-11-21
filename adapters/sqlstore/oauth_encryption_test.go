package sqlstore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/FineStack/finestack-auth"
	"golang.org/x/oauth2"
)

func TestEncryptedProviderCredentialLifecycle(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := Open(ctx, dialect, organizationTestDSN(t, dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"initial-access","refresh_token":"initial-refresh","id_token":"initial-identity","expires_in":3600,"token_type":"Bearer"}`)
			}))
			defer oauthServer.Close()
			profile := auth.OAuthProfile{Subject: "subject", Email: "subject@example.test", Name: "Alice", EmailVerified: true}
			provider := auth.OAuthProvider{
				Config:  oauth2.Config{ClientID: "fixture", Endpoint: oauth2.Endpoint{AuthURL: oauthServer.URL + "/authorize", TokenURL: oauthServer.URL + "/token"}},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil },
				Refresh: func(_ context.Context, _ oauth2.Config, value string) (*oauth2.Token, error) {
					if value != "initial-refresh" {
						return nil, fmt.Errorf("wrong refresh token")
					}
					return &oauth2.Token{AccessToken: "next-access", RefreshToken: "next-refresh", Expiry: time.Now().Add(time.Hour)}, nil
				},
				VerifyIDToken: func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
					if raw != "native-identity" || nonce != "nonce" {
						return auth.OAuthProfile{}, time.Time{}, fmt.Errorf("invalid fixture identity")
					}
					return profile, time.Now().Add(time.Hour), nil
				},
			}
			const origin = "http://app.example.test"
			opts := auth.Options{BaseURL: origin, Store: store, Secret: strings.Repeat("a", 32), SocialProviders: map[string]auth.OAuthProvider{"demo": provider}, EncryptOAuthTokens: true}
			instance, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			call := func(method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, origin+"/api/auth/"+path, strings.NewReader(body))
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/json")
				for _, c := range cookies {
					req.AddCookie(c)
				}
				w := httptest.NewRecorder()
				instance.ServeHTTP(w, req)
				return w
			}
			start := call("POST", "sign-in/social", `{"provider":"demo","callbackURL":"/done","disableRedirect":true}`, nil)
			var target struct{ URL string }
			if start.Code != 200 || json.Unmarshal(start.Body.Bytes(), &target) != nil {
				t.Fatal("authorization start", start.Code, start.Body)
			}
			location, err := url.Parse(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			res := call("GET", "callback/demo?code=code&state="+url.QueryEscape(location.Query().Get("state")), "", start.Result().Cookies())
			if res.Code != 302 || res.Header().Get("Location") != "/done" {
				t.Fatal("callback failed", res.Header().Get("Location"), res.Body)
			}
			var id, userID string
			if err = store.db.QueryRowContext(ctx, store.bind(`SELECT "id","userId" FROM "account" WHERE "providerId"=?`), "demo").Scan(&id, &userID); err != nil {
				t.Fatal(err)
			}
			selection := auth.AccountSelection{UserID: userID, AccountID: id}
			assertSealed := func(version string) {
				t.Helper()
				record, err := store.ProviderCredential(ctx, userID, id)
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range []string{record.AccessToken, record.RefreshToken, record.IDToken} {
					if !strings.HasPrefix(v, "authn.v1."+version+".") {
						t.Fatal("provider credential stored without active encryption version")
					}
				}
			}
			assertSealed("0")
			token, err := instance.GetAccessToken(ctx, nil, selection)
			if err != nil || token.AccessToken != "initial-access" || token.IDToken != "initial-identity" {
				t.Fatal("read encrypted provider credential", err)
			}
			opts.Secrets = []auth.VersionedSecret{{Version: 1, Value: strings.Repeat("b", 32)}, {Version: 0, Value: opts.Secret}}
			instance, err = auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			rotated, err := instance.RefreshToken(ctx, nil, selection)
			if err != nil || rotated.AccessToken != "next-access" || rotated.RefreshToken != "next-refresh" || rotated.IDToken == nil || *rotated.IDToken != "initial-identity" {
				t.Fatal("rotated provider credential", err)
			}
			assertSealed("1")
			opts.Secrets = opts.Secrets[:1]
			instance, err = auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			const grant = `{"provider":"demo","idToken":{"token":"native-identity","nonce":"nonce"}}`
			if w := call("POST", "sign-in/social", grant, nil); w.Code != 200 {
				t.Fatal("direct identity grant", w.Code, w.Body)
			}
			if w := call("POST", "sign-in/social", grant, nil); w.Code != 401 {
				t.Fatal("encrypted identity replay was accepted", w.Code)
			}
			assertSealed("1")
			tokens, err := instance.GetAccessToken(ctx, nil, selection)
			if err != nil || tokens.AccessToken != "next-access" || tokens.IDToken != "native-identity" {
				t.Fatal("partial account update lost preserved credentials", err)
			}
			if _, err = store.db.ExecContext(ctx, store.bind(`UPDATE "account" SET "accessToken"="refreshToken" WHERE "id"=?`), id); err != nil {
				t.Fatal(err)
			}
			if _, err = instance.GetAccessToken(ctx, nil, selection); err == nil {
				t.Fatal("accepted ciphertext moved to a different credential field")
			}
		})
	}
}
