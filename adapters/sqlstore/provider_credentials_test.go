package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"golang.org/x/oauth2"
)

func TestProviderCredentialRoutes(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			dsn := ":memory:"
			if engine != "sqlite" {
				env := "AUTH_TEST_" + strings.ToUpper(engine) + "_DSN"
				dsn = os.Getenv(env)
				if dsn == "" {
					t.Skipf("set %s", env)
				}
			}
			ctx := context.Background()
			store, err := Open(ctx, engine, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var count atomic.Int32
			var fail atomic.Bool
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					return
				}
				n := count.Add(1)
				if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != fmt.Sprintf("rotate-%d", n-1) || r.Form.Get("client_secret") != "test-secret" {
					t.Error("incorrect refresh credential")
				}
				w.Header().Set("Content-Type", "application/json")
				if fail.Load() {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error":"invalid_grant","error_description":"private-provider-detail"}`)
					return
				}
				fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":"rotate-%d","expires_in":120,"scope":"read","refresh_token_expires_in":600,"token_type":"Bearer"}`, n, n)
			}))
			defer provider.Close()
			subject := rand.Text()
			wrongProfile := false
			p := auth.OAuthProvider{Config: oauth2.Config{ClientID: "client", ClientSecret: "test-secret", Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}, Resolve: func(_ context.Context, tok *oauth2.Token, _ string) (auth.OAuthProfile, error) {
				if !strings.HasPrefix(tok.AccessToken, "access-") {
					return auth.OAuthProfile{}, fmt.Errorf("unknown fixture token")
				}
				id := subject
				if wrongProfile {
					id = "different"
				}
				return auth.OAuthProfile{Subject: id, Email: "person@example.org", Data: map[string]any{"name": "fixture"}}, nil
			}}
			const origin = "http://app.example.org"
			opts := auth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("s", 32), SocialProviders: map[string]auth.OAuthProvider{"demo": p}}
			h, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			user := testUser(rand.Text())
			user.CreatedAt = now
			user.UpdatedAt = now
			sess := testSession(user, rand.Text())
			cleanup := func(userID string) {
				for _, table := range []string{"account", "session", "user"} {
					key := "userId"
					if table == "user" {
						key = "id"
					}
					_, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "`+table+`" WHERE "`+key+`"=?`), userID)
					if err != nil {
						t.Error(err)
					}
				}
			}
			defer cleanup(user.ID)
			_, _, err = store.CompleteOAuth(ctx, "demo", subject, auth.OAuthTokens{AccessToken: "stale", RefreshToken: "rotate-0", Scope: "read,write", ExpiresAt: now.Add(time.Second), RefreshExpiresAt: now.Add(time.Hour)}, user, sess, auth.OAuthLoginOptions{})
			if err != nil {
				t.Fatal(err)
			}
			accounts, err := store.ListUserAccounts(ctx, user.ID)
			if err != nil || len(accounts) != 1 {
				t.Fatalf("accounts %v %v", accounts, err)
			}
			id := accounts[0].ID
			selector := auth.AccountSelection{UserID: user.ID, AccountID: id}
			httpCall := func(route, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
				method := "POST"
				if strings.HasPrefix(route, "account-info") {
					method = "GET"
				}
				req := httptest.NewRequest(method, origin+"/api/auth/"+route, strings.NewReader(body))
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/json")
				if cookie != nil {
					req.AddCookie(cookie)
				}
				res := httptest.NewRecorder()
				h.ServeHTTP(res, req)
				return res
			}
			cookie := h.SessionCookie(sess.Token, true)
			body := fmt.Sprintf(`{"accountId":%q,"userId":%q}`, id, user.ID)
			if res := httpCall("get-access-token", body, nil); res.Code != 401 {
				t.Fatalf("anonymous %d", res.Code)
			}
			other := testUser(rand.Text())
			other.CreatedAt = now
			otherSession := testSession(other, rand.Text())
			if err := store.CreateUser(ctx, other, "hash", &otherSession); err != nil {
				t.Fatal(err)
			}
			defer cleanup(other.ID)
			if res := httpCall("refresh-token", body, h.SessionCookie(otherSession.Token, true)); res.Code != 400 || !strings.Contains(res.Body.String(), "ACCOUNT_NOT_FOUND") {
				t.Fatalf("account isolation %d %s", res.Code, res.Body)
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					result, err := h.GetAccessToken(ctx, nil, selector)
					if err != nil || result.AccessToken != "access-1" || len(result.Scopes) != 2 {
						t.Errorf("read %#v %v", result, err)
					}
				}()
			}
			wg.Wait()
			if count.Load() != 1 {
				t.Fatalf("automatic refreshes %d", count.Load())
			}
			if res := httpCall("get-access-token", body, cookie); res.Code != 200 || strings.Contains(res.Body.String(), "refreshToken") || strings.Contains(res.Body.String(), "rotate-") {
				t.Fatalf("access response %s", res.Body)
			}
			res := httpCall("refresh-token", body, cookie)
			var refreshed auth.RefreshTokenResult
			if err = json.Unmarshal(res.Body.Bytes(), &refreshed); err != nil || res.Code != 200 || refreshed.RefreshToken != "rotate-2" || refreshed.Scope == nil || *refreshed.Scope != "read,write" || refreshed.RefreshTokenExpiresAt == nil {
				t.Fatalf("rotated response %d %s", res.Code, res.Body)
			}
			if res := httpCall("account-info?accountId="+id, "", cookie); res.Code != 200 || !strings.Contains(res.Body.String(), subject) || strings.Contains(res.Body.String(), "access-") {
				t.Fatalf("account-info %d %s", res.Code, res.Body)
			}
			wrongProfile = true
			if res := httpCall("account-info?accountId="+id, "", cookie); res.Code != 401 {
				t.Fatalf("changed provider subject accepted: %s", res.Body)
			}
			fail.Store(true)
			if res := httpCall("refresh-token", body, cookie); res.Code != 400 || strings.Contains(res.Body.String(), "private-provider-detail") {
				t.Fatalf("provider failure %s", res.Body)
			}
			after, err := store.ProviderCredential(ctx, user.ID, id)
			if err != nil || after.RefreshToken != "rotate-2" || after.AccessToken != "access-2" {
				t.Fatalf("rollback %v", err)
			}
			p.DisableRefresh = true
			opts.SocialProviders = map[string]auth.OAuthProvider{"demo": p}
			h, err = auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if res := httpCall("refresh-token", body, cookie); res.Code != 400 || !strings.Contains(res.Body.String(), "TOKEN_REFRESH_NOT_SUPPORTED") {
				t.Fatalf("unsupported refresh: %d %s", res.Code, res.Body)
			}
			if err := store.DeleteSession(ctx, sess.Token); err != nil {
				t.Fatal(err)
			}
			if res := httpCall("get-access-token", body, cookie); res.Code != 401 {
				t.Fatalf("revoked session: %d", res.Code)
			}
		})
	}
}
