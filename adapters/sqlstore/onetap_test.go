package sqlstore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authn "github.com/FineStack/finestack-auth"
	"github.com/FineStack/finestack-auth/plugins/onetap"
	"github.com/FineStack/finestack-auth/providers"
)

type googleJWKS func(*http.Request) (*http.Response, error)

func (f googleJWKS) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOneTapGoogleSignIn(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "example.apps.googleusercontent.com"
	const origin = "https://app.example"
	const workspace = "example.org"
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "local", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	hc := &http.Client{Transport: googleJWKS(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://www.googleapis.com/oauth2/v3/certs" {
			t.Errorf("unexpected Google request %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(jwks))}, nil
	})}
	sign := func(nonce, sub, email string, edits jwt.MapClaims) string {
		t.Helper()
		now := time.Now()
		claims := jwt.MapClaims{"iss": "https://accounts.google.com", "sub": sub, "email": email, "name": "Alice", "email_verified": true, "hd": workspace, "aud": audience, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": nonce, "jti": rand.Text()}
		for k, v := range edits {
			claims[k] = v
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "local"
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := organizationTestDSN(t, dialect)
			ctx := t.Context()
			build := func(pluginDisabled, providerDisabled bool, hd string) (*authn.Auth, *Store) {
				t.Helper()
				s, err := Open(ctx, dialect, dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				google := providers.GoogleWithOptions(providers.GoogleOptions{ClientID: audience, HostedDomain: hd, DisableSignUp: providerDisabled, HTTPClient: hc})
				off := false
				a, err := authn.New(authn.Options{Store: s, EmailAndPassword: true, BaseURL: origin, Secret: strings.Repeat("x", 32), TrustedOrigins: []string{"https://dashboard.example"}, RateLimit: &off, Plugins: []authn.Plugin{onetap.New(onetap.Options{DisableSignUp: pluginDisabled})}, SocialProviders: map[string]authn.OAuthProvider{"google": google}})
				if err != nil {
					t.Fatal(err)
				}
				return a, s
			}
			first, store := build(false, false, workspace)
			other, _ := build(false, false, workspace)
			type reply struct {
				code    int
				data    map[string]any
				cookies []*http.Cookie
			}
			request := func(a *authn.Auth, path, from string, in map[string]string, cookie *http.Cookie) reply {
				raw, _ := json.Marshal(in)
				r := httptest.NewRequest("POST", origin+"/api/auth/one-tap/"+path, bytes.NewReader(raw))
				r.Header.Set("Content-Type", "application/json")
				if from != "" {
					r.Header.Set("Origin", from)
				}
				if cookie != nil {
					r.AddCookie(cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var res map[string]any
				json.Unmarshal(w.Body.Bytes(), &res)
				return reply{w.Code, res, w.Result().Cookies()}
			}
			insist := func(r reply, code int) {
				t.Helper()
				if r.code != code {
					t.Fatalf("One Tap returned %d, want %d (code=%v)", r.code, code, r.data["code"])
				}
			}
			begin := func(a *authn.Auth) (string, *http.Cookie) {
				t.Helper()
				r := request(a, "nonce", origin, map[string]string{}, nil)
				insist(r, 200)
				if len(r.cookies) != 1 || !r.cookies[0].Secure || !r.cookies[0].HttpOnly || !strings.HasPrefix(r.cookies[0].Name, "__Host-") || r.cookies[0].MaxAge != 300 || r.data["clientId"] != audience {
					t.Fatal("invalid One Tap browser binding")
				}
				n, _ := r.data["nonce"].(string)
				if n == "" {
					t.Fatal("missing nonce")
				}
				return n, r.cookies[0]
			}
			submit := func(a *authn.Auth, raw string, c *http.Cookie) reply {
				return request(a, "callback", origin, map[string]string{"idToken": raw}, c)
			}
			userID := func(r reply) string {
				t.Helper()
				u, ok := r.data["user"].(map[string]any)
				if !ok {
					t.Fatal("missing Google user")
				}
				return u["id"].(string)
			}
			insist(request(first, "nonce", "https://elsewhere.example", map[string]string{}, nil), 403)
			insist(request(first, "nonce", "", map[string]string{}, nil), 403)
			n, c := begin(first)
			_, wrong := begin(other)
			email := "alice@example.org"
			raw := sign(n, "alice-sub", email, nil)
			parts := strings.Split(raw, ".")
			if strings.HasPrefix(parts[2], "A") {
				parts[2] = "B" + parts[2][1:]
			} else {
				parts[2] = "A" + parts[2][1:]
			}
			insist(submit(first, strings.Join(parts, "."), c), 400)
			insist(submit(first, raw, nil), 400)
			insist(submit(other, raw, wrong), 400)
			insist(request(first, "callback", "https://dashboard.example", map[string]string{"idToken": raw}, c), 400)
			insist(request(first, "callback", origin, map[string]string{"idToken": raw, "callbackURL": "https://other.example"}, c), 403)
			for _, bad := range []jwt.MapClaims{{"aud": "other"}, {"azp": "other"}, {"iss": "https://other.example"}, {"nonce": "other"}, {"hd": "elsewhere.org"}, {"hd": nil}, {"exp": time.Now().Add(-time.Hour).Unix()}, {"iat": time.Now().Add(-2 * time.Hour).Unix()}, {"sub": ""}} {
				r := submit(first, sign(n, "alice-sub", email, bad), c)
				if r.code != 400 && r.code != 401 {
					t.Fatalf("accepted invalid verified Google claims: %v", bad)
				}
			}
			out := make(chan reply, 2)
			go func() { out <- submit(first, raw, c) }()
			go func() { out <- submit(other, sign(n, "alice-sub", email, nil), c) }()
			a, b := <-out, <-out
			if b.code == 200 {
				a, b = b, a
			}
			insist(a, 200)
			insist(b, 400)
			owner := userID(a)
			ss, _, err := store.Session(ctx, a.data["token"].(string))
			if err != nil || ss.UserID != owner {
				t.Fatal("one-use challenge failed to issue the owner's session")
			}
			insist(submit(other, raw, c), 400)
			blocked, _ := build(true, false, workspace)
			n, c = begin(blocked)
			insist(submit(blocked, sign(n, "new", "new@example.org", nil), c), 403)
			n, c = begin(blocked)
			same := submit(blocked, sign(n, "alice-sub", "renamed@example.org", nil), c)
			insist(same, 200)
			if userID(same) != owner {
				t.Fatal("verified Google subject lost ownership after email change")
			}
			blocked, _ = build(false, true, "*")
			n, c = begin(blocked)
			insist(submit(blocked, sign(n, "new", "new@example.org", nil), c), 403)
			n, c = begin(blocked)
			insist(submit(blocked, sign(n, "alice-sub", email, jwt.MapClaims{"hd": "another.workspace"}), c), 200)
			n, c = begin(blocked)
			missing := submit(blocked, sign(n, "alice-sub", email, jwt.MapClaims{"hd": nil}), c)
			if missing.code != 401 && missing.code != 400 {
				t.Fatal("wildcard permitted a personal Google account")
			}
			_, err = first.SignUpEmail(ctx, authn.SignUpInput{Name: "Other", Email: "pending@example.org", Password: "local good password"}, authn.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			n, c = begin(first)
			insist(submit(first, sign(n, "new-sub", "pending@example.org", nil), c), 401)
		})
	}
}
