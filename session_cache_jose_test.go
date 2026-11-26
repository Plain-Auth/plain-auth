package plainauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestJOSESessionCookieValidityAndRotation(t *testing.T) {
	cleanConfigEnv(t)
	for _, strategy := range []SessionCookieCacheStrategy{SessionCacheJWT, SessionCacheJWE} {
		t.Run(string(strategy), func(t *testing.T) {
			issued := time.Date(2026, 1, 1, 1, 2, 3, 120000000, time.UTC)
			now := issued
			old := VersionedSecret{Version: 1, Value: strings.Repeat("a", 64)}
			next := VersionedSecret{Version: 2, Value: strings.Repeat("b", 32)}
			store := &compactFixture{}
			host := func(mode SessionCookieCacheStrategy, version string, keys ...VersionedSecret) *Auth {
				t.Helper()
				a, err := New(Options{Store: store, BaseURL: "https://id.example.test", Secrets: keys,
					CrossSubDomainCookies: &CrossSubDomainCookiesOptions{Domain: "example.test"},
					SessionCookieCache:    &SessionCookieCacheOptions{Strategy: mode, MaxAge: 90 * time.Second, Version: version}})
				if err != nil {
					t.Fatal(err)
				}
				a.now = func() time.Time { return now }
				return a
			}
			a := host(strategy, "", old)
			data := SessionResult{Session: Session{ID: "s", Token: "value", UserID: "u", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}, User: User{ID: "u", Name: "public", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}}
			issue := func(node *Auth, data SessionResult, remember bool) *http.Cookie {
				t.Helper()
				cookies := testSessionCache(t, node, data, remember)
				if len(cookies) != 1 {
					t.Fatal("expected one session snapshot")
				}
				return cookies[0]
			}
			read := func(node *Auth, token string, value string) bool {
				r := httptest.NewRequest("GET", "https://id.example.test/api/auth/get-session", nil)
				if token != "" {
					r.AddCookie(node.SessionCookie(token, true))
				}
				r.AddCookie(&http.Cookie{Name: node.prefixedCookieName("session_data"), Value: value})
				got, err := node.cachedSessionView(r, token)
				if err != nil && err != errSessionCacheVersionChanged {
					t.Fatal(err)
				}
				return got != nil
			}
			c := issue(a, data, true)
			if !c.HttpOnly || !c.Secure || c.Domain != "example.test" || c.MaxAge != 90 || !read(a, "value", c.Value) {
				t.Fatal("initial scoped cache rejected")
			}
			short := issue(a, data, false)
			if short.MaxAge != 0 {
				t.Fatal("nonpersistent login set Max-Age")
			}
			rotated := host(strategy, "", next, old)
			removed := host(strategy, "", next)
			if !read(rotated, "value", c.Value) || read(removed, "value", c.Value) || !read(removed, "value", issue(rotated, data, true).Value) {
				t.Fatal("key rollover did not select the current and retained keys")
			}
			if read(host(strategy, "new", old), "value", c.Value) || read(a, "other", c.Value) || read(a, "", c.Value) {
				t.Fatal("cookie escaped its version or signed credential binding")
			}
			for _, other := range []SessionCookieCacheStrategy{SessionCacheCompact, SessionCacheJWT, SessionCacheJWE} {
				if other != strategy && read(host(other, "", old), "value", c.Value) {
					t.Fatal("accepted another strategy", other)
				}
			}
			parts := strings.Split(c.Value, ".")
			last := len(parts) - 1
			tag, err := base64.RawURLEncoding.DecodeString(parts[last])
			if err != nil || len(tag) == 0 {
				t.Fatal("missing authenticator")
			}
			tag[0] ^= 1
			parts[last] = base64.RawURLEncoding.EncodeToString(tag)
			if read(a, "value", strings.Join(parts, ".")) || read(a, "value", c.Value[:len(c.Value)/2]) {
				t.Fatal("accepted modified or incomplete cookie")
			}
			now = issued.Add(89 * time.Second)
			if !read(a, "value", c.Value) {
				t.Fatal("ended window early")
			}
			now = issued.Add(90 * time.Second)
			if read(a, "value", c.Value) || !read(a, "value", short.Value) {
				t.Fatal("persistent and browser-only expiry windows differed")
			}
			now = issued.Add(5 * time.Minute)
			if read(a, "value", short.Value) {
				t.Fatal("expired browser-only snapshot accepted")
			}
			now = issued
			data.Session.ExpiresAt = issued.Add(time.Second)
			expiring := issue(a, data, true)
			now = data.Session.ExpiresAt
			if read(a, "value", expiring.Value) {
				t.Fatal("expired embedded session accepted")
			}
			now = issued

			// A correctly protected envelope still needs a complete matching identity.
			payload := sessionCachePayload{Session: data.Session, User: data.User, UpdatedAt: issued.UnixMilli(), Version: "1"}
			payload.Session.UserID = "other-owner"
			invalid, err := a.writeJOSESnapshot(t.Context(), payload, issued, time.Minute)
			if err != nil || read(a, "value", invalid) {
				t.Fatal("mismatched session and user", err)
			}
			payload.Session.UserID = data.User.ID
			payload.User.CreatedAt = time.Time{}
			invalid, err = a.writeJOSESnapshot(t.Context(), payload, issued, time.Minute)
			if err != nil || read(a, "value", invalid) {
				t.Fatal("missing snapshot field", err)
			}

			craft := func(raw []byte, recipient jose.Recipient, enc jose.ContentEncryption, opts *jose.EncrypterOptions) string {
				t.Helper()
				if strategy == SessionCacheJWT {
					signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte(old.Value)}, nil)
					if err != nil {
						t.Fatal(err)
					}
					signed, err := signer.Sign(raw)
					if err != nil {
						t.Fatal(err)
					}
					s, err := signed.CompactSerialize()
					if err != nil {
						t.Fatal(err)
					}
					return s
				}
				cipher, err := jose.NewEncrypter(enc, recipient, opts)
				if err != nil {
					t.Fatal(err)
				}
				msg, err := cipher.Encrypt(raw)
				if err != nil {
					t.Fatal(err)
				}
				s, err := msg.CompactSerialize()
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			recipient := jose.Recipient{Algorithm: jose.DIRECT, Key: a.sessionCacheKeys[0].material}
			raw := a.readJOSESnapshot(t.Context(), c.Value, issued)
			var claims map[string]any
			if err = json.Unmarshal(raw, &claims); err != nil {
				t.Fatal(err)
			}
			delete(claims, "exp")
			incomplete, err := json.Marshal(claims)
			if err != nil || read(a, "value", craft(incomplete, recipient, jose.A256CBC_HS512, nil)) {
				t.Fatal("accepted a snapshot without expiry", err)
			}
			claims["exp"] = issued.Add(time.Minute).Unix()
			claims["nbf"] = issued.Add(time.Minute).Unix()
			future, err := json.Marshal(claims)
			if err != nil || read(a, "value", craft(future, recipient, jose.A256CBC_HS512, nil)) {
				t.Fatal("accepted a snapshot before activation", err)
			}
			if strategy == SessionCacheJWT {
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS512, Key: []byte(old.Value)}, nil)
				if err != nil {
					t.Fatal(err)
				}
				signed, err := signer.Sign(raw)
				if err != nil {
					t.Fatal(err)
				}
				token, err := signed.CompactSerialize()
				if err != nil || read(a, "value", token) {
					t.Fatal("accepted an unconfigured signing algorithm", err)
				}
			}
			if strategy == SessionCacheJWE {
				legacy := craft(raw, recipient, jose.A256CBC_HS512, nil)
				if !read(rotated, "value", legacy) || read(removed, "value", legacy) {
					t.Fatal("keyless envelope escaped its retained key set")
				}
				recipient.KeyID = "foreign-thumbprint"
				if read(a, "value", craft(raw, recipient, jose.A256CBC_HS512, nil)) {
					t.Fatal("ignored an explicit foreign key ID")
				}
				recipient.KeyID = a.sessionCacheKeys[0].id
				if read(a, "value", craft(raw, recipient, jose.A256CBC_HS512, &jose.EncrypterOptions{Compression: jose.DEFLATE})) {
					t.Fatal("accepted a compressed snapshot")
				}
				recipient.Key = a.sessionCacheKeys[0].material[:32]
				if read(a, "value", craft(raw, recipient, jose.A256GCM, nil)) {
					t.Fatal("accepted a different encryption profile")
				}
			}
		})
	}
	if _, err := New(Options{Store: &compactFixture{}, BaseURL: "https://auth.test", Secret: strings.Repeat("s", 32), SessionCookieCache: &SessionCookieCacheOptions{Strategy: "unsupported"}}); err == nil {
		t.Fatal("accepted unknown cache strategy")
	}
}
