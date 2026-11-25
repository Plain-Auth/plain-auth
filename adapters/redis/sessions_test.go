package redisstore_test

import (
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	redisstore "github.com/Plain-Org/plain-auth/adapters/redis"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
)

var _ auth.SecondaryStorage = (*redisstore.Store)(nil)

// Two replicas with their own Redis clients share sessions through Redis:
// each session is a prefixed key with the session's lifetime, a sign-out on
// one replica ends it on the other, and a flush falls back to the database.
func TestSessionsInRedis(t *testing.T) {
	ctx := t.Context()
	opts := serverOptions(t)
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first := storage(t, connection(t, opts), "sessions-a:")
	second := storage(t, connection(t, opts), "sessions-a:")
	replica := func(s *redisstore.Store) *auth.Auth {
		node, err := auth.New(auth.Options{Store: db, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
			RateLimit: new(bool), SecondaryStorage: s, StoreSessionInDatabase: true})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	// The same Store attaches one storage; the second replica's client
	// reaches the same keys under the same prefix.
	a := replica(first)
	if _, err := auth.New(auth.Options{Store: db, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", SecondaryStorage: second, StoreSessionInDatabase: true}); err == nil {
		t.Fatal("a second storage was attached to the same store")
	}
	other, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	call := func(node *auth.Auth, method, path, body, cookie string) (int, map[string]any, string) {
		r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://auth.example")
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		session := ""
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, "session_token") && c.Value != "" {
				session = c.Name + "=" + c.Value
			}
		}
		return w.Code, out, session
	}
	status, out, cookie := call(a, "POST", "/sign-up/email", `{"name":"Person","email":"redis@example.org","password":"a redis test password"}`, "")
	if status != 200 || cookie == "" {
		t.Fatal("sign-up", status, out)
	}
	keys, err := second.ListKeys(ctx)
	if err != nil || len(keys) != 1 || !strings.HasPrefix(keys[0], "session:") {
		t.Fatal("keys", keys, err)
	}
	ttl, err := connection(t, opts).TTL(ctx, "sessions-a:"+keys[0]).Result()
	if err != nil || ttl < 6*24*time.Hour || ttl > 7*24*time.Hour {
		t.Fatal("the session key's TTL was", ttl, err)
	}
	// A replica on another database reads the session from Redis alone.
	b, err := auth.New(auth.Options{Store: other, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
		RateLimit: new(bool), SecondaryStorage: second, StoreSessionInDatabase: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := call(b, "GET", "/get-session", "", cookie); out["user"] == nil {
		t.Fatal("the session copy in Redis was not served:", out)
	}
	if err := second.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := call(a, "GET", "/get-session", "", cookie); out["user"] == nil {
		t.Fatal("a flushed Redis did not fall back to the database:", out)
	}
	if keys, _ := second.ListKeys(ctx); len(keys) != 1 {
		t.Fatal("the read did not copy the session back:", keys)
	}
	if status, _, _ := call(a, "POST", "/sign-out", `{}`, cookie); status != 200 {
		t.Fatal("sign-out", status)
	}
	if keys, _ := second.ListKeys(ctx); len(keys) != 0 {
		t.Fatal("sign-out kept the session key:", keys)
	}
	if _, out, _ := call(b, "GET", "/get-session", "", cookie); out != nil {
		t.Fatal("a signed-out session was still served from Redis:", out)
	}
}

// Replicas with only SecondaryStorage set share rate limits through it: the
// Redis store keeps one counter per client and route under its own
// namespace, a replica on another database refuses the request over the
// shared budget, and a sign-out whose bearer token names the counter's key
// leaves it alone.
func TestRateLimitsThroughSecondaryStorage(t *testing.T) {
	opts := serverOptions(t)
	prefix := "limits-" + rand.Text() + ":"
	on := true
	replica := func() *auth.Auth {
		db, err := sqlite.Open(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		node, err := auth.New(auth.Options{Store: db, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
			RateLimit: &on, SecondaryStorage: storage(t, connection(t, opts), prefix), StoreSessionInDatabase: true, Plugins: []auth.Plugin{bearer.New(bearer.Options{})}})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	a, b := replica(), replica()
	send := func(node *auth.Auth, path, body string, header map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range header {
			r.Header.Set(k, v)
		}
		r.RemoteAddr = "[2001:db8:1:2::10]:1234"
		w := httptest.NewRecorder()
		node.ServeHTTP(w, r)
		return w
	}
	signIn := func(node *auth.Auth) *httptest.ResponseRecorder {
		return send(node, "/sign-in/email", `{"email":"ada@example.com","password":"wrong password here"}`, map[string]string{"Origin": "https://auth.example"})
	}
	const counter = "rate-limit:2001:db8:1:2::/64|/sign-in/email"
	start := time.Now()
	for _, node := range []*auth.Auth{a, b, a} {
		if w := signIn(node); w.Code == 429 {
			t.Fatal("a request within the shared limit was refused")
		}
	}
	if w := signIn(b); w.Code != 429 || w.Header().Get("X-Retry-After") != "10" {
		t.Fatal("the replicas did not share the sign-in limit:", w.Code, w.Header())
	}
	client := connection(t, opts)
	ttl, err := client.PTTL(t.Context(), prefix+counter).Result()
	if err != nil || ttl > 10*time.Second || ttl < 10*time.Second-time.Since(start)-time.Millisecond {
		t.Fatal("the shared counter's TTL was", ttl, err)
	}
	send(a, "/sign-out", `{}`, map[string]string{"Authorization": "Bearer " + counter})
	if n, err := client.Exists(t.Context(), prefix+counter).Result(); err != nil || n != 1 {
		t.Fatal("a sign-out with a made-up token removed the rate-limit counter:", n, err)
	}
	if w := signIn(a); w.Code != 429 {
		t.Fatal("the limit reopened after a sign-out with a made-up token:", w.Code)
	}
}
