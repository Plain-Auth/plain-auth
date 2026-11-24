package redisstore_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	redisstore "github.com/Plain-Org/plain-auth/adapters/redis"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
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
	if err != nil || len(keys) != 1 {
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
