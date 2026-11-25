package goapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// verificationEvents records verification hooks and the user and session
// create after hooks, and can decline, fail or edit any of them, or run code
// in them.
type verificationEvents struct {
	mu       sync.Mutex
	events   []string
	records  []authn.VerificationRecord
	contexts []*authn.HookContext
	decline  map[string]bool
	fail     map[string]error
	edit     map[string]bool
	run      map[string]func(context.Context)
}

func newVerificationEvents() *verificationEvents {
	return &verificationEvents{decline: map[string]bool{}, fail: map[string]error{}, edit: map[string]bool{}, run: map[string]func(context.Context){}}
}

// during runs fn, outside the recorder's lock, whenever event's hook runs; nil stops it.
func (v *verificationEvents) during(event string, fn func(context.Context)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.run[event] = fn
}

func (v *verificationEvents) set(table map[string]bool, event string, on bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	table[event] = on
}

func (v *verificationEvents) failWith(event string, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fail[event] = err
}

func (v *verificationEvents) note(event string, rec *authn.VerificationRecord, c *authn.HookContext) error {
	return v.noteIn(context.Background(), event, rec, c)
}

func (v *verificationEvents) noteIn(ctx context.Context, event string, rec *authn.VerificationRecord, c *authn.HookContext) error {
	v.mu.Lock()
	v.events = append(v.events, event)
	if rec != nil {
		v.records, v.contexts = append(v.records, *rec), append(v.contexts, c)
		if v.edit[event] {
			rec.UserID = "someone-else"
		}
	}
	fn, declined, err := v.run[event], v.decline[event], v.fail[event]
	v.mu.Unlock()
	if fn != nil {
		fn(ctx)
	}
	if declined {
		return authn.ErrSkipWrite
	}
	return err
}

func (v *verificationEvents) drain() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.events
	v.events = nil
	return out
}

func (v *verificationEvents) last() (authn.VerificationRecord, *authn.HookContext) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.records[len(v.records)-1], v.contexts[len(v.contexts)-1]
}

func (v *verificationEvents) hooks() authn.DatabaseHooks {
	return authn.DatabaseHooks{
		Verification: authn.ModelHooks[authn.VerificationRecord]{
			Create: authn.OperationHooks[authn.VerificationRecord]{
				Before: func(ctx context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
					return v.noteIn(ctx, "create-before:"+r.Identifier, r, c)
				},
				After: func(ctx context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
					return v.noteIn(ctx, "create-after:"+r.Identifier, &r, c)
				},
			},
			// Email codes refuse update before hooks: a count has none.
			Update: authn.OperationHooks[authn.VerificationRecord]{
				After: func(ctx context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
					return v.noteIn(ctx, "update-after:"+r.Identifier, &r, c)
				},
			},
			Delete: authn.OperationHooks[authn.VerificationRecord]{
				Before: func(ctx context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
					return v.noteIn(ctx, "delete-before:"+r.Identifier, r, c)
				},
				After: func(ctx context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
					return v.noteIn(ctx, "delete-after:"+r.Identifier, &r, c)
				},
			},
		},
		User: authn.ModelHooks[authn.UserRecord]{Create: authn.OperationHooks[authn.UserRecord]{
			After: func(context.Context, authn.UserRecord, *authn.HookContext) error {
				return v.note("user-create-after", nil, nil)
			},
		}},
		Session: authn.ModelHooks[authn.SessionRecord]{Create: authn.OperationHooks[authn.SessionRecord]{
			After: func(context.Context, authn.SessionRecord, *authn.HookContext) error {
				return v.note("session-create-after", nil, nil)
			},
		}},
	}
}

func sameEvents(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("hooks ran as %q, want %q", got, want)
	}
}

// keyedID is the ID a magic link or one-time token stored under key gets.
func keyedID(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + hex.EncodeToString(sum[:16])
}

// blindFinders hides every magic link and one-time token from the finders,
// as a custom store that breaks the finder contract would.
type blindFinders struct{ *memory.Store }

func (blindFinders) FindMagicLink(context.Context, string, time.Time) (authn.MagicLinkChallenge, error) {
	return authn.MagicLinkChallenge{}, authn.ErrNotFound
}

func (blindFinders) FindOneTimeToken(context.Context, string, time.Time) (string, time.Time, error) {
	return "", time.Time{}, authn.ErrNotFound
}

// magicHost serves magic links and one-time tokens with recorded hooks.
type magicHost struct {
	t      *testing.T
	auth   *authn.Auth
	mu     sync.Mutex
	tokens []string
	logs   *bytes.Buffer
}

func newMagicHost(t *testing.T, store authn.Store, events *verificationEvents, edit func(*authn.Options)) *magicHost {
	t.Helper()
	h := &magicHost{t: t, logs: &bytes.Buffer{}}
	magic, err := authn.NewMagicLink(authn.MagicLinkOptions{Send: func(_ context.Context, m authn.MagicLinkMessage) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.tokens = append(h.tokens, m.Token)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	transfers, err := authn.NewOneTimeToken(authn.OneTimeTokenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	opts := authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
		Plugins: []authn.Plugin{magic, transfers}, DatabaseHooks: events.hooks(), Logger: slog.New(slog.NewTextHandler(&lockedWriter{w: h.logs}, nil))}
	if edit != nil {
		edit(&opts)
	}
	h.auth, err = authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// lockedWriter serializes concurrent log writes into one buffer.
type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (h *magicHost) serve(method, path, body, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://auth.example/api/auth"+path, strings.NewReader(body))
	r.Header.Set("Origin", "https://auth.example")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.auth.ServeHTTP(w, r)
	return w
}

// request asks for a magic link and returns the mailed token, or "" when
// nothing was mailed.
func (h *magicHost) request(email string) string {
	h.t.Helper()
	h.mu.Lock()
	before := len(h.tokens)
	h.mu.Unlock()
	if w := h.serve("POST", "/sign-in/magic-link", `{"email":"`+email+`"}`, ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"status":true}` {
		h.t.Fatal("the magic link request answered", w.Code, w.Body.String())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.tokens) == before {
		return ""
	}
	return h.tokens[len(h.tokens)-1]
}

func verifyPath(token string) string {
	return "/magic-link/verify?" + url.Values{"token": {token}, "callbackURL": {"/done"}, "errorCallbackURL": {"/failed"}}.Encode()
}

// Verification hooks run around magic links: create when a link is
// mailed, delete when it is spent, before the user and session hooks of its
// sign-in. A declined request stores and mails nothing, a declined spend
// keeps the link, a hook's error is never read as an invalid link, and a
// link that is expired or spent runs no hook.
func TestDatabaseVerificationHooksForMagicLinks(t *testing.T) {
	events := newVerificationEvents()
	store := memory.New()
	h := newMagicHost(t, store, events, nil)

	// A declined request answers as a sent one, with nothing mailed.
	events.set(events.decline, "create-before:magic-link", true)
	if token := h.request("ada@example.test"); token != "" {
		t.Fatal("a declined magic link was mailed")
	}
	sameEvents(t, events.drain(), "create-before:magic-link")
	_, c := events.last()
	if c == nil || c.Path != "/sign-in/magic-link" || c.Body["email"] != "ada@example.test" {
		t.Fatal("the create hook saw the endpoint", c)
	}
	events.set(events.decline, "create-before:magic-link", false)

	// A mailed link's record.
	token := h.request("ada@example.test")
	sameEvents(t, events.drain(), "create-before:magic-link", "create-after:magic-link")
	created, _ := events.last()
	if created.ID != keyedID("ml-", token) || created.Identifier != "magic-link" || created.UserID != "" ||
		created.ExpiresAt.Before(time.Now().Add(4*time.Minute)) || created.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		t.Fatal("the magic link's record was", created)
	}
	for _, field := range []string{created.ID, created.Identifier, created.UserID} {
		if strings.Contains(field, token) {
			t.Fatal("a verification record holds the mailed token")
		}
	}

	// A declined spend keeps the link; the retry signs in.
	events.set(events.decline, "delete-before:magic-link", true)
	if w := h.serve("GET", verifyPath(token), "", ""); w.Code != http.StatusFound || w.Header().Get("Location") != "https://auth.example/failed?error=INVALID_TOKEN" {
		t.Fatal("a declined spend answered", w.Code, w.Header().Get("Location"))
	}
	sameEvents(t, events.drain(), "delete-before:magic-link")
	events.set(events.decline, "delete-before:magic-link", false)
	w := h.serve("GET", verifyPath(token), "", "")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://auth.example/done" {
		t.Fatal("the retried link answered", w.Code, w.Header().Get("Location"))
	}
	sameEvents(t, events.drain(), "delete-before:magic-link", "delete-after:magic-link", "user-create-after", "session-create-after")
	spent, c := events.last()
	if spent != created || c == nil || c.Path != "/magic-link/verify" || c.Request.URL.Query().Get("token") != token {
		t.Fatal("the spend's record or endpoint was", spent, c)
	}
	// A spent link runs no hook.
	if w := h.serve("GET", verifyPath(token), "", ""); w.Header().Get("Location") != "https://auth.example/failed?error=INVALID_TOKEN" {
		t.Fatal("a replayed link answered", w.Header().Get("Location"))
	}
	sameEvents(t, events.drain())

	// An expired link runs no hook.
	past := time.Now().UTC().Add(-time.Hour)
	if err := store.SaveMagicLink(t.Context(), authn.MagicLinkChallenge{Key: "stale-link", Email: "ada@example.test", CreatedAt: past.Add(-time.Minute), ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if w := h.serve("GET", verifyPath("stale-link"), "", ""); w.Header().Get("Location") != "https://auth.example/failed?error=INVALID_TOKEN" {
		t.Fatal("an expired link answered", w.Header().Get("Location"))
	}
	sameEvents(t, events.drain())

	// Closed sign-up spends the link and runs its after hooks.
	closed := newMagicHost(t, store, events, func(o *authn.Options) {
		for i, p := range o.Plugins {
			if p.ID == "magic-link" {
				magic, _ := authn.NewMagicLink(authn.MagicLinkOptions{DisableSignUp: true, Send: func(_ context.Context, m authn.MagicLinkMessage) error {
					h.mu.Lock()
					defer h.mu.Unlock()
					h.tokens = append(h.tokens, m.Token)
					return nil
				}})
				o.Plugins[i] = magic
			}
		}
	})
	token = h.request("new@example.test")
	events.drain()
	if w := closed.serve("GET", verifyPath(token), "", ""); w.Header().Get("Location") != "https://auth.example/failed?error=new_user_signup_disabled" {
		t.Fatal("closed sign-up answered", w.Header().Get("Location"))
	}
	sameEvents(t, events.drain(), "delete-before:magic-link", "delete-after:magic-link")
	if w := closed.serve("GET", verifyPath(token), "", ""); w.Header().Get("Location") != "https://auth.example/failed?error=INVALID_TOKEN" {
		t.Fatal("a link spent by closed sign-up answered", w.Header().Get("Location"))
	}
	sameEvents(t, events.drain())

	// A before hook's API error answers as JSON and keeps the link.
	token = h.request("bo@example.test")
	events.drain()
	events.failWith("delete-before:magic-link", &authn.APIError{Status: 403, Code: "blocked", Message: "Blocked"})
	if w := h.serve("GET", verifyPath(token), "", ""); w.Code != 403 || !strings.Contains(w.Body.String(), "blocked") {
		t.Fatal("a before hook's error answered", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	events.failWith("delete-before:magic-link", nil)
	events.drain()
	// An after hook's error, even one wrapping ErrNotFound, fails the
	// request rather than reading as an invalid link, and leaves no session.
	events.failWith("delete-after:magic-link", fmt.Errorf("lookup: %w", authn.ErrNotFound))
	w = h.serve("GET", verifyPath(token), "", "")
	if w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("an after hook's error answered", w.Code, w.Header().Get("Location"), w.Result().Cookies())
	}
	sameEvents(t, events.drain(), "delete-before:magic-link", "delete-after:magic-link")
	events.failWith("delete-after:magic-link", nil)
	bo, err := store.FindAccountUser(t.Context(), "bo@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if sessions, err := store.ListSessions(t.Context(), bo.ID); err != nil || len(sessions) != 0 {
		t.Fatal("a failed after hook left sessions", sessions, err)
	}

	// A hook may not change the record.
	events.set(events.edit, "create-before:magic-link", true)
	if w := h.serve("POST", "/sign-in/magic-link", `{"email":"ada@example.test"}`, ""); w.Code != 500 {
		t.Fatal("an edited record answered", w.Code)
	}
	events.set(events.edit, "create-before:magic-link", false)
	events.drain()

	// Concurrent redemptions of one link run one delete after hook.
	token = h.request("ada@example.test")
	events.drain()
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for range 8 {
		wg.Go(func() { results <- h.serve("GET", verifyPath(token), "", "").Header().Get("Location") })
	}
	wg.Wait()
	close(results)
	signedIn := 0
	for location := range results {
		if location == "https://auth.example/done" {
			signedIn++
		}
	}
	afters := 0
	for _, e := range events.drain() {
		if e == "delete-after:magic-link" {
			afters++
		}
	}
	if signedIn != 1 || afters != 1 {
		t.Fatal("concurrent redemptions signed in", signedIn, "times and ran", afters, "after hooks")
	}

	// A store whose finder misses a link it then spends is refused.
	blind := newMagicHost(t, blindFinders{store}, events, nil)
	token = blind.request("ada@example.test")
	events.drain()
	if w := blind.serve("GET", verifyPath(token), "", ""); w.Header().Get("Location") != "https://auth.example/failed?error=INVALID_TOKEN" || len(w.Result().Cookies()) != 0 {
		t.Fatal("an unseen spend answered", w.Header().Get("Location"), w.Result().Cookies())
	}
	sameEvents(t, events.drain())
	if !strings.Contains(blind.logs.String(), "spent that its delete hooks did not see") {
		t.Fatal("an unseen spend was not logged:", blind.logs.String())
	}
}

// Verification hooks run around one-time tokens: create when a token is
// generated, delete when it is redeemed. A declined generate returns a token
// that redeems nothing, a declined redeem keeps the token, a token whose
// session ended runs its after hooks before the refusal, and an after hook's
// error is never read as an invalid token.
func TestDatabaseVerificationHooksForOneTimeTokens(t *testing.T) {
	events := newVerificationEvents()
	store := memory.New()
	h := newMagicHost(t, store, events, nil)
	c := sessionClient{t, h.auth}
	c.post("/sign-up/email", `{"name":"Ada","email":"ada@example.test","password":"`+sessionEndpointPassword+`"}`, "", 200)
	cookie, _ := c.signIn("ada@example.test")
	ada, err := store.FindAccountUser(t.Context(), "ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	events.drain()
	generate := func(cookie string) string {
		t.Helper()
		w := h.serve("GET", "/one-time-token/generate", "", cookie)
		var out struct{ Token string }
		if w.Code != 200 || jsonDecode(w.Body.Bytes(), &out) != nil || out.Token == "" {
			t.Fatal("generate answered", w.Code, w.Body.String())
		}
		return out.Token
	}
	redeem := func(token string) (int, string) {
		w := h.serve("POST", "/one-time-token/verify", `{"token":"`+token+`"}`, "")
		var out struct{ Message string }
		_ = jsonDecode(w.Body.Bytes(), &out)
		return w.Code, out.Message
	}

	token := generate(cookie)
	sameEvents(t, events.drain(), "create-before:one-time-token", "create-after:one-time-token")
	created, hc := events.last()
	if created.ID != keyedID("ot-", token) || created.Identifier != "one-time-token" || created.UserID != ada.ID || hc == nil || hc.Path != "/one-time-token/generate" ||
		created.ExpiresAt.Before(time.Now().Add(2*time.Minute)) || created.ExpiresAt.After(time.Now().Add(4*time.Minute)) {
		t.Fatal("the one-time token's record was", created, hc)
	}
	// A declined redeem keeps the token; the retry redeems it once.
	events.set(events.decline, "delete-before:one-time-token", true)
	if status, message := redeem(token); status != 400 || message != "Invalid token" {
		t.Fatal("a declined redeem answered", status, message)
	}
	sameEvents(t, events.drain(), "delete-before:one-time-token")
	events.set(events.decline, "delete-before:one-time-token", false)
	if status, _ := redeem(token); status != 200 {
		t.Fatal("the retried token answered", status)
	}
	sameEvents(t, events.drain(), "delete-before:one-time-token", "delete-after:one-time-token")
	if spent, _ := events.last(); spent != created {
		t.Fatal("the redeem's record was", spent, "want", created)
	}
	if status, message := redeem(token); status != 400 || message != "Invalid token" {
		t.Fatal("a replayed token answered", status, message)
	}
	sameEvents(t, events.drain())

	// A declined generate returns a token that redeems nothing.
	events.set(events.decline, "create-before:one-time-token", true)
	unusable := generate(cookie)
	sameEvents(t, events.drain(), "create-before:one-time-token")
	events.set(events.decline, "create-before:one-time-token", false)
	if status, message := redeem(unusable); status != 400 || message != "Invalid token" {
		t.Fatal("a declined token answered", status, message)
	}
	sameEvents(t, events.drain())

	// The Go API passes no endpoint.
	direct, err := h.auth.GenerateOneTimeToken(context.Background(), http.Header{"Cookie": {cookie}})
	if err != nil {
		t.Fatal(err)
	}
	if _, hc := events.last(); hc != nil {
		t.Fatal("a direct generate passed an endpoint")
	}
	if _, err := h.auth.VerifyOneTimeToken(context.Background(), direct); err != nil {
		t.Fatal(err)
	}
	if _, hc := events.last(); hc != nil {
		t.Fatal("a direct redeem passed an endpoint")
	}
	events.drain()

	// An after hook's error fails the redeem rather than reading as an
	// invalid token.
	token = generate(cookie)
	events.drain()
	events.failWith("delete-after:one-time-token", fmt.Errorf("lookup: %w", authn.ErrNotFound))
	if status, _ := redeem(token); status != 500 {
		t.Fatal("an after hook's error answered", status)
	}
	events.failWith("delete-after:one-time-token", nil)
	sameEvents(t, events.drain(), "delete-before:one-time-token", "delete-after:one-time-token")

	// Concurrent redemptions of one token run one delete after hook.
	token = generate(cookie)
	events.drain()
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for range 8 {
		wg.Go(func() { status, _ := redeem(token); codes <- status })
	}
	wg.Wait()
	close(codes)
	ok := 0
	for status := range codes {
		if status == 200 {
			ok++
		}
	}
	afters := 0
	for _, e := range events.drain() {
		if e == "delete-after:one-time-token" {
			afters++
		}
	}
	if ok != 1 || afters != 1 {
		t.Fatal("concurrent redemptions succeeded", ok, "times and ran", afters, "after hooks")
	}

	// A token whose session ended is spent: its after hooks run, then the
	// refusal.
	token = generate(cookie)
	c.post("/sign-out", `{}`, cookie, 200)
	events.drain()
	if status, message := redeem(token); status != 400 || message != "Session not found" {
		t.Fatal("a token of an ended session answered", status, message)
	}
	sameEvents(t, events.drain(), "delete-before:one-time-token", "delete-after:one-time-token")
	if status, _ := redeem(token); status != 400 {
		t.Fatal("a spent token answered", status)
	}
	sameEvents(t, events.drain())

	// A store whose finder misses a token it then spends is refused.
	blind := newMagicHost(t, blindFinders{store}, events, nil)
	cookie, _ = sessionClient{t, blind.auth}.signIn("ada@example.test")
	token = generateWith(t, blind, cookie)
	events.drain()
	if w := blind.serve("POST", "/one-time-token/verify", `{"token":"`+token+`"}`, ""); w.Code != 400 {
		t.Fatal("an unseen spend answered", w.Code, w.Body.String())
	}
	sameEvents(t, events.drain())
	if !strings.Contains(blind.logs.String(), "spent that its delete hooks did not see") {
		t.Fatal("an unseen spend was not logged:", blind.logs.String())
	}
}

func generateWith(t *testing.T, h *magicHost, cookie string) string {
	t.Helper()
	w := h.serve("GET", "/one-time-token/generate", "", cookie)
	var out struct{ Token string }
	if w.Code != 200 || jsonDecode(w.Body.Bytes(), &out) != nil || out.Token == "" {
		t.Fatal("generate answered", w.Code, w.Body.String())
	}
	return out.Token
}

func jsonDecode(raw []byte, v any) error {
	if len(raw) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(raw, v)
}
