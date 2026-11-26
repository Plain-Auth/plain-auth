package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// hookLog records the verification and session create hooks a test runs.
// Each hook first reads through every store with a deadline, which a hook
// run inside a store's transaction or under its lock would miss on SQLite's
// one connection, and then runs probe, if set.
type hookLog struct {
	t       *testing.T
	stores  []*Store
	mu      sync.Mutex
	events  []string
	records []auth.VerificationRecord
	skip    map[string]bool
	fail    map[string]bool
	probe   func(event string)
}

func newHookLog(t *testing.T, stores ...*Store) *hookLog {
	return &hookLog{t: t, stores: stores, skip: map[string]bool{}, fail: map[string]bool{}}
}

func (l *hookLog) note(ctx context.Context, event string, rec *auth.VerificationRecord) error {
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, s := range l.stores {
		var n int
		if err := s.db.QueryRowContext(read, s.bind(`SELECT COUNT(*) FROM "verification"`)).Scan(&n); err != nil {
			l.t.Error("a store was locked during", event, err)
		}
	}
	l.mu.Lock()
	probe := l.probe
	l.mu.Unlock()
	if probe != nil {
		probe(event)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	if rec != nil {
		l.records = append(l.records, *rec)
	}
	if l.skip[event] {
		return auth.ErrSkipWrite
	}
	if l.fail[event] {
		return errors.New("hook failed")
	}
	return nil
}

func (l *hookLog) set(m map[string]bool, event string, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m[event] = on
}

func (l *hookLog) setProbe(probe func(string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.probe = probe
}

func (l *hookLog) drain() ([]string, []auth.VerificationRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, r := l.events, l.records
	l.events, l.records = nil, nil
	return e, r
}

func (l *hookLog) same(got []string, want ...string) {
	l.t.Helper()
	if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
		l.t.Fatalf("hooks ran as %q, want %q", got, want)
	}
}

// clean fails when any record carries one of secrets.
func (l *hookLog) clean(recs []auth.VerificationRecord, secrets ...string) {
	l.t.Helper()
	for _, r := range recs {
		for _, secret := range secrets {
			if secret != "" && strings.Contains(fmt.Sprint(r), secret) {
				l.t.Fatal("a record carried a secret:", r)
			}
		}
	}
}

func (l *hookLog) hooks() auth.DatabaseHooks {
	var h auth.DatabaseHooks
	v := &h.Verification
	v.Create.Before = func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
		return l.note(ctx, "v-create-before:"+r.Identifier, r)
	}
	v.Create.After = func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
		return l.note(ctx, "v-create-after:"+r.Identifier, &r)
	}
	v.Update.After = func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
		return l.note(ctx, "v-update-after:"+r.Identifier, &r)
	}
	v.Delete.Before = func(ctx context.Context, r *auth.VerificationRecord, _ *auth.HookContext) error {
		return l.note(ctx, "v-delete-before:"+r.Identifier, r)
	}
	v.Delete.After = func(ctx context.Context, r auth.VerificationRecord, _ *auth.HookContext) error {
		return l.note(ctx, "v-delete-after:"+r.Identifier, &r)
	}
	h.Session.Create.Before = func(ctx context.Context, _ *auth.SessionRecord, _ *auth.HookContext) error {
		return l.note(ctx, "session-before", nil)
	}
	h.Session.Create.After = func(ctx context.Context, _ auth.SessionRecord, _ *auth.HookContext) error {
		return l.note(ctx, "session-after", nil)
	}
	return h
}

// An enterprise OpenID Connect sign-in keeps its state in an oauth-state
// record on SQLite, PostgreSQL and MySQL: its create hooks run when the
// sign-in starts, and its delete hooks when the callback spends it, before
// the code is exchanged and before the session's hooks.
func TestVerificationHooksAroundEnterpriseSignIn(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, e := schema.Generate(dialect, []string{"sso"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer first.Close()
			other, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer other.Close()
			idp := newSSOIssuer(t)
			log := newHookLog(t, first, other)
			host := func(s *Store) *auth.Auth {
				p, e := sso.New(sso.Options{})
				must(e)
				a, e := auth.New(auth.Options{BaseURL: "https://service.test", BasePath: "/identity", RateLimit: new(bool), Store: s, Secret: strings.Repeat("k", 32),
					TrustedOrigins: []string{idp.URL}, Plugins: []auth.Plugin{p}, DatabaseHooks: log.hooks()})
				must(e)
				return a
			}
			one, two := host(first), host(other)
			call := func(a *auth.Auth, method, path, cookie string, body any) *httptest.ResponseRecorder {
				var buf bytes.Buffer
				if body != nil {
					json.NewEncoder(&buf).Encode(body)
				}
				req := httptest.NewRequest(method, "https://service.test/identity/"+path, &buf)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://service.test")
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				w := httptest.NewRecorder()
				a.ServeHTTP(w, req)
				return w
			}
			now := time.Now().UTC()
			must(first.CreateUser(ctx, auth.User{ID: "owner", Name: "owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			cfg := sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token",
				JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_post", PKCE: new(bool)}
			*cfg.PKCE = true
			raw, _ := json.Marshal(cfg)
			_, e = first.db.ExecContext(ctx, first.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId") VALUES (?,?,?,?,?,?)`), "record-staff", "staff", idp.URL, string(raw), "staff.example", "owner")
			must(e)
			type pending struct{ cookie, state, nonce, challenge, path string }
			start := func(a *auth.Auth, status int) (pending, *httptest.ResponseRecorder) {
				t.Helper()
				w := call(a, "POST", "sign-in/sso", "", map[string]any{"providerId": "staff", "callbackURL": "/home", "newUserCallbackURL": "/welcome", "errorCallbackURL": "/retry"})
				if w.Code != status {
					t.Fatalf("start %d %s", w.Code, w.Body.String())
				}
				if status != 200 {
					return pending{}, w
				}
				var result struct{ URL string }
				must(json.Unmarshal(w.Body.Bytes(), &result))
				u, e := url.Parse(result.URL)
				must(e)
				q := u.Query()
				code := rand.Text()
				idp.mu.Lock()
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), "employee@staff.example", rand.Text(), "client_secret_post", ""}
				idp.mu.Unlock()
				cb, e := url.Parse(q.Get("redirect_uri"))
				must(e)
				c := w.Result().Cookies()[0]
				return pending{c.Name + "=" + c.Value, q.Get("state"), q.Get("nonce"), q.Get("code_challenge"),
					strings.TrimPrefix(cb.Path, "/identity/") + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()}, w
			}
			target := func(w *httptest.ResponseRecorder, want string) {
				t.Helper()
				if w.Code != 302 || w.Header().Get("Location") != "https://service.test"+want {
					t.Fatalf("callback: got %d %s %s want %s", w.Code, w.Header().Get("Location"), w.Body.String(), want)
				}
			}
			flowRow := func(state string) (time.Time, bool) {
				t.Helper()
				var expires time.Time
				err := first.db.QueryRowContext(ctx, first.bind(`SELECT "expiresAt" FROM "verification" WHERE "id"=? AND "identifier" LIKE 'oauth-state:%'`), state).Scan(&expires)
				return expires, err == nil
			}
			flows := func() int {
				t.Helper()
				var n int
				must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'oauth-state:%'`)).Scan(&n))
				return n
			}

			// A declined enterprise flow is never stored.
			log.set(log.skip, "v-create-before:oauth-state", true)
			before := flows()
			_, w := start(one, 500)
			log.set(log.skip, "v-create-before:oauth-state", false)
			if !strings.Contains(w.Body.String(), "STATE_GENERATION_ERROR") || len(w.Result().Cookies()) != 0 || flows() != before {
				t.Fatal("a declined enterprise flow answered", w.Body.String(), "and stored", flows()-before)
			}
			got, _ := log.drain()
			log.same(got, "v-create-before:oauth-state")
			// An approved flow names the state the provider returns, and no owner.
			f, _ := start(one, 200)
			got, recs := log.drain()
			log.same(got, "v-create-before:oauth-state", "v-create-after:oauth-state")
			expires, stored := flowRow(f.state)
			want := auth.VerificationRecord{ID: f.state, Identifier: "oauth-state", ExpiresAt: expires.UTC().Truncate(time.Millisecond)}
			if !stored || recs[0] != want || recs[1] != want {
				t.Fatal("the flow's hooks saw", recs, "for", want)
			}
			log.clean(recs, f.nonce, f.challenge, f.cookie, "/home", "/welcome", "/retry")

			// A declined callback keeps the flow, so the retry signs in.
			tokens := idp.tokens.Load()
			log.set(log.skip, "v-delete-before:oauth-state", true)
			target(call(two, "GET", f.path, f.cookie, nil), "/identity/error?error=state_mismatch")
			log.set(log.skip, "v-delete-before:oauth-state", false)
			got, _ = log.drain()
			log.same(got, "v-delete-before:oauth-state")
			if _, stored := flowRow(f.state); !stored || idp.tokens.Load() != tokens {
				t.Fatal("a declined callback spent the flow or exchanged its code")
			}
			// The flow's hooks run once, before the session's, despite the
			// sign-in's dry run.
			target(call(two, "GET", f.path, f.cookie, nil), "/welcome")
			got, recs = log.drain()
			log.same(got, "v-delete-before:oauth-state", "v-delete-after:oauth-state", "session-before", "session-after")
			if recs[0] != want || recs[1] != want {
				t.Fatal("the callback's hooks saw", recs)
			}
			// A callback without the browser's state cookie runs no hooks.
			f, _ = start(one, 200)
			log.drain()
			target(call(two, "GET", f.path, "", nil), "/identity/error?error=state_mismatch")
			got, _ = log.drain()
			log.same(got)
			// A provider error still spends the flow with its hooks.
			errorPath := strings.SplitN(f.path, "?", 2)[0] + "?" + url.Values{"error": {"access_denied"}, "state": {f.state}}.Encode()
			if w := call(one, "GET", errorPath, f.cookie, nil); w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://service.test/retry?error=") {
				t.Fatal("a provider error answered", w.Code, w.Header().Get("Location"))
			}
			got, _ = log.drain()
			log.same(got, "v-delete-before:oauth-state", "v-delete-after:oauth-state")
			if _, stored := flowRow(f.state); stored {
				t.Fatal("a provider error kept the flow")
			}
		})
	}
}

// SSO domain tokens run the verification create hooks on SQLite, PostgreSQL
// and MySQL, outside the store's transaction: registration and a request for
// a new token run them before the token is stored, and returning a live
// token, verifying and deleting a provider run none.
func TestVerificationHooksAroundSSODomains(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				ddl, e := schema.Generate(dialect, []string{"organization", "sso-domain-verification"})
				must(e)
				s, e := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(e)
				t.Cleanup(func() { s.Close() })
				return s
			}
			a, b := open(), open()
			dns := &dnsAnswers{records: map[string][]string{}}
			idp := newSSOIssuer(t)
			log := newHookLog(t, a, b)
			host := func(s *Store) *auth.Auth {
				pl, e := sso.New(sso.Options{DomainVerification: &sso.DomainVerificationOptions{Resolver: dns}})
				must(e)
				h, e := auth.New(auth.Options{BaseURL: "https://domain.test", BasePath: "/identity", Store: s, Secret: strings.Repeat("x", 32), TrustedOrigins: []string{idp.URL},
					EmailAndPassword: true, RateLimit: new(bool), Plugins: []auth.Plugin{pl}, DatabaseHooks: log.hooks()})
				must(e)
				return h
			}
			first, second := host(a), host(b)
			sdk := func(h *auth.Auth) *client.Client {
				c, e := client.New("https://domain.test/identity", &http.Client{Transport: guestTransport{h}})
				must(e)
				return c
			}
			credentials := client.SignUpRequest{Name: "Owner", Email: "owner@local.example", Password: "an independent fixture password"}
			_, e := sdk(first).SignUpEmail(ctx, credentials)
			must(e)
			signed := func(h *auth.Auth) *client.Client {
				c := sdk(h)
				_, e := c.SignInEmail(ctx, client.SignInRequest{Email: credentials.Email, Password: credentials.Password})
				must(e)
				return c
			}
			one, two := signed(first), signed(second)
			log.drain()
			exec := func(q string, args ...any) { _, e := a.db.ExecContext(ctx, a.bind(q), args...); must(e) }
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(a.db.QueryRowContext(ctx, a.bind(q), args...).Scan(&n))
				return n
			}
			register := func(id, domain string) (sso.Registered, error) {
				return one.RegisterOIDCProvider(ctx, client.RegisterOIDCProviderRequest{ProviderID: id, Domain: domain, Issuer: idp.URL, OIDC: client.OIDCRegistration{SkipDiscovery: true,
					Config: sso.Config{ClientID: "enterprise-client", ClientSecret: "oidc-secret", TokenEndpointAuthentication: "client_secret_basic", AuthorizationEndpoint: idp.URL + "/authorize",
						TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys"}}})
			}
			tokenRow := func(label string) (string, string, time.Time) {
				t.Helper()
				var id, token string
				var expires time.Time
				err := a.db.QueryRowContext(ctx, a.bind(`SELECT "id","value","expiresAt" FROM "verification" WHERE "identifier"=?`), label).Scan(&id, &token, &expires)
				if err != nil {
					return "", "", time.Time{}
				}
				return id, token, expires
			}
			providers := func(id string) int {
				return count(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId"=?`, id)
			}

			// A registration runs the token's create hooks with its row's ID and
			// no owner; the before hook sees no provider yet.
			var seenProviders []int
			log.setProbe(func(event string) {
				if strings.HasPrefix(event, "v-create") {
					seenProviders = append(seenProviders, providers("corp"))
				}
			})
			reg, e := register("corp", "proof.example")
			must(e)
			log.setProbe(nil)
			got, recs := log.drain()
			log.same(got, "v-create-before:sso-domain-verification", "v-create-after:sso-domain-verification")
			const label = "_plain-auth-token-corp"
			id, token, expires := tokenRow(label)
			want := sso.DomainChallengeRecord(id, expires)
			if token != reg.DomainVerificationToken || id != originDigest("dc-", reg.ID) || recs[0] != want || recs[1] != want || !reflect.DeepEqual(seenProviders, []int{0, 1}) {
				t.Fatal("the token's hooks saw", recs, "for", want, "while the provider rows were", seenProviders)
			}
			log.clean(recs, token, label, "corp", "proof.example")
			// A live token is returned without hooks.
			if live, e := two.RequestSSODomainVerification(ctx, "corp"); e != nil || live != token {
				t.Fatal("a live token request answered", live, e)
			}
			got, _ = log.drain()
			log.same(got)
			// Verifying and deleting a provider run no verification hooks.
			dns.put(label+".proof.example.", token)
			must(two.VerifySSODomain(ctx, "corp"))
			must(one.DeleteSSOProvider(ctx, "corp"))
			got, _ = log.drain()
			for _, e := range got {
				if strings.HasPrefix(e, "v-") {
					t.Fatal("verifying or deleting a provider ran", got)
				}
			}

			// A declined token registers the provider, and verification answers 404.
			log.set(log.skip, "v-create-before:sso-domain-verification", true)
			reg, e = register("pending", "pending.example")
			log.set(log.skip, "v-create-before:sso-domain-verification", false)
			must(e)
			got, _ = log.drain()
			log.same(got, "v-create-before:sso-domain-verification")
			const pendingLabel = "_plain-auth-token-pending"
			if id, _, _ := tokenRow(pendingLabel); id != "" || reg.DomainVerificationToken == "" || providers("pending") != 1 || count(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`, originDigest("dp-", reg.ID)) != 1 {
				t.Fatal("a declined token was stored, or its provider was not registered as pending")
			}
			dns.put(pendingLabel+".pending.example.", reg.DomainVerificationToken)
			var api *auth.APIError
			if e := one.VerifySSODomain(ctx, "pending"); !errors.As(e, &api) || api.Status != 404 {
				t.Fatal("a declined token verified:", e)
			}
			fresh, e := one.RequestSSODomainVerification(ctx, "pending")
			must(e)
			got, _ = log.drain()
			log.same(got, "v-create-before:sso-domain-verification", "v-create-after:sso-domain-verification")
			dns.put(pendingLabel+".pending.example.", fresh)
			must(one.VerifySSODomain(ctx, "pending"))
			log.drain()

			// A declined reissue leaves the earlier token and proof as they were.
			reg, e = register("reissue", "reissue.example")
			must(e)
			const reissueLabel = "_plain-auth-token-reissue"
			exec(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`, a.date(time.Now().Add(-time.Minute)), reissueLabel)
			snapshot := func() string {
				t.Helper()
				var out strings.Builder
				rows, e := a.db.QueryContext(ctx, a.bind(`SELECT "id","identifier","value","expiresAt" FROM "verification" WHERE "id" IN (?,?) ORDER BY "id"`), originDigest("dc-", reg.ID), originDigest("dp-", reg.ID))
				must(e)
				defer rows.Close()
				for rows.Next() {
					var id, identifier, value string
					var expires time.Time
					must(rows.Scan(&id, &identifier, &value, &expires))
					fmt.Fprintln(&out, id, identifier, value, expires.UnixMilli())
				}
				return out.String()
			}
			kept := snapshot()
			log.drain()
			log.set(log.skip, "v-create-before:sso-domain-verification", true)
			declined, e := one.RequestSSODomainVerification(ctx, "reissue")
			log.set(log.skip, "v-create-before:sso-domain-verification", false)
			must(e)
			got, _ = log.drain()
			log.same(got, "v-create-before:sso-domain-verification")
			if declined == "" || snapshot() != kept {
				t.Fatal("a declined reissue changed the token or proof")
			}
			dns.put(reissueLabel+".reissue.example.", declined)
			if e := one.VerifySSODomain(ctx, "reissue"); !errors.As(e, &api) || api.Status != 404 {
				t.Fatal("a declined reissue verified:", e)
			}
			// Concurrent domain token requests store one token and run its after hooks once.
			result := make(chan string, 2)
			errs := make(chan error, 2)
			for _, c := range []*client.Client{one, two} {
				go func() { v, e := c.RequestSSODomainVerification(ctx, "reissue"); result <- v; errs <- e }()
			}
			l, r := <-result, <-result
			must(<-errs)
			must(<-errs)
			after := 0
			got, _ = log.drain()
			for _, e := range got {
				if e == "v-create-after:sso-domain-verification" {
					after++
				}
			}
			if l != r || after != 1 {
				t.Fatal("two concurrent requests answered", l, r, "with", after, "after hooks")
			}

			// A failed after hook is returned with the provider registered, and
			// its live token is then returned without hooks.
			log.set(log.fail, "v-create-after:sso-domain-verification", true)
			_, e = register("failing", "failing.example")
			log.set(log.fail, "v-create-after:sso-domain-verification", false)
			if e == nil || providers("failing") != 1 {
				t.Fatal("a failed after hook answered", e)
			}
			log.drain()
			if live, e := one.RequestSSODomainVerification(ctx, "failing"); e != nil || live == "" {
				t.Fatal("the stored token was not returned:", e)
			}
			got, _ = log.drain()
			log.same(got)
		})
	}
}
