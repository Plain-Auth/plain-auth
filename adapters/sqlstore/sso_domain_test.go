package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

type dnsAnswers struct {
	queries atomic.Int32
	mu      sync.Mutex
	records map[string][]string
	pause   func(context.Context) error
}

func (d *dnsAnswers) LookupTXT(ctx context.Context, name string) ([]string, error) {
	d.mu.Lock()
	d.queries.Add(1)
	v := d.records[name]
	pause := d.pause
	d.mu.Unlock()
	if pause != nil {
		if err := pause(ctx); err != nil {
			return nil, err
		}
	}
	if v == nil {
		return nil, errors.New("fixture DNS lookup failed")
	}
	return v, nil
}
func (d *dnsAnswers) put(name, record string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[name] = []string{"unrelated", record}
}
func (d *dnsAnswers) barrier() (chan struct{}, chan struct{}) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	d.mu.Lock()
	d.pause = func(ctx context.Context) error {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
			return nil
		}
	}
	d.mu.Unlock()
	return entered, release
}
func (d *dnsAnswers) resume(release chan struct{}) {
	d.mu.Lock()
	d.pause = nil
	close(release)
	d.mu.Unlock()
}

func TestEnterpriseDomainVerification(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			status := func(err error, want int, code string) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != want || (code != "" && api.Code != code) {
					t.Fatalf("expected %d %s, got %v", want, code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func(profile string) *Store {
				ddl, e := schema.Generate(dialect, []string{"organization", profile})
				must(e)
				s, e := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(e)
				t.Cleanup(func() { s.Close() })
				return s
			}
			a := open("sso")
			dns := &dnsAnswers{records: map[string][]string{}}
			idp := newSSOIssuer(t)
			host := func(s *Store, o *sso.DomainVerificationOptions, explicitOnly bool) (*auth.Auth, error) {
				pl, e := sso.New(sso.Options{DomainVerification: o})
				if e != nil {
					return nil, e
				}
				return auth.New(auth.Options{BaseURL: "https://domain.test", BasePath: "/identity", Store: s, DisableImplicitAccountLinking: explicitOnly, Secret: strings.Repeat("x", 32), TrustedOrigins: []string{idp.URL}, EmailAndPassword: true, RateLimit: new(bool), Plugins: []auth.Plugin{pl}})
			}
			opt := &sso.DomainVerificationOptions{Resolver: dns}
			if _, err := host(a, opt, false); err == nil {
				t.Fatal("enabled DNS without migrated schema")
			}
			plain, e := host(a, nil, false)
			must(e)
			sdk := func(h *auth.Auth) *client.Client {
				c, e := client.New("https://domain.test/identity", &http.Client{Transport: guestTransport{h}})
				must(e)
				return c
			}
			plainOwner := sdk(plain)
			credentials := client.SignUpRequest{Name: "Owner", Email: "owner@local.example", Password: "an independent fixture password"}
			owner, e := plainOwner.SignUpEmail(ctx, credentials)
			must(e)
			params := client.RegisterOIDCProviderRequest{ProviderID: "corp", Domain: " Proof.Example,second.example,proof.example ", Issuer: idp.URL, OIDC: client.OIDCRegistration{SkipDiscovery: true, Config: sso.Config{ClientID: "enterprise-client", ClientSecret: "oidc-secret", TokenEndpointAuthentication: "client_secret_basic", AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys"}}}
			legacy := params
			legacy.ProviderID = "previous"
			legacy.Domain = "import.example"
			prior, e := plainOwner.RegisterOIDCProvider(ctx, legacy)
			must(e)
			b := open("sso-domain-verification")
			if err := a.CheckSSODomainSchema(ctx); err != nil {
				t.Fatalf("existing instance did not see migrated profile: %v", err)
			}
			first, e := host(a, opt, false)
			must(e)
			second, e := host(b, opt, false)
			must(e)
			signed := func(h *auth.Auth) *client.Client {
				c := sdk(h)
				_, e := c.SignInEmail(ctx, client.SignInRequest{Email: credentials.Email, Password: credentials.Password})
				must(e)
				return c
			}
			one, two := signed(first), signed(second)
			exec := func(q string, args ...any) { _, e := a.db.ExecContext(ctx, a.bind(q), args...); must(e) }
			exec(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`, true, prior.ID)
			p, e := one.GetSSOProvider(ctx, prior.ProviderID)
			must(e)
			if p.DomainVerified {
				t.Fatal("unbound imported flag granted ownership")
			}
			_, e = one.RequestSSODomainVerification(ctx, prior.ProviderID)
			must(e)
			reg, e := one.RegisterOIDCProvider(ctx, params)
			must(e)
			if reg.DomainVerified == nil || *reg.DomainVerified || len(reg.DomainVerificationToken) != 24 || reg.Domain != "proof.example,second.example" {
				t.Fatal("missing registration challenge or normalized domain")
			}
			const label = "_stonewrit-auth-token-corp"
			token := reg.DomainVerificationToken
			var expires, created time.Time
			must(b.db.QueryRowContext(ctx, b.bind(`SELECT "expiresAt","createdAt" FROM "verification" WHERE "identifier"=? AND "value"=?`), label, token).Scan(&expires, &created))
			if expires.Sub(created) != 7*24*time.Hour {
				t.Fatal("challenge lifetime", expires.Sub(created))
			}
			active, e := two.RequestSSODomainVerification(ctx, "corp")
			must(e)
			if active != token {
				t.Fatal("second store replaced active challenge")
			}
			_, e = sdk(first).RequestSSODomainVerification(ctx, "corp")
			status(e, 401, "")
			foreign := sdk(first)
			_, e = foreign.SignUpEmail(ctx, client.SignUpRequest{Name: "Foreign", Email: "foreign@local.example", Password: credentials.Password})
			must(e)
			_, e = foreign.RequestSSODomainVerification(ctx, "corp")
			status(e, 403, "")
			start := client.SSOSignInRequest{Domain: "team.proof.example", CallbackURL: "/home"}
			for _, h := range []*auth.Auth{first, plain} {
				_, e = sdk(h).SignInSSO(ctx, start)
				status(e, 401, "")
			}
			_, e = two.SignInSSO(ctx, client.SSOSignInRequest{Domain: "lookalikeproof.example", CallbackURL: "/home"})
			status(e, 404, "")
			dns.put(label+".proof.example.", " "+token+" ")
			e = two.VerifySSODomain(ctx, "corp")
			status(e, 502, "DOMAIN_VERIFICATION_FAILED")
			dns.put(label+".second.example.", label+"=incorrect")
			status(two.VerifySSODomain(ctx, "corp"), 502, "DOMAIN_VERIFICATION_FAILED")
			exec(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`, a.date(time.Now().Add(-time.Minute)), label)
			status(one.VerifySSODomain(ctx, "corp"), 404, "NO_PENDING_VERIFICATION")
			result := make(chan string, 2)
			errs := make(chan error, 2)
			for _, c := range []*client.Client{one, two} {
				go func() { v, e := c.RequestSSODomainVerification(ctx, "corp"); result <- v; errs <- e }()
			}
			l, r := <-result, <-result
			must(<-errs)
			must(<-errs)
			if l == token || l != r {
				t.Fatal("concurrent renewal returned different challenge tokens")
			}
			token = l
			dns.put(label+".proof.example.", token)
			dns.put(label+".second.example.", " "+label+"="+token+" ")
			for _, c := range []*client.Client{one, two} {
				go func() { errs <- c.VerifySSODomain(ctx, "corp") }()
			}
			e1, e2 := <-errs, <-errs
			if e1 != nil {
				e1, e2 = e2, e1
			}
			must(e1)
			status(e2, 409, "DOMAIN_VERIFIED")
			_, e = two.RequestSSODomainVerification(ctx, "corp")
			status(e, 409, "DOMAIN_VERIFIED")
			pub, e := one.ListSSOProviders(ctx)
			must(e)
			if len(pub) != 2 {
				t.Fatal("domain catalog size")
			}
			p, e = two.GetSSOProvider(ctx, "corp")
			must(e)
			if !p.DomainVerified {
				t.Fatal("peer did not observe the completed ownership proof")
			}
			// An independent manager cannot shadow a proved tenant by requesting its suffix.
			other := params
			other.ProviderID = "pending-exact"
			other.Domain = "proof.example"
			_, e = foreign.RegisterOIDCProvider(ctx, other)
			must(e)
			other.ProviderID = "pending-specific"
			other.Domain = "team.proof.example"
			_, e = foreign.RegisterOIDCProvider(ctx, other)
			must(e)
			for _, h := range []*auth.Auth{first, plain} {
				for _, domain := range []string{"proof.example", "team.proof.example"} {
					r, e := sdk(h).SignInSSO(ctx, client.SSOSignInRequest{Domain: domain, CallbackURL: "/home"})
					must(e)
					u, e := url.Parse(r.URL)
					must(e)
					if !strings.HasSuffix(u.Query().Get("redirect_uri"), "/corp") {
						t.Fatal("pending directory shadowed a verified route")
					}
				}
				_, e := sdk(h).SignInSSO(ctx, client.SSOSignInRequest{ProviderID: "pending-specific", CallbackURL: "/home"})
				status(e, 401, "")
			}
			// The local identity provider signs the user's email independently of the browser's routing hint.
			person := func(email string, verified bool) string {
				now := time.Now()
				id := rand.Text()
				must(a.CreateUser(ctx, auth.User{ID: id, Email: email, Name: "Existing", EmailVerified: verified, CreatedAt: now, UpdatedAt: now}, rand.Text(), nil))
				return id
			}
			existingID := person("existing@team.proof.example", true)
			person("existing@unrelated.example", true)
			person("unverified@proof.example", false)
			callbackHost := plain
			browser := func(email string, finish func()) *httptest.ResponseRecorder {
				t.Helper()
				request := httptest.NewRequest("POST", "https://domain.test/identity/sign-in/sso", strings.NewReader(`{"email":"hint@proof.example","callbackURL":"/home"}`))
				request.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				first.ServeHTTP(w, request)
				if w.Code != 200 {
					t.Fatal("browser initiation", w.Code, w.Body.String())
				}
				var out client.SSOAuthorization
				must(json.Unmarshal(w.Body.Bytes(), &out))
				u, e := url.Parse(out.URL)
				must(e)
				q := u.Query()
				code := rand.Text()
				idp.mu.Lock()
				mode := ""
				if email == "inflight@proof.example" {
					mode = "pause"
				}
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"), email, "idp-" + email, "client_secret_basic", mode}
				idp.mu.Unlock()
				if finish != nil {
					finish()
				}
				cb := httptest.NewRequest("GET", q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), nil)
				for _, cookie := range w.Result().Cookies() {
					cb.AddCookie(cookie)
				}
				w = httptest.NewRecorder()
				callbackHost.ServeHTTP(w, cb)
				return w
			}
			strict, e := host(b, opt, true)
			must(e)
			callbackHost = strict
			w := browser("existing@team.proof.example", nil)
			if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "account_not_linked") {
				t.Fatal("DNS-based authority bypassed explicit account linking", w.Code, w.Header().Get("Location"))
			}
			callbackHost = plain
			w = browser("existing@team.proof.example", nil)
			if w.Code != 302 || !strings.HasSuffix(w.Header().Get("Location"), "/home") {
				t.Fatal("proved subdomain failed to link verified existing identity", w.Code, w.Body.String(), w.Header().Get("Location"))
			}
			var linked string
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT "userId" FROM "account" WHERE "providerId"=? AND "accountId"=?`), "corp", "idp-existing@team.proof.example").Scan(&linked))
			if linked != existingID {
				t.Fatal("linked incorrect user")
			}
			for _, email := range []string{"existing@unrelated.example", "unverified@proof.example"} {
				w := browser(email, nil)
				if !strings.Contains(w.Header().Get("Location"), "account_not_linked") {
					t.Fatal("email outside trust scope linked", email, w.Code, w.Body.String())
				}
			}
			pending := make(chan *httptest.ResponseRecorder, 1)
			go func() { pending <- browser("inflight@proof.example", nil) }()
			<-idp.entered
			exec(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`, false, reg.ID)
			close(idp.release)
			if w := <-pending; w.Code != 401 {
				t.Fatal("session transaction missed a proof withdrawn during exchange", w.Code, w.Body.String())
			}
			var count int
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT COUNT(*) FROM "user" WHERE "email"=?`), "inflight@proof.example").Scan(&count))
			if count != 0 {
				t.Fatal("withdrawn proof left a partial account")
			}
			exec(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`, true, reg.ID)
			if dialect == "mysql" {
				// The fixture uses an accent-insensitive collation so distinct imported
				// mailboxes can compare equal in SQL during candidate selection.
				exec(`ALTER TABLE "user" MODIFY "email" varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL`)
				person("résumé@team.proof.example", true)
				w := browser("resume@team.proof.example", nil)
				if !strings.Contains(w.Header().Get("Location"), "account_not_linked") {
					t.Fatal("collation-equivalent different mailbox was linked")
				}
			}
			before := idp.tokens.Load()
			w = browser("invalidated@proof.example", func() { exec(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`, false, reg.ID) })
			if w.Code != 401 || idp.tokens.Load() != before {
				t.Fatal("unchecked callback reached the identity provider")
			}
			// A live scope change invalidates the old token, even when its DNS records persist.
			old, e := two.RequestSSODomainVerification(ctx, "corp")
			must(e)
			dns.put(label+".proof.example.", old)
			dns.put(label+".second.example.", old)
			entered, release := dns.barrier()
			go func() { errs <- one.VerifySSODomain(ctx, "corp") }()
			<-entered
			exec(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`, a.date(time.Now().Add(-time.Minute)), label)
			renewed, e := two.RequestSSODomainVerification(ctx, "corp")
			must(e)
			dns.resume(release)
			status(<-errs, 409, "SSO_PROVIDER_CHANGED")
			dns.put(label+".proof.example.", renewed)
			dns.put(label+".second.example.", renewed)
			entered, release = dns.barrier()
			go func() { errs <- one.VerifySSODomain(ctx, "corp") }()
			<-entered
			exec(`UPDATE "ssoProvider" SET "domain"=? WHERE "id"=?`, "new.example", reg.ID)
			dns.resume(release)
			status(<-errs, 409, "SSO_PROVIDER_CHANGED")
			next, e := two.RequestSSODomainVerification(ctx, "corp")
			must(e)
			if next == old {
				t.Fatal("changed scope reused previous proof")
			}
			dns.put(label+".new.example.", next)
			// Recheck the tenant and live administrator after a potentially slow lookup.
			now := time.Now()
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`, "dns-org", "DNS", "dns", a.date(now))
			exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`, "dns-owner", "dns-org", owner.User.ID, "admin", a.date(now))
			exec(`UPDATE "ssoProvider" SET "organizationId"=? WHERE "id"=?`, "dns-org", reg.ID)
			status(two.VerifySSODomain(ctx, "corp"), 404, "NO_PENDING_VERIFICATION")
			next, e = two.RequestSSODomainVerification(ctx, "corp")
			must(e)
			dns.put(label+".new.example.", next)
			entered, release = dns.barrier()
			go func() { errs <- one.VerifySSODomain(ctx, "corp") }()
			<-entered
			exec(`UPDATE "member" SET "role"='member' WHERE "id"='dns-owner'`)
			dns.resume(release)
			status(<-errs, 403, "")
			exec(`UPDATE "member" SET "role"='admin' WHERE "id"='dns-owner'`)
			must(two.VerifySSODomain(ctx, "corp"))
			// Legacy registrations can retain their original IDs for ordinary management.
			for _, tc := range []struct{ id, domain, code string }{
				{strings.Repeat("a", 46), "long.example", "IDENTIFIER_TOO_LONG"},
				{"legacy.dotted", "bound.example", "INVALID_VERIFICATION_IDENTIFIER"},
				{"oversized", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 53), "INVALID_DOMAIN"},
			} {
				spec := params
				spec.ProviderID = tc.id
				spec.Domain = tc.domain
				_, e = two.RegisterOIDCProvider(ctx, spec)
				status(e, 400, tc.code)
				old, e := plainOwner.RegisterOIDCProvider(ctx, spec)
				must(e)
				exec(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE "id"=?`, true, old.ID)
				calls := dns.queries.Load()
				_, e = two.RequestSSODomainVerification(ctx, tc.id)
				status(e, 400, tc.code)
				status(two.VerifySSODomain(ctx, tc.id), 400, tc.code)
				if calls != dns.queries.Load() {
					t.Fatal("malformed verification name reached DNS")
				}
				_, e = two.SignInSSO(ctx, client.SSOSignInRequest{ProviderID: tc.id, CallbackURL: "/home"})
				status(e, 401, "")
			}
			// Bind the live proof to the exact confidential client's identity source.
			config := params
			config.ProviderID = "authority"
			config.Domain = "authority.example"
			directory, e := one.RegisterOIDCProvider(ctx, config)
			must(e)
			const authLabel = "_stonewrit-auth-token-authority"
			dns.put(authLabel+".authority.example.", directory.DomainVerificationToken)
			change := func(key, value string) {
				var raw string
				must(a.db.QueryRowContext(ctx, a.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "id"=?`), directory.ID).Scan(&raw))
				var cfg map[string]any
				must(json.Unmarshal([]byte(raw), &cfg))
				cfg[key] = value
				encoded, e := json.Marshal(cfg)
				must(e)
				exec(`UPDATE "ssoProvider" SET "oidcConfig"=? WHERE "id"=?`, string(encoded), directory.ID)
			}
			entered, release = dns.barrier()
			go func() { errs <- two.VerifySSODomain(ctx, "authority") }()
			<-entered
			captured, e := a.FindBrowserProvider(ctx, sso.Selector{ProviderID: "authority"})
			must(e)
			change("jwksEndpoint", idp.URL+"/replacement-keys")
			dns.resume(release)
			status(<-errs, 409, "SSO_PROVIDER_CHANGED")
			again, e := one.RequestSSODomainVerification(ctx, "authority")
			must(e)
			if again == directory.DomainVerificationToken {
				t.Fatal("identity source change reused the old DNS challenge")
			}
			dns.put(authLabel+".authority.example.", again)
			must(two.VerifySSODomain(ctx, "authority"))
			valid, e := b.SSODomainVerified(ctx, captured.Provider, captured.Reference)
			must(e)
			if valid {
				t.Fatal("stale identity source borrowed the replacement proof before exchange")
			}
			change("clientSecret", "rotated-secret")
			public, e := one.GetSSOProvider(ctx, "authority")
			must(e)
			if !public.DomainVerified {
				t.Fatal("rotating only the client secret invalidated proof")
			}
			change("userInfoEndpoint", idp.URL+"/different-userinfo")
			public, e = two.GetSSOProvider(ctx, "authority")
			must(e)
			if public.DomainVerified {
				t.Fatal("changed identity source retained email-link authority")
			}
			// The existing enterprise login retains its original personal authority. Restore it before deletion.
			status(one.DeleteSSOProvider(ctx, "corp"), 409, "SSO_ACCOUNT_ORIGIN_REQUIRED")
			exec(`UPDATE "ssoProvider" SET "organizationId"=NULL WHERE "id"=?`, reg.ID)
			must(one.DeleteSSOProvider(ctx, "corp"))
			var n int
			must(b.db.QueryRowContext(ctx, b.bind(`SELECT COUNT(*) FROM "verification" WHERE "id" IN (?,?)`), originDigest("dc-", reg.ID), originDigest("dp-", reg.ID)).Scan(&n))
			if n != 0 {
				t.Fatal("deleted provider retained DNS material")
			}
		})
	}
}
