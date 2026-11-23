package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

type profileIdentity struct {
	Subject, Email string
	Claims         map[string]any
}
type profileIssuer struct {
	server   *httptest.Server
	mu       sync.Mutex
	identity profileIdentity
	codes    map[string]profileIdentity
	tokens   map[string]profileIdentity
	seq      int
}

func newProfileIssuer(t *testing.T) *profileIssuer {
	f := &profileIssuer{codes: map[string]profileIdentity{}, tokens: map[string]profileIdentity{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/authorize":
			q := r.URL.Query()
			callback, err := url.Parse(q.Get("redirect_uri"))
			if err != nil || callback.Host == "" || q.Get("client_id") != "fields" || q.Get("state") == "" {
				w.WriteHeader(400)
				return
			}
			code := fmt.Sprintf("code-%d", f.seq)
			f.seq++
			f.codes[code] = f.identity
			params := callback.Query()
			params.Set("code", code)
			params.Set("state", q.Get("state"))
			callback.RawQuery = params.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case "/token":
			code := r.FormValue("code")
			identity, ok := f.codes[code]
			if !ok || r.Method != http.MethodPost || r.FormValue("client_secret") != "fields-secret" {
				w.WriteHeader(400)
				return
			}
			delete(f.codes, code)
			f.tokens["access-"+code] = identity
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + code, "token_type": "Bearer"})
		case "/userinfo":
			identity, ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
			if !ok {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(identity)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *profileIssuer) set(subject string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity = profileIdentity{Subject: subject, Email: subject + "@social.test", Claims: fields}
}
func (f *profileIssuer) provider() auth.OAuthProvider {
	base := f.server.URL
	return auth.OAuthProvider{AllowVerifiedEmailLink: true, Config: oauth2.Config{ClientID: "fields", ClientSecret: "fields-secret", Endpoint: oauth2.Endpoint{AuthURL: base + "/authorize", TokenURL: base + "/token", AuthStyle: oauth2.AuthStyleInParams}}, Resolve: func(ctx context.Context, tok *oauth2.Token, _ string) (auth.OAuthProfile, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/userinfo", nil)
		if err != nil {
			return auth.OAuthProfile{}, err
		}
		tok.SetAuthHeader(req)
		res, err := f.server.Client().Do(req)
		if err != nil {
			return auth.OAuthProfile{}, err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return auth.OAuthProfile{}, errors.New("invalid issuer token")
		}
		var profile profileIdentity
		decoder := json.NewDecoder(res.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&profile); err != nil {
			return auth.OAuthProfile{}, err
		}
		return auth.OAuthProfile{Subject: profile.Subject, Email: profile.Email, EmailVerified: true, Name: "Local identity", Data: map[string]any{"locale": "raw-claim"}, AdditionalFields: profile.Claims}, nil
	}}
}

func TestOAuthRegistrationUserFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			// These fields may coincide with a provider response or a browser query.
			// They have no automatic source in either credential.
			fields["accessToken"] = auth.UserField{Type: auth.FieldString, Column: "application_token"}
			fields["state"] = auth.UserField{Type: auth.FieldString, Column: "application_state"}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			issuer := newProfileIssuer(t)
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			opts := auth.Options{Store: store, BaseURL: base, Secret: strings.Repeat("s", 40), RateLimit: &off, UserAdditionalFields: fields, SocialProviders: map[string]auth.OAuthProvider{"work": issuer.provider()}}
			server, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = server
			app.Start()
			defer app.Close()
			jar, _ := cookiejar.New(nil)
			transport := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			c, err := client.New(base, transport)
			if err != nil {
				t.Fatal(err)
			}
			login := func() (string, url.Values) {
				t.Helper()
				start, err := c.SignInSocial(ctx, client.SocialSignInRequest{Provider: "work", DisableRedirect: true, CallbackURL: "/done", ErrorCallbackURL: "/failed?origin=test"})
				if err != nil {
					t.Fatal(err)
				}
				approval, err := transport.Get(start.URL)
				if err != nil {
					t.Fatal(err)
				}
				approval.Body.Close()
				if approval.StatusCode != 302 {
					t.Fatal("authorization", approval.StatusCode)
				}
				cb, err := approval.Location()
				if err != nil {
					t.Fatal(err)
				}
				// Browser callback parameters are separate from the resolved provider profile.
				q := cb.Query()
				q.Set("locale", "browser")
				q.Set("secretNote", "browser private")
				cb.RawQuery = q.Encode()
				res, err := transport.Get(cb.String())
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != 302 {
					t.Fatal("callback", res.StatusCode)
				}
				landing, err := res.Location()
				if err != nil {
					t.Fatal(err)
				}
				return landing.Path, landing.Query()
			}
			issuer.set("ada", nil)
			path, params := login()
			if path != "/failed" || params.Get("error") != "MISSING_FIELD" || params.Get("origin") != "test" {
				t.Fatal(path, params)
			}
			if _, err := store.FindAccountUser(ctx, "ada@social.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("missing provider field committed a profile", err)
			}
			issuer.set("ada", map[string]any{"locale": "en", "activeFlag": false, "score": 0, "accountClass": "provider-forged", "privateRank": 99, "secretNote": "issuer-private", "unknownClaim": "ignored"})
			if path, _ := login(); path != "/done" {
				t.Fatal(path)
			}
			current, err := c.GetSession(ctx)
			if err != nil || current == nil {
				t.Fatal(err)
			}
			id := current.User.ID
			checkUserField(t, current.User, "locale", "en")
			checkUserField(t, current.User, "activeFlag", false)
			checkUserField(t, current.User, "score", int64(0))
			checkUserField(t, current.User, "accountClass", "basic")
			checkUserField(t, current.User, "state", nil)
			checkUserField(t, current.User, "accessToken", nil)
			for _, k := range []string{"privateRank", "secretNote", "unknownClaim", "preferred_locale"} {
				if _, present := current.User.AdditionalField(k); present {
					t.Fatal("unexpected public user field", k)
				}
			}
			if err := server.UpdateTrustedUserFields(ctx, id, map[string]any{"accountClass": "host-owned"}); err != nil {
				t.Fatal(err)
			}
			issuer.set("ada", map[string]any{"locale": false, "accountClass": "second", "secretNote": "replacement"})
			if path, _ := login(); path != "/done" {
				t.Fatal("returning user evaluated signup data", path)
			}
			current, err = c.GetSession(ctx)
			if err != nil || current == nil || current.User.ID != id {
				t.Fatal(err)
			}
			checkUserField(t, current.User, "locale", "en")
			checkUserField(t, current.User, "accountClass", "host-owned")
			var note string
			var rank int
			err = store.db.QueryRowContext(ctx, store.bind(`SELECT "secretNote","privateRank" FROM "user" WHERE "id"=?`), id).Scan(&note, &rank)
			if err != nil || note != "issuer-private" || rank != 9 {
				t.Fatal("private provider and host field sources", note, rank, err)
			}
			// A newly encountered subject that legitimately links to an existing
			// verified mailbox takes the link path and preserves the existing profile.
			issuer.mu.Lock()
			issuer.identity = profileIdentity{Subject: "alternate-subject", Email: "ada@social.test", Claims: map[string]any{"locale": false, "secretNote": "linked-private"}}
			issuer.mu.Unlock()
			if path, _ := login(); path != "/done" {
				t.Fatal("verified mailbox link", path)
			}
			current, err = c.GetSession(ctx)
			if err != nil || current == nil || current.User.ID != id {
				t.Fatal("linked owner", err)
			}
			checkUserField(t, current.User, "locale", "en")
			checkUserField(t, current.User, "accountClass", "host-owned")
			issuer.set("other", map[string]any{"locale": "en", "score": "wrong"})
			if path, q := login(); path != "/failed" || q.Get("error") != "VALIDATION_ERROR" {
				t.Fatal(path, q)
			}
			if _, err := store.FindAccountUser(ctx, "other@social.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("invalid scalar inserted an account", err)
			}
		})
	}
}

type legacySocialProfileStore struct {
	auth.Store
	auth.OAuthStore
	auth.UserFieldStore
}

func TestOAuthRegistrationFieldStoreContract(t *testing.T) {
	ctx := t.Context()
	field := map[string]auth.UserField{"locale": {Type: auth.FieldString}}
	schemaStore, err := OpenWithAdditionalFields(ctx, "sqlite", ":memory:", nil, schema.AdditionalFields{User: field})
	if err != nil {
		t.Fatal(err)
	}
	defer schemaStore.Close()
	old := legacySocialProfileStore{Store: schemaStore, OAuthStore: schemaStore, UserFieldStore: schemaStore}
	provider := newProfileIssuer(t).provider()
	opts := auth.Options{Store: old, BaseURL: "http://app.localhost", Secret: strings.Repeat("s", 40), UserAdditionalFields: field, SocialProviders: map[string]auth.OAuthProvider{"work": provider}}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "OAuthRegistrationStore") {
		t.Fatal("legacy store silently accepted mapped signup", err)
	}
	provider.DisableSignUp = true
	opts.SocialProviders["work"] = provider
	if _, err := auth.New(opts); err != nil {
		t.Fatal("disabled registration required new capability", err)
	}
	provider.DisableSignUp = false
	opts.SocialProviders["work"] = provider
	opts.UserAdditionalFields = nil
	if _, err := auth.New(opts); err != nil {
		t.Fatal("legacy social signup configuration regressed", err)
	}
}
