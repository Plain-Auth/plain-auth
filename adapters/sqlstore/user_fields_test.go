package sqlstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func userFieldFixture() map[string]auth.UserField {
	return map[string]auth.UserField{
		"locale":       {Type: auth.FieldString, Column: "preferred_locale", Required: true},
		"score":        {Type: auth.FieldNumber, Default: 42},
		"activeFlag":   {Type: auth.FieldBoolean},
		"accountClass": {Type: auth.FieldString, ServerOnly: true, Default: "basic"},
		"secretNote":   {Type: auth.FieldString, Hidden: true},
		"privateRank":  {Type: auth.FieldNumber, ServerOnly: true, Hidden: true, Default: 9},
	}
}
func checkUserField(t *testing.T, u auth.User, key string, want any) {
	t.Helper()
	v, ok := u.AdditionalField(key)
	if !ok || v != want {
		t.Fatalf("%s = (%v,%t), want %v", key, v, ok, want)
	}
}
func checkUserFieldError(t *testing.T, err error, code string) {
	t.Helper()
	var api *auth.APIError
	if !errors.As(err, &api) || api.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}
func TestConfiguredUserFieldsAcrossStores(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			var store, peer auth.Store
			if dialect == "memory" {
				store = memory.New()
				peer = store
			} else {
				dsn := organizationTestDSN(t, dialect)
				open := func() *Store {
					s, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, schema.AdditionalFields{User: fields})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					return s
				}
				store, peer = open(), open()
			}
			server := httptest.NewUnstartedServer(nil)
			off := false
			opts := auth.Options{Store: store, BaseURL: "http://" + server.Listener.Addr().String(), Secret: strings.Repeat("s", 40), EmailAndPassword: true, RateLimit: &off, UserAdditionalFields: fields, SessionCookieCache: &auth.SessionCookieCacheOptions{}}
			api, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = api
			server.Start()
			defer server.Close()
			opts.Store = peer
			host, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			httpClient := &http.Client{Jar: jar}
			c, err := client.New(opts.BaseURL, httpClient)
			if err != nil {
				t.Fatal(err)
			}
			input := client.SignUpRequest{Name: "Owner", Email: "profile@fields.test", Password: "local profile test"}
			_, err = c.SignUpEmail(ctx, input)
			checkUserFieldError(t, err, "MISSING_FIELD")
			input.AdditionalFields = map[string]any{"locale": "en", "activeFlag": false, "accountClass": "from-client", "secretNote": "first-secret"}
			signup, err := c.SignUpEmail(ctx, input)
			if err != nil || signup.Token == nil {
				t.Fatal(signup, err)
			}
			id := signup.User.ID
			h := http.Header{"Cookie": {api.SessionCookie(*signup.Token, true).String()}}
			checkUserField(t, signup.User, "locale", "en")
			checkUserField(t, signup.User, "score", int64(42))
			checkUserField(t, signup.User, "accountClass", "basic")
			base, _ := url.Parse(opts.BaseURL + "/api/auth/get-session")
			for _, cookie := range httpClient.Jar.Cookies(base) {
				if strings.Contains(cookie.Name, "session_data") {
					t.Fatal("additional profile persisted in snapshot")
				}
			}
			for _, k := range []string{"secretNote", "privateRank", "preferred_locale"} {
				if _, ok := signup.User.AdditionalField(k); ok {
					t.Fatalf("visible hidden/physical key %s", k)
				}
			}
			renamed := "Updated"
			change := auth.ProfileUpdate{Name: &renamed, AdditionalFields: map[string]any{"locale": "es", "activeFlag": true, "score": 1, "secretNote": "updated-secret"}}
			if err := c.UpdateUser(ctx, change); err != nil {
				t.Fatal(err)
			}
			if err := host.UpdateTrustedUserFields(ctx, id, map[string]any{"accountClass": "host-owned", "privateRank": 0}); err != nil {
				t.Fatal(err)
			}
			if err := host.UpdateTrustedUserFields(ctx, id+"-missing", map[string]any{"locale": "x"}); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("unknown owner", err)
			}
			update := auth.ProfileUpdate{AdditionalFields: map[string]any{"accountClass": "forbidden", "locale": "discard"}}
			checkUserFieldError(t, c.UpdateUser(ctx, update), "FIELD_NOT_ALLOWED")
			for _, v := range []any{1.5, true, json.Number("1.000000000000000001"), int64(2147483648)} {
				patch := auth.ProfileUpdate{AdditionalFields: map[string]any{"score": v}}
				checkUserFieldError(t, api.UpdateUser(ctx, h, patch), "VALIDATION_ERROR")
			}
			if err := c.UpdateUser(ctx, auth.ProfileUpdate{AdditionalFields: map[string]any{"activeFlag": nil}}); err != nil {
				t.Fatal(err)
			}
			type op func() error
			ops := []op{func() error { return host.UpdateTrustedUserFields(ctx, id, map[string]any{"score": 23}) }, func() error {
				return api.UpdateUser(ctx, h, auth.ProfileUpdate{AdditionalFields: map[string]any{"locale": "fr"}})
			}}
			var wg sync.WaitGroup
			for _, f := range ops {
				wg.Go(func() {
					if e := f(); e != nil {
						t.Error(e)
					}
				})
			}
			wg.Wait()
			current, err := c.GetSession(ctx)
			if err != nil || current == nil {
				t.Fatal(current, err)
			}
			checkUserField(t, current.User, "locale", "fr")
			checkUserField(t, current.User, "score", int64(23))
			checkUserField(t, current.User, "accountClass", "host-owned")
			checkUserField(t, current.User, "activeFlag", nil)
			if current.User.Name != renamed {
				t.Fatal(current.User.Name)
			}
			raw, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"secretNote", "updated-secret", "privateRank", "preferred_locale"} {
				if strings.Contains(string(raw), text) {
					t.Fatal("private data in public session", text)
				}
			}
			if sql, ok := store.(*Store); ok {
				var secret string
				var rank int
				err := sql.db.QueryRowContext(ctx, sql.bind(`SELECT "secretNote","privateRank" FROM "user" WHERE "id"=?`), id).Scan(&secret, &rank)
				if err != nil || secret != "updated-secret" || rank != 0 {
					t.Fatal("physical values", secret, rank, err)
				}
			}
			if err := api.SignOut(ctx, h); err != nil {
				t.Fatal(err)
			}
			if err := host.UpdateUser(ctx, h, change); err == nil {
				t.Fatal("revoked owner updated profile")
			}
			login, err := c.SignInEmail(ctx, client.SignInRequest{Email: input.Email, Password: input.Password})
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, login.User, "accountClass", "host-owned")
		})
	}
}

func TestUserFieldSchemaAndLiveUpgrades(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			legacy, err := auth.New(auth.Options{Store: s, BaseURL: "http://test.localhost", Secret: strings.Repeat("s", 40), EmailAndPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			u, err := legacy.SignUpEmail(ctx, auth.SignUpInput{Name: "Old", Email: "old@profile.test", Password: "old profile test"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			const defaultLabel = "team's café; east\\west"
			defs := schema.AdditionalFields{User: map[string]auth.UserField{"label": {Type: auth.FieldString, Column: "dept_label", Required: true, Default: defaultLabel}, "nullable": {Type: auth.FieldBoolean}}, Session: map[string]auth.SessionField{"label": {Type: auth.FieldNumber, Column: "dept_label", Default: 4}}}
			findings, err := CheckSchemaWithAdditionalFields(ctx, dialect, dsn, nil, defs)
			if err != nil || len(findings) != 3 {
				t.Fatal("preflight findings", findings, err)
			}
			if ok, err := s.fieldColumnCatalog(ctx, s.db, "user"); err != nil || ok["dept_label"].name != "" {
				t.Fatal("read-only check mutated the schema", err)
			}
			bad := schema.AdditionalFields{User: defs.User, Session: map[string]auth.SessionField{"mustSupply": {Type: auth.FieldNumber, Required: true}}}
			if made, e := OpenWithAdditionalFields(ctx, dialect, dsn, nil, bad); e == nil {
				made.Close()
				t.Fatal("migrated required field without backfill")
			}
			if ok, err := s.fieldColumnCatalog(ctx, s.db, "user"); err != nil || ok["dept_label"].name != "" {
				t.Fatal("failed combined preflight wrote a column", err)
			}
			for range 2 {
				ready, e := OpenWithAdditionalFields(ctx, dialect, dsn, nil, defs)
				if e != nil {
					t.Fatal(e)
				}
				ready.Close()
			}
			findings, err = CheckSchemaWithAdditionalFields(ctx, dialect, dsn, nil, defs)
			if err != nil || len(findings) != 0 {
				t.Fatal(findings, err)
			}
			api, err := auth.New(auth.Options{Store: s, BaseURL: "http://test.localhost", UserAdditionalFields: defs.User, SessionAdditionalFields: defs.Session, Secret: strings.Repeat("s", 40)})
			if err != nil {
				t.Fatal(err)
			}
			session, err := api.GetSession(ctx, http.Header{"Cookie": {api.SessionCookie(u.Token, true).String()}})
			if err != nil || session == nil {
				t.Fatal(session, err)
			}
			checkUserField(t, session.User, "label", defaultLabel)
			if v, _ := session.Session.AdditionalField("label"); v != int64(4) {
				t.Fatal("independent model value", v)
			}
			defs.User["label"] = auth.UserField{Type: auth.FieldNumber, Column: "dept_label", Required: true}
			findings, err = CheckSchemaWithAdditionalFields(ctx, dialect, dsn, nil, defs)
			if err != nil || len(findings) != 1 || findings[0] != (SchemaFinding{Kind: "incompatible-column", Table: "user", Column: "dept_label"}) {
				t.Fatal("incompatible user column", findings, err)
			}
			for _, key := range []string{"email", "password", "ROLE", "twoFactorEnabled", "phoneNumber", "stripeCustomerId", "rememberMe", "token", "constructor"} {
				if _, err := schema.GenerateWithAdditionalFields(dialect, nil, schema.AdditionalFields{User: map[string]auth.UserField{"safe": {Type: auth.FieldString, Column: key}}}); err == nil {
					t.Fatal("reserved column", key)
				}
			}
		})
	}
}

func TestUserFieldProtectedSignupAndVerification(t *testing.T) {
	ctx := t.Context()
	fields := userFieldFixture()
	store, err := OpenWithAdditionalFields(ctx, "sqlite", organizationTestDSN(t, "sqlite"), nil, schema.AdditionalFields{User: fields})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var proof auth.MailLink
	a, err := auth.New(auth.Options{BaseURL: "http://profile.localhost", Store: store, UserAdditionalFields: fields, Secret: strings.Repeat("s", 40), EmailAndPassword: true, RequireEmailVerification: true, SendVerificationEmail: func(_ context.Context, m auth.MailLink) error { proof = m; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	in := auth.SignUpInput{Name: "Existing", Email: "existing@profile.test", Password: "existing profile", AdditionalFields: map[string]any{"locale": "private-original-locale", "secretNote": "hidden-input-unique"}}
	real, err := a.SignUpEmail(ctx, in, auth.RequestMeta{})
	if err != nil || proof.Token == "" || real.Token != "" {
		t.Fatal(err)
	}
	if err := a.UpdateTrustedUserFields(ctx, real.User.ID, map[string]any{"accountClass": "private-owner-class"}); err != nil {
		t.Fatal(err)
	}
	in.AdditionalFields["locale"] = "applicant"
	in.AdditionalFields["secretNote"] = "different-hidden-input"
	other, err := a.SignUpEmail(ctx, in, auth.RequestMeta{})
	if err != nil || other.User.ID == real.User.ID || other.Token != "" {
		t.Fatal(err)
	}
	checkUserField(t, other.User, "locale", "applicant")
	checkUserField(t, other.User, "accountClass", "basic")
	raw, err := json.Marshal(other)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"secretNote", "privateRank", "hidden-input", "private-owner-class", "private-original-locale"} {
		if strings.Contains(string(raw), value) {
			t.Fatal("synthetic signup exposed another profile or secret", value)
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(proof.Token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	mailUser, err := json.Marshal(proof.User)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://profile.localhost/api/auth/verify-email?"+url.Values{"token": {proof.Token}}.Encode(), nil)
	out := httptest.NewRecorder()
	a.ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatal(out.Code, out.Body.String())
	}
	for _, out := range []string{out.Body.String(), string(payload), string(mailUser)} {
		for _, private := range []string{"privateRank", "secretNote", "hidden-input-unique"} {
			if strings.Contains(out, private) {
				t.Fatal("verification exposed hidden field", private)
			}
		}
	}
}

// Run a second connection's committed change after Auth loaded the session and
// before the adapter enters the transaction that updates the profile.
type userFieldGate struct {
	*Store
	beforeUpdate func()
}

func (s *userFieldGate) UpdateUserFields(ctx context.Context, id string, actor *auth.Session, patch auth.ProfileUpdate, now time.Time) error {
	if s.beforeUpdate != nil {
		s.beforeUpdate()
	}
	return s.Store.UpdateUserFields(ctx, id, actor, patch, now)
}

func TestUserFieldWritesRecheckLiveAuthority(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			fields := map[string]auth.UserField{"label": {Type: auth.FieldString}}
			decl := schema.AdditionalFields{User: fields}
			s, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, decl)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			gate := &userFieldGate{Store: s}
			opts := auth.Options{BaseURL: "http://profile.localhost", Store: gate, UserAdditionalFields: fields, Secret: strings.Repeat("s", 40), EmailAndPassword: true}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			user, err := node.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: "live@profile.test", Password: "profile fixture", AdditionalFields: map[string]any{"label": "original"}}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			peer, err := OpenWithAdditionalFields(ctx, dialect, dsn, []string{"admin"}, decl)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			write := func(q string, args ...any) {
				t.Helper()
				if _, err := peer.db.ExecContext(ctx, peer.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			h := http.Header{"Cookie": {node.SessionCookie(user.Token, true).String()}}
			for _, mode := range []string{"delegated", "banned", "revoked"} {
				gate.beforeUpdate = func() {
					switch mode {
					case "delegated":
						write(`UPDATE "session" SET "impersonatedBy"=? WHERE "token"=?`, "other", user.Token)
					case "banned":
						write(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, user.User.ID)
					case "revoked":
						write(`DELETE FROM "session" WHERE "token"=?`, user.Token)
					}
				}
				if err := node.UpdateUser(ctx, h, auth.ProfileUpdate{AdditionalFields: map[string]any{"label": "unexpected"}}); err == nil {
					t.Fatalf("accepted %s owner write", mode)
				}
				val, err := s.ReadUserFields(ctx, user.User.ID, fields)
				if err != nil || val["label"] != "original" {
					t.Fatal(mode, val, err)
				}
				write(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "token"=?`, user.Token)
				write(`UPDATE "user" SET "banned"=? WHERE "id"=?`, false, user.User.ID)
			}
		})
	}
}
