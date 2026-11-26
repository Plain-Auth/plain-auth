package sqlstore

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

func keyErrorCode(err error) string {
	var api *plainauth.APIError
	if errors.As(err, &api) {
		return api.Code
	}
	return ""
}

// NewPlugin refuses no configurations, a nil one, and two that share a
// ConfigID, two unnamed ones included, since an empty ConfigID is "default".
func TestAPIKeyPluginRefusesInvalidConfigurationSets(t *testing.T) {
	ctx := t.Context()
	ddl, err := schema.Generate("sqlite", []string{"api-key"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := func(config string) *ak.Service {
		s, err := ak.New(ak.Options{Store: store, ConfigID: config})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	one, again, teams, teamsAgain := service(""), service(""), service("teams"), service("teams")
	if _, err := ak.NewPlugin(); err == nil {
		t.Fatal("a plugin without configurations was built")
	}
	if _, err := ak.NewPlugin(one, nil); err == nil {
		t.Fatal("a nil configuration was accepted")
	}
	if _, err := ak.NewPlugin(one, again); err == nil {
		t.Fatal("two default configurations were accepted")
	}
	if _, err := ak.NewPlugin(teams, one, teamsAgain); err == nil {
		t.Fatal("two configurations sharing a ConfigID were accepted")
	}
	if _, err := ak.NewPlugin(one, teams); err != nil {
		t.Fatal("an unnamed configuration next to a named one was refused", err)
	}
}

// Keys default to 64 random letters showing their first six, ten uses a day
// and no expiry. The key length, display, prefix, expiration and rate
// options each change that, and New refuses settings outside its bounds.
func TestAPIKeyGenerationDefaults(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			user := testUser("defaults-owner")
			must(store.CreateUser(ctx, user, "", nil))
			service := func(o ak.Options) *ak.Service {
				t.Helper()
				o.Store = store
				s, err := ak.New(o)
				must(err)
				return s
			}
			for _, o := range []ak.Options{{KeyLength: 31}, {KeyLength: 40, StartLength: 17}, {DefaultPrefix: "bad prefix"}, {DefaultPrefix: strings.Repeat("p", 33)}} {
				o.Store = store
				if _, err := ak.New(o); err == nil {
					t.Fatalf("New accepted %+v", o)
				}
			}

			plain := service(ak.Options{})
			k, err := plain.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			if !regexp.MustCompile(`^[A-Za-z]{64}$`).MatchString(k.Secret) || k.Prefix != nil || k.Start == nil || *k.Start != k.Secret[:6] {
				t.Fatal("default key was not 64 random letters with a six-character start", k.Secret, k.Start)
			}
			if !k.RateLimitEnabled || k.RateLimitMax == nil || *k.RateLimitMax != 10 || k.RateLimitTimeWindow == nil || *k.RateLimitTimeWindow != 86_400_000 || k.ExpiresAt != nil || k.Remaining != nil {
				t.Fatal("default policy differs from ten uses a day without expiry", k.Key)
			}
			for i := range 10 {
				if v, err := plain.Verify(ctx, k.Secret, nil); err != nil || !v.Valid {
					t.Fatalf("request %d of ten was refused: %v %+v", i+1, err, v.Error)
				}
			}
			v, err := plain.Verify(ctx, k.Secret, nil)
			must(err)
			if v.Valid || v.Error.Code != "RATE_LIMITED" || v.Error.Details == nil || v.Error.Details.TryAgainIn <= 0 || v.Error.Details.TryAgainIn > 86_400_000 {
				t.Fatal("default rate limit was not ten per day", v.Error)
			}
			open := service(ak.Options{ConfigID: "open", DisableRateLimit: true, RateMax: 1})
			o, err := open.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			for range 3 {
				if v, err := open.Verify(ctx, o.Secret, nil); err != nil || !v.Valid || o.RateLimitEnabled {
					t.Fatal("disabled rate limiting still refused a key", err, v.Error)
				}
			}

			shaped := service(ak.Options{ConfigID: "shaped", KeyLength: 40, DefaultPrefix: "dflt_", StartLength: 10})
			s1, err := shaped.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			if !regexp.MustCompile(`^dflt_[A-Za-z]{40}$`).MatchString(s1.Secret) {
				t.Fatal("built-in generator ignored the configured length", s1.Secret)
			}
			if s1.Prefix == nil || *s1.Prefix != "dflt_" || s1.Start == nil || *s1.Start != s1.Secret[:10] {
				t.Fatal("built-in key did not carry the default prefix and configured start", s1.Prefix, s1.Start)
			}
			s2, err := shaped.Create(ctx, user.ID, ak.CreateInput{Prefix: "own_"})
			must(err)
			if !regexp.MustCompile(`^own_[A-Za-z]{40}$`).MatchString(s2.Secret) || s2.Prefix == nil || *s2.Prefix != "own_" {
				t.Fatal("a request prefix did not replace the default prefix", s2.Secret)
			}
			hidden := service(ak.Options{ConfigID: "hidden", HideStart: true})
			h, err := hidden.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			got, err := hidden.Get(ctx, user.ID, h.ID)
			must(err)
			var start sql.NullString
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "start" FROM "apikey" WHERE "id"=?`), h.ID).Scan(&start))
			if h.Start != nil || got.Start != nil || start.Valid {
				t.Fatal("hidden start was stored")
			}

			for expires, code := range map[time.Duration]string{23 * time.Hour: "EXPIRES_IN_IS_TOO_SMALL", 24 * time.Hour: "", 365 * 24 * time.Hour: "", 365*24*time.Hour + time.Second: "EXPIRES_IN_IS_TOO_LARGE"} {
				k, err := plain.Create(ctx, user.ID, ak.CreateInput{ExpiresIn: expires})
				if keyErrorCode(err) != code || code == "" && (err != nil || k.ExpiresAt == nil || k.ExpiresAt.Sub(k.CreatedAt).Round(time.Second) != expires) {
					t.Fatal("default expiration bounds were not enforced", expires, err)
				}
			}
			fixed := service(ak.Options{ConfigID: "fixed", DisableCustomExpiration: true, DefaultExpiration: 2 * time.Hour})
			if _, err := fixed.Create(ctx, user.ID, ak.CreateInput{ExpiresIn: 48 * time.Hour}); keyErrorCode(err) != "KEY_DISABLED_EXPIRATION" {
				t.Fatal("custom expiration was accepted while disabled", err)
			}
			f, err := fixed.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			zero := time.Duration(0)
			if _, err := fixed.Update(ctx, user.ID, f.ID, ak.UpdateInput{ExpiresIn: &zero}); f.ExpiresAt == nil || f.ExpiresAt.Sub(f.CreatedAt).Round(time.Second) != 2*time.Hour || keyErrorCode(err) != "KEY_DISABLED_EXPIRATION" {
				t.Fatal("custom expiration was accepted while disabled, or the default lifetime was not used", f.ExpiresAt, err)
			}
		})
	}
}

// Names and prefixes keep to their default and configured lengths, names
// counted in UTF-16 units, on create and update.
func TestAPIKeyNameAndPrefixLimits(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			base, err := ak.New(ak.Options{Store: store})
			must(err)
			limits, err := ak.New(ak.Options{Store: store, ConfigID: "limits", MinPrefixLength: 3, MaxPrefixLength: 5, MinNameLength: 3, MaxNameLength: 8})
			must(err)
			plugin, err := ak.NewPlugin(base, limits)
			must(err)
			const origin = "https://limits.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("n", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			account, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Limits", Email: "limits@example.test", Password: "limits-password"})
			must(err)
			create := func(r client.CreateAPIKeyRequest) (*ak.Created, string) {
				t.Helper()
				k, err := member.CreateAPIKey(ctx, r)
				if code := keyErrorCode(err); code != "" {
					return nil, code
				}
				must(err)
				return k, ""
			}

			long, code := create(client.CreateAPIKeyRequest{Prefix: strings.Repeat("p", 32)})
			if _, refused := create(client.CreateAPIKeyRequest{Prefix: strings.Repeat("p", 33)}); code != "" || !strings.HasPrefix(long.Secret, strings.Repeat("p", 32)) || len(long.Secret) != 96 || refused != "INVALID_PREFIX_LENGTH" {
				t.Fatal("default maximum prefix length was not enforced", code, refused)
			}
			for prefix, want := range map[string]string{"ab": "INVALID_PREFIX_LENGTH", "abc": "", "abcde": "", "abcdef": "INVALID_PREFIX_LENGTH"} {
				k, code := create(client.CreateAPIKeyRequest{ConfigID: "limits", Prefix: prefix})
				if code != want || want == "" && (!strings.HasPrefix(k.Secret, prefix) || k.Prefix == nil || *k.Prefix != prefix) {
					t.Fatalf("configured prefix lengths were not enforced for %q: %s", prefix, code)
				}
			}
			if _, err := limits.Create(ctx, account.User.ID, ak.CreateInput{Prefix: "ab"}); keyErrorCode(err) != "INVALID_PREFIX_LENGTH" {
				t.Fatal("server code created a key with a prefix under the configured minimum", err)
			}

			for name, want := range map[string]string{strings.Repeat("n", 32): "", strings.Repeat("n", 33): "INVALID_NAME_LENGTH", strings.Repeat("😀", 16): "", strings.Repeat("😀", 17): "INVALID_NAME_LENGTH"} {
				k, code := create(client.CreateAPIKeyRequest{Name: name})
				if code != want || want == "" && (k.Name == nil || *k.Name != name) {
					t.Fatalf("default maximum name length was not enforced for %d bytes: %s", len(name), code)
				}
			}
			for name, want := range map[string]string{"ab": "INVALID_NAME_LENGTH", "abcdefghi": "INVALID_NAME_LENGTH", "abcdefgh": ""} {
				if _, code := create(client.CreateAPIKeyRequest{ConfigID: "limits", Name: name}); code != want {
					t.Fatalf("configured name lengths were not enforced for %q: %s", name, code)
				}
			}
			unnamed, code := create(client.CreateAPIKeyRequest{ConfigID: "limits"})
			if code != "" || unnamed.Name != nil {
				t.Fatal("a key created without a name got one", code)
			}
			short, code := create(client.CreateAPIKeyRequest{ConfigID: "limits", Name: "abc"})
			if code != "" {
				t.Fatal("configured minimum name length was not enforced", code)
			}
			for _, name := range []string{"ab", "", "abcdefghi"} {
				_, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{ConfigID: "limits", KeyID: short.ID, Name: &name})
				if keyErrorCode(err) != "INVALID_NAME_LENGTH" {
					t.Fatalf("an update to name %q was not refused: %v", name, err)
				}
			}
			if got, err := member.GetAPIKey(ctx, short.ID, "limits"); err != nil || got.Name == nil || *got.Name != "abc" {
				t.Fatal("an update outside the name limits changed the name", err)
			}
		})
	}
}

// Keys are stored only as their digest: a row holding the plain secret, as
// a store with hashing turned off writes it, matches no lookup.
func TestAPIKeyPlainTextRowsAreRefused(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			keys, err := ak.New(ak.Options{Store: store, EnableSession: true})
			must(err)
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: "https://plain.example", Secret: strings.Repeat("q", 32), Plugins: []plainauth.Plugin{keys.Plugin()}})
			must(err)
			user := testUser("plain-owner")
			must(store.CreateUser(ctx, user, "", nil))
			k, err := keys.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			stored := func(value string) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "key"=? WHERE "id"=?`), value, k.ID)
				must(err)
			}
			stored(k.Secret)
			v, err := keys.Verify(ctx, k.Secret, nil)
			must(err)
			r := httptest.NewRequest("GET", "https://plain.example/api/auth/get-session", nil)
			r.Header.Set("X-Api-Key", k.Secret)
			w := httptest.NewRecorder()
			host.ServeHTTP(w, r)
			var count int64
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "requestCount" FROM "apikey" WHERE "id"=?`), k.ID).Scan(&count))
			if v.Valid || v.Error.Code != "INVALID_API_KEY" || w.Code != 401 || !strings.Contains(w.Body.String(), "INVALID_API_KEY") || count != 0 {
				t.Fatal("a key stored in plain text was accepted", v.Error, w.Code, count)
			}
			stored(ak.Digest(k.Secret))
			if v, err := keys.Verify(ctx, k.Secret, nil); err != nil || !v.Valid {
				t.Fatal("the restored digest did not verify", err, v.Error)
			}
		})
	}
}

// Rate limiting turns off for a whole configuration or for one key, which
// still records its last request, and comes back on from the kept count.
// An API-key session past its maximum answers 429 RATE_LIMITED.
func TestAPIKeyRateLimitSwitches(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			defaults, err := ak.New(ak.Options{Store: store, EnableSession: true})
			must(err)
			open, err := ak.New(ak.Options{Store: store, ConfigID: "open", DisableRateLimit: true, RateMax: 1})
			must(err)
			capped, err := ak.New(ak.Options{Store: store, ConfigID: "capped", RateMax: 2, RateWindow: time.Hour})
			must(err)
			plugin, err := ak.NewPlugin(defaults, open, capped)
			must(err)
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: "https://rates.example", Secret: strings.Repeat("r", 32), Plugins: []plainauth.Plugin{plugin}})
			must(err)
			user := testUser("rates-owner")
			must(store.CreateUser(ctx, user, "", nil))
			on, off, one, two := true, false, int64(1), int64(2)
			verify := func(s *ak.Service, secret string) *ak.VerifyError {
				t.Helper()
				v, err := s.Verify(ctx, secret, nil)
				must(err)
				return v.Error
			}

			burst, err := defaults.Create(ctx, user.ID, ak.CreateInput{Policy: ak.Policy{RateLimitMax: &two}})
			must(err)
			session := func() *httptest.ResponseRecorder {
				r := httptest.NewRequest("GET", "https://rates.example/api/auth/get-session", nil)
				r.Header.Set("X-Api-Key", burst.Secret)
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w
			}
			first, second, third := session(), session(), session()
			if first.Code != 200 || second.Code != 200 || third.Code != 429 || !strings.Contains(third.Body.String(), `"code":"RATE_LIMITED"`) {
				t.Fatal("an API-key session past its rate maximum was not answered 429 RATE_LIMITED", first.Code, second.Code, third.Code, third.Body)
			}

			plain, err := open.Create(ctx, user.ID, ak.CreateInput{})
			must(err)
			if plain.RateLimitEnabled || plain.RateLimitMax == nil || *plain.RateLimitMax != 1 || plain.RateLimitTimeWindow == nil || *plain.RateLimitTimeWindow != 86_400_000 {
				t.Fatal("a configuration with rate limiting off did not store its policy with the limit off", plain.Key)
			}
			forced, err := open.Create(ctx, user.ID, ak.CreateInput{Policy: ak.Policy{RateLimitEnabled: &on, RateLimitMax: &one}})
			must(err)
			mark := time.Now().Add(-time.Second)
			for range 12 {
				if e := verify(open, forced.Secret); e != nil {
					t.Fatal("disabled rate limiting still limited a key", e)
				}
			}
			if got, err := open.Get(ctx, user.ID, forced.ID); err != nil || got.RequestCount != 0 || got.LastRequest == nil || got.LastRequest.Before(mark) {
				t.Fatal("disabled rate limiting still limited a key or stopped recording its last request", err)
			}

			exempt, err := capped.Create(ctx, user.ID, ak.CreateInput{Policy: ak.Policy{RateLimitEnabled: &off}})
			must(err)
			for range 4 {
				if e := verify(capped, exempt.Secret); e != nil {
					t.Fatal("a key with its own rate limit off was limited", e)
				}
			}
			if got, err := capped.Get(ctx, user.ID, exempt.ID); err != nil || got.RequestCount != 0 || got.LastRequest == nil || got.LastRequest.Before(mark) {
				t.Fatal("a key with its own rate limit off was limited or its last request was not recorded", err)
			}
			_, err = capped.Update(ctx, user.ID, exempt.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitEnabled: &on}})
			must(err)
			if a, b, c := verify(capped, exempt.Secret), verify(capped, exempt.Secret), verify(capped, exempt.Secret); a != nil || b != nil || c == nil || c.Code != "RATE_LIMITED" {
				t.Fatal("turning a key's rate limit back on did not limit it again", a, b, c)
			}
			_, err = capped.Update(ctx, user.ID, exempt.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitEnabled: &off}})
			must(err)
			if e := verify(capped, exempt.Secret); e != nil {
				t.Fatal("turning a key's rate limit off again did not lift the limit", e)
			}
		})
	}
}

// Configurations mounted together keep their own prefix, display, rate
// policy, default permissions and metadata switch.
func TestAPIKeyConfigurations(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			base, err := ak.New(ak.Options{Store: store})
			must(err)
			public, err := ak.New(ak.Options{Store: store, ConfigID: "public", KeyLength: 40, DefaultPrefix: "pk_", StartLength: 10, RateMax: 2, RateWindow: time.Hour})
			must(err)
			secret, err := ak.New(ak.Options{Store: store, ConfigID: "secret", DefaultPrefix: "sk_", HideStart: true, EnableMetadata: true, RateMax: 3, RateWindow: time.Hour, DefaultPermissions: ak.Permissions{"files": {"write"}}})
			must(err)
			plugin, err := ak.NewPlugin(base, public, secret)
			must(err)
			const origin = "https://configs.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("c", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			_, err = member.SignUpEmail(ctx, client.SignUpRequest{Name: "Configs", Email: "configs@example.test", Password: "configs-password"})
			must(err)
			plain, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{})
			must(err)
			pub, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "public"})
			must(err)
			sec, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "secret", Metadata: map[string]any{"plan": "premium"}})
			must(err)
			if len(plain.Secret) != 64 || !strings.HasPrefix(pub.Secret, "pk_") || len(pub.Secret) != 43 || *pub.Start != pub.Secret[:10] || !strings.HasPrefix(sec.Secret, "sk_") || len(sec.Secret) != 67 || sec.Start != nil {
				t.Fatal("a configuration's key shape was not applied to its keys only", pub.Start, sec.Start)
			}
			if len(sec.Permissions["files"]) != 1 || sec.Permissions["files"][0] != "write" || pub.Permissions != nil || plain.Permissions != nil {
				t.Fatal("configured default permissions were not applied to their configuration only", sec.Permissions, pub.Permissions)
			}
			_, err = member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{ConfigID: "public", Metadata: map[string]any{"plan": "free"}})
			if sec.Metadata["plan"] != "premium" || keyErrorCode(err) != "METADATA_DISABLED" {
				t.Fatal("metadata was not limited to the configuration that enables it", sec.Metadata, err)
			}
			if *pub.RateLimitMax != 2 || *pub.RateLimitTimeWindow != 3_600_000 || *sec.RateLimitMax != 3 || *plain.RateLimitMax != 10 {
				t.Fatal("a configuration's rate policy was not stored on its keys")
			}
			for _, c := range []struct {
				service *ak.Service
				key     string
				max     int
			}{{public, pub.Secret, 2}, {secret, sec.Secret, 3}} {
				for i := range c.max {
					if v, err := c.service.Verify(ctx, c.key, nil); err != nil || !v.Valid {
						t.Fatalf("request %d within a configuration's rate maximum was refused: %v", i+1, err)
					}
				}
				if v, err := c.service.Verify(ctx, c.key, nil); err != nil || v.Valid || v.Error.Code != "RATE_LIMITED" {
					t.Fatal("a configuration's own rate maximum was not enforced", c.max, err)
				}
			}
			// Past the configured hour, though within the default day, the
			// window resets.
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "lastRequest"=? WHERE "id"=?`), store.date(time.Now().Add(-2*time.Hour)), pub.ID)
			must(err)
			if v, err := public.Verify(ctx, pub.Secret, nil); err != nil || !v.Valid {
				t.Fatal("a configuration's rate window did not reset after its own length", err, v.Error)
			}

			bounded, err := ak.New(ak.Options{Store: store, ConfigID: "bounded", MinExpiration: time.Hour, MaxExpiration: 48 * time.Hour})
			must(err)
			owner := pub.ReferenceID
			for expires, code := range map[time.Duration]string{59 * time.Minute: "EXPIRES_IN_IS_TOO_SMALL", time.Hour: "", 48 * time.Hour: "", 49 * time.Hour: "EXPIRES_IN_IS_TOO_LARGE"} {
				k, err := bounded.Create(ctx, owner, ak.CreateInput{ExpiresIn: expires})
				if keyErrorCode(err) != code || code == "" && (err != nil || k.ExpiresAt.Sub(k.CreatedAt).Round(time.Second) != expires) {
					t.Fatal("configured expiration bounds were not enforced", expires, err)
				}
			}
		})
	}
}
