package sqlstore

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/authtest"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestComputedFieldDefaultsAcrossStores(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var users, sessions atomic.Int64
			var badSession, badUser atomic.Bool
			fields := schema.AdditionalFields{User: map[string]auth.UserField{
				"ticket": {Type: auth.FieldNumber, Required: true, ServerOnly: true, Default: func() int64 { return users.Add(1) }},
				"color":  {Type: auth.FieldString, Default: func() string { return "blue" }},
				"stage": {Type: auth.FieldString, Required: true, Default: func() any {
					if badUser.Load() {
						return 12
					}
					return "new"
				}},
			}, Session: map[string]auth.SessionField{
				"serial": {Type: auth.FieldNumber, Required: true, ServerOnly: true, Default: func() any {
					if badSession.Load() {
						return "broken"
					}
					return sessions.Add(1)
				}},
			}}
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				db, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, fields)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				store = db
			}
			host, err := authtest.New(auth.Options{Store: store, BaseURL: "http://localhost", Secret: strings.Repeat("a", 40), EmailAndPassword: true, UserAdditionalFields: fields.User, SessionAdditionalFields: fields.Session})
			if err != nil {
				t.Fatal(err)
			}
			api := host.Auth
			if slices.Contains(api.DescribeHTTP().RequiredUserInputs, "stage") {
				t.Fatal("schema required clients to supply a computed default")
			}
			if sessions.Load() != 0 || users.Load() != 0 {
				t.Fatal("configuration invoked a creation default")
			}
			input := auth.SignUpInput{Name: "User", Email: "user@example.test", Password: "local credential", AdditionalFields: map[string]any{"ticket": 999, "color": nil}}
			account, err := api.SignUpEmail(ctx, input, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, account.User, "ticket", int64(1))
			checkUserField(t, account.User, "color", nil)
			headers := http.Header{"Cookie": {api.SessionCookie(account.Token, true).String()}}
			for range 2 {
				result, err := api.GetSession(ctx, headers)
				if err != nil {
					t.Fatal(err)
				}
				if serial, _ := result.Session.AdditionalField("serial"); serial != int64(1) {
					t.Fatalf("stored serial %v", serial)
				}
			}
			if err := api.UpdateTrustedUserFields(ctx, account.User.ID, map[string]any{"color": "green"}); err != nil {
				t.Fatal(err)
			}
			if _, err := host.LoginWithOptions(ctx, authtest.LoginOptions{UserID: account.User.ID, Fields: map[string]any{"serial": 100}}); err != nil {
				t.Fatal(err)
			}
			if _, err := host.Login(ctx, account.User.ID); err != nil {
				t.Fatal(err)
			}
			if users.Load() != 1 || sessions.Load() != 2 {
				t.Fatalf("callbacks after fixture issuance: users %d, sessions %d", users.Load(), sessions.Load())
			}
			badSession.Store(true)
			input.Email = "failed@example.test"
			input.AdditionalFields = nil
			if _, err := api.SignUpEmail(ctx, input, auth.RequestMeta{}); err == nil {
				t.Fatal("accepted invalid session default")
			}
			if _, _, err := store.Credential(ctx, input.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("partial credential on failed issuance: %v", err)
			}
			badSession.Store(false)
			other, err := api.SignUpEmail(ctx, input, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, other.User, "color", "blue")
			checkUserField(t, other.User, "ticket", int64(3))
			badUser.Store(true)
			input.Email = "baduser@example.test"
			if _, err := api.SignUpEmail(ctx, input, auth.RequestMeta{}); err == nil {
				t.Fatal("accepted invalid profile default")
			}
			if _, _, err := store.Credential(ctx, input.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("partial profile on invalid default: %v", err)
			}

		})
	}
}

func TestComputedDefaultsDuringMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			base, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			opts := auth.Options{Store: base, BaseURL: "http://localhost", Secret: strings.Repeat("s", 40), EmailAndPassword: true}
			api, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			account, err := api.SignUpEmail(ctx, auth.SignUpInput{Name: "Initial", Email: "initial@example.test", Password: "local test password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int64
			callback := func() int64 { return calls.Add(1) }
			decl := schema.AdditionalFields{User: map[string]auth.UserField{"sequence": {Type: auth.FieldNumber, Default: callback}}, Session: map[string]auth.SessionField{"sequence": {Type: auth.FieldNumber, Required: true, Default: callback}}}
			if bad, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, decl); err == nil {
				bad.Close()
				t.Fatal("required computed field backfilled a populated table")
			}
			cols, err := base.fieldColumnCatalog(ctx, base.db, "user")
			if err != nil || cols["sequence"].name != "" {
				t.Fatal("preflight changed the existing user schema", err)
			}
			decl.Session["sequence"] = auth.SessionField{Type: auth.FieldNumber, Default: callback}
			migrated, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, decl)
			if err != nil {
				t.Fatal(err)
			}
			defer migrated.Close()
			opts.Store, opts.UserAdditionalFields, opts.SessionAdditionalFields = migrated, decl.User, decl.Session
			after, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			current, err := after.GetSession(ctx, http.Header{"Cookie": {api.SessionCookie(account.Token, true).String()}})
			if err != nil || current == nil {
				t.Fatal(err)
			}
			checkUserField(t, current.User, "sequence", nil)
			if v, present := current.Session.AdditionalField("sequence"); !present || v != nil {
				t.Fatal("existing session received a newly evaluated default")
			}
			if calls.Load() != 0 {
				t.Fatal("migration or read invoked a creation callback")
			}
		})
	}
}
