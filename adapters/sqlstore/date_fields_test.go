package sqlstore

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestDateFieldsAcrossStores(t *testing.T) {
	const initial = "2026-02-15T11:02:03.123Z"
	const changed = "2025-01-02T00:00:00.000Z"
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			decl := schema.AdditionalFields{
				User:    map[string]auth.UserField{"reviewedAt": {Column: "review_at", Type: auth.FieldDate}},
				Session: map[string]auth.SessionField{"issuedOn": {Type: auth.FieldDate, Required: true, Default: "2026-02-15T12:02:03.123456+01:00"}},
			}
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				dsn := organizationTestDSN(t, dialect)
				sqlStore, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, decl)
				if err != nil {
					t.Fatal(err)
				}
				defer sqlStore.Close()
				findings, err := CheckSchemaWithAdditionalFields(ctx, dialect, dsn, nil, decl)
				if err != nil || len(findings) > 0 {
					t.Fatalf("date schema: %v %v", findings, err)
				}
				store = sqlStore
			}
			server := httptest.NewUnstartedServer(nil)
			defer server.Close()
			baseURL := "http://" + server.Listener.Addr().String()
			instance, err := auth.New(auth.Options{Store: store, BaseURL: baseURL, Secret: strings.Repeat("s", 40), EmailAndPassword: true, UserAdditionalFields: decl.User, SessionAdditionalFields: decl.Session})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = instance
			server.Start()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(baseURL, &http.Client{Jar: jar})
			if err != nil {
				t.Fatal(err)
			}
			registered, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Reader", Email: "reader@example.test", Password: "a local fixture secret", AdditionalFields: map[string]any{"reviewedAt": "2026-02-15T06:02:03.123999-05:00"}})
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, registered.User, "reviewedAt", initial)
			session, err := c.GetSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := session.Session.AdditionalField("issuedOn"); !ok || got != initial {
				t.Errorf("session default %v", got)
			}
			date := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
			if err := instance.UpdateTrustedUserFields(ctx, registered.User.ID, map[string]any{"reviewedAt": date}); err != nil {
				t.Fatal(err)
			}
			updated, err := c.UpdateSession(ctx, map[string]any{"issuedOn": date})
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := updated.AdditionalField("issuedOn"); got != changed {
				t.Fatalf("updated session date %v", got)
			}
			err = c.UpdateUser(ctx, auth.ProfileUpdate{AdditionalFields: map[string]any{"reviewedAt": "invalid"}})
			checkUserFieldError(t, err, "VALIDATION_ERROR")
			session, err = c.GetSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, session.User, "reviewedAt", changed)
			if err := c.UpdateUser(ctx, auth.ProfileUpdate{AdditionalFields: map[string]any{"reviewedAt": nil}}); err != nil {
				t.Fatal(err)
			}
			session, err = c.GetSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, session.User, "reviewedAt", nil)
		})
	}
}

func TestDateFieldMigrationAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			base, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer base.Close()
			before, err := auth.New(auth.Options{Store: base, BaseURL: "http://localhost", Secret: strings.Repeat("s", 40), EmailAndPassword: true})
			if err != nil {
				t.Fatal(err)
			}
			registered, err := before.SignUpEmail(ctx, auth.SignUpInput{Name: "Row", Email: "row@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			const declaration = `{"deadline":{"type":"date","required":true,"column":"mapped_deadline","default":"2025-08-02T06:01:02.709-04:00"}}`
			user, err := schema.ReadUserFields(strings.NewReader(declaration))
			if err != nil {
				t.Fatal(err)
			}
			session, err := schema.ReadSessionFields(strings.NewReader(declaration))
			if err != nil {
				t.Fatal(err)
			}
			fields := schema.AdditionalFields{User: user, Session: session}
			for range 2 {
				migrated, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, fields)
				if err != nil {
					t.Fatal(err)
				}
				if err := migrated.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for table, key := range map[string]string{"user": "id", "session": "userId"} {
				var saved time.Time
				query := base.bind(`SELECT "mapped_deadline" FROM "` + table + `" WHERE "` + key + `"=?`)
				if err := base.db.QueryRowContext(ctx, query, registered.User.ID).Scan(&saved); err != nil {
					t.Fatal(err)
				}
				if got := saved.UTC().Format(time.RFC3339Nano); got != "2025-08-02T10:01:02.709Z" {
					t.Fatalf("migrated %s: %s", table, got)
				}
			}
			if dialect != "sqlite" {
				kind := "timestamptz(0)"
				if dialect == "mysql" {
					kind = "timestamp(0) NULL"
				}
				if _, err := base.db.ExecContext(ctx, base.bind(`ALTER TABLE "user" ADD COLUMN "low_precision" `)+kind); err != nil {
					t.Fatal(err)
				}
				err := base.ValidateUserFields(map[string]auth.UserField{"review": {Type: auth.FieldDate, Column: "low_precision"}})
				if err == nil {
					t.Fatal("validated a timestamp column that drops milliseconds")
				}
			}
		})
	}
}
