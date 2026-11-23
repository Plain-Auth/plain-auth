package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAPIKeyLedgerMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate(dialect, []string{"api-key"})
			must(e)
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, e := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(e)
				t.Cleanup(func() { s.Close() })
				return s
			}
			a, b := open(), open()
			host, e := plainauth.New(plainauth.Options{BaseURL: "https://issuer.example", Store: a, EmailAndPassword: true, Secret: strings.Repeat("z", 32)})
			must(e)
			user, e := host.SignUpEmail(ctx, plainauth.SignUpInput{Name: "Owner", Email: "owner@example.test", Password: "a secure account password"}, plainauth.RequestMeta{})
			must(e)
			insertOld := func(id, digest string) {
				t.Helper()
				now := time.Now().UTC()
				key := ak.Key{ID: id, ReferenceID: user.User.ID, ConfigID: "default", Enabled: true, CreatedAt: now, UpdatedAt: now}
				values, e := a.keyValues(key)
				must(e)
				values = append(values, digest)
				q := `INSERT INTO "apikey" (` + apiKeyFields + `,"key") VALUES (` + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + `)`
				_, e = a.db.ExecContext(ctx, a.bind(q), values...)
				must(e)
			}
			old := strings.Repeat("old-credential-", 4)
			first := ak.Digest(old)
			caseVariant := strings.ToLower(first)
			if first == caseVariant {
				t.Fatal("fixture must distinguish binary digests")
			}
			insertOld("legacy-one", first)
			insertOld("legacy-two", first)
			insertOld("legacy-case", caseVariant)
			// Cover more than one backfill page, including equivalent imported rows.
			for i := 0; i < 256; i++ {
				insertOld(fmt.Sprintf("history-%03d", i), first)
			}
			importedPlain := "historical-noncanonical-credential"
			insertOld("plaintext-legacy", importedPlain)
			exists, e := a.hasKeyOwnerTable(ctx, a.db, "plainauth_api_key_digest")
			must(e)
			if exists {
				t.Fatal("canonical schema unexpectedly installed the extension")
			}
			must(a.CheckAPIKeySchema(ctx))
			e = a.WithAPIKey(ctx, ak.Owner{}, ak.Lookup{ConfigID: "default", Digest: first}, time.Now(), func(*ak.Key) (ak.Mutation, error) { t.Fatal("ambiguous imported digest accepted"); return ak.Read, nil })
			if !errors.Is(e, ak.ErrMissing) {
				t.Fatal("legacy read unexpectedly depended on ledger", e)
			}
			done := make(chan error, 2)
			for _, store := range []*Store{a, b} {
				go func() { done <- store.PrepareAPIKeyLedger(ctx) }()
			}
			must(<-done)
			must(<-done)
			count := func(table string) int {
				t.Helper()
				var n int
				q := `SELECT COUNT(*) FROM "` + table + `"`
				if table == "plainauth_api_key_digest" {
					q += ` WHERE length("digest")=32`
				}
				must(a.db.QueryRowContext(ctx, a.bind(q)).Scan(&n))
				return n
			}
			if count("apikey") != 260 || count("plainauth_api_key_digest") != 3 {
				t.Fatal("backfill merged distinct digests or changed historical key rows")
			}
			later := strings.Repeat("late-old-writer-", 3)
			insertOld("legacy-late", ak.Digest(later))
			_, e = ak.New(ak.Options{Store: open()})
			must(e)
			if count("plainauth_api_key_digest") != 3 {
				t.Fatal("ordinary startup unexpectedly repeated a completed historical scan")
			}
			must(b.PrepareAPIKeyLedger(ctx))
			var leaked bool
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT EXISTS(SELECT 1 FROM "plainauth_api_key_digest" WHERE "digest"=?)`), []byte(importedPlain)).Scan(&leaked))
			if leaked {
				t.Fatal("permanent ledger copied recoverable imported material")
			}
			if count("plainauth_api_key_digest") != 4 {
				t.Fatal("repeated backfill missed a live legacy digest")
			}
			// A crash can leave committed pages but no completion marker on MySQL.
			_, e = a.db.ExecContext(ctx, a.bind(`DELETE FROM "plainauth_api_key_digest" WHERE "digest" IN (?,?)`), []byte{1}, apiKeyFingerprint(ak.Digest(later)))
			must(e)
			_, e = ak.New(ak.Options{Store: open()})
			must(e)
			if count("plainauth_api_key_digest") != 4 {
				t.Fatal("startup did not recover an incomplete backfill")
			}
			// Model a revoked historical key and a complete verification-cache purge.
			for _, table := range []string{"apikey", "verification"} {
				_, e = a.db.ExecContext(ctx, a.bind(`DELETE FROM "`+table+`"`))
				must(e)
			}
			restarted := open()
			for _, spent := range []string{old, later} {
				service, e := ak.New(ak.Options{Store: restarted, KeyLength: 32, GenerateKey: func(context.Context, ak.Generation) (string, error) { return spent, nil }})
				must(e)
				if result, e := service.Create(ctx, user.User.ID, ak.CreateInput{}); result != nil || !errors.Is(e, ak.ErrKeyCollision) {
					t.Fatal("revoked key was reissued after verification cleanup and restart", e)
				}
			}
			if count("plainauth_api_key_digest") != 4 || count("apikey") != 0 {
				t.Fatal("failed issuance changed ledger or active keys")
			}
			_, e = a.db.ExecContext(ctx, a.bind(`DROP TABLE "plainauth_api_key_digest"`))
			must(e)
			_, e = a.db.ExecContext(ctx, a.bind(`CREATE TABLE "plainauth_api_key_digest" ("digest" varchar(64))`))
			must(e)
			if e := open().PrepareAPIKeyLedger(ctx); e == nil {
				t.Fatal("ledger without a binary primary key passed validation")
			}
		})
	}
}
