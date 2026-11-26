package sqlstore

import (
	"context"
	"sync/atomic"
	"testing"

	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

// VerifyAny verifies a key with the configuration that issued it, under
// that configuration's validator, permissions and rate limit.
func TestAPIKeyUnscopedVerification(t *testing.T) {
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
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			owner := testUser("unscoped-owner")
			must(store.CreateUser(ctx, owner, "", nil))
			var personalChecks, automationChecks atomic.Int32
			personal, err := ak.New(ak.Options{Store: store, ValidateKey: func(context.Context, string) (bool, error) { personalChecks.Add(1); return true, nil }})
			must(err)
			automation, err := ak.New(ak.Options{Store: store, ConfigID: "automation", RateMax: 1, DefaultPermissions: ak.Permissions{"build": {"run"}}, ValidateKey: func(context.Context, string) (bool, error) { automationChecks.Add(1); return true, nil }})
			must(err)
			job, err := automation.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			own, err := personal.Create(ctx, owner.ID, ak.CreateInput{})
			must(err)
			r, err := ak.VerifyAny(ctx, job.Secret, ak.Permissions{"build": {"run"}}, personal, automation)
			must(err)
			if !r.Valid || r.Key.ID != job.ID || r.Key.ConfigID != "automation" || automationChecks.Load() != 1 || personalChecks.Load() != 0 {
				t.Fatal("an unscoped verification did not use the issuing configuration")
			}
			if r, err := ak.VerifyAny(ctx, job.Secret, nil, personal, automation); err != nil || r.Valid || r.Error.Code != "RATE_LIMITED" {
				t.Fatal("an unscoped verification did not apply the issuing configuration's rate limit", err)
			}
			if r, err := ak.VerifyAny(ctx, own.Secret, ak.Permissions{"build": {"run"}}, personal, automation); err != nil || r.Valid || r.Error.Code != "KEY_NOT_FOUND" {
				t.Fatal("an unscoped verification granted another configuration's permissions", err)
			}
			if r, err := ak.VerifyAny(ctx, own.Secret, nil, personal, automation); err != nil || !r.Valid || r.Key.ConfigID != "default" || personalChecks.Load() != 2 || automationChecks.Load() != 2 {
				t.Fatal("an unscoped verification ran another configuration's validator", err)
			}
			if r, err := personal.Verify(ctx, job.Secret, nil); err != nil || r.Valid || r.Error.Code != "INVALID_API_KEY" {
				t.Fatal("scoped verification accepted another configuration's key", err)
			}
			checks := personalChecks.Load() + automationChecks.Load()
			if r, err := ak.VerifyAny(ctx, "not-a-key", nil, personal, automation); err != nil || r.Valid || r.Error.Code != "INVALID_API_KEY" || personalChecks.Load()+automationChecks.Load() != checks {
				t.Fatal("an unknown secret reached a validator", err)
			}
			peer, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer peer.Close()
			other, err := ak.New(ak.Options{Store: peer, ConfigID: "other"})
			must(err)
			if _, err := ak.VerifyAny(ctx, own.Secret, nil, personal, other); err == nil {
				t.Fatal("services on different stores were accepted")
			}
			if _, err := ak.VerifyAny(ctx, own.Secret, nil, personal, personal); err == nil {
				t.Fatal("a duplicate configuration was accepted")
			}
		})
	}
}
