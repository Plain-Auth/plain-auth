package sqlstore

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authn "github.com/nabuhadba/go-better-auth"
)

func TestDeviceSessionStorage(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			a, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			u := testUser("switch-" + rand.Text())
			now := time.Now().UTC().Truncate(time.Millisecond)
			if err := a.CreateUser(ctx, u, "test-hash", nil); err != nil {
				t.Fatal(err)
			}
			insert := func(label string, expiry time.Time) string {
				t.Helper()
				row := testSession(u, rand.Text())
				row.Token = label + "-" + rand.Text()
				row.ExpiresAt = expiry
				if err := a.CreateSession(ctx, row); err != nil {
					t.Fatal(err)
				}
				return row.Token
			}
			active := insert("Active", now.Add(time.Hour))
			target := insert("Target", now.Add(time.Hour))
			foreign := insert("Other", now.Add(time.Hour))
			expired := insert("Expired", now)
			rows, err := b.DeviceSessions(ctx, []string{target, active, target, strings.ToLower(foreign), expired, "absent"}, now)
			if err != nil || len(rows) != 2 || rows[active].User.ID != u.ID || rows[target].Session.Token != target {
				t.Fatal("live device session batch", err)
			}
			for _, denied := range []string{strings.ToLower(active), expired, "absent"} {
				if err := b.RevokeDeviceSession(ctx, denied, target, now); !errors.Is(err, authn.ErrNotFound) {
					t.Fatal("invalid active credential accepted", err)
				}
			}
			if _, _, err := b.Session(ctx, target); err != nil {
				t.Fatal("unauthorized revoke affected target", err)
			}
			if err := b.DeleteDeviceSessions(ctx, []string{strings.ToLower(foreign)}); err != nil {
				t.Fatal(err)
			}
			if err := b.RevokeDeviceSession(ctx, active, strings.ToLower(target), now); err != nil {
				t.Fatal(err)
			}
			if _, _, err := a.Session(ctx, target); err != nil {
				t.Fatal("case-folded credential revoked target")
			}
			var wins atomic.Int32
			var group sync.WaitGroup
			for i := range 8 {
				worker := []*Store{a, b}[i%2]
				group.Go(func() {
					err := worker.RevokeDeviceSession(ctx, active, active, now)
					if err == nil {
						wins.Add(1)
					} else if !errors.Is(err, authn.ErrNotFound) {
						t.Error(err)
					}
				})
			}
			group.Wait()
			if wins.Load() != 1 {
				t.Fatal("concurrent self-revocation must have one winner", wins.Load())
			}
			if err := b.RevokeDeviceSession(ctx, active, target, now); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("revoked login authorized deletion", err)
			}
			proven := make([]string, 405)
			for i := range proven {
				proven[i] = "unused"
			}
			proven[0], proven[404] = target, expired
			if err := b.DeleteDeviceSessions(ctx, proven); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{active, target, expired} {
				if _, _, err := a.Session(ctx, token); !errors.Is(err, authn.ErrNotFound) {
					t.Fatal("batch failed to revoke signed session", err)
				}
			}
			if _, _, err := a.Session(ctx, foreign); err != nil {
				t.Fatal("unrelated session affected", err)
			}
		})
	}
}
