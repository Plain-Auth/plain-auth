package sqlstore

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDPoPReplayReservation(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			var stores []*Store
			for range 2 {
				s, err := Open(ctx, dialect, dsn)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				stores = append(stores, s)
			}
			now := time.Now().UTC().Truncate(time.Second)
			expiry := now.Add(2 * time.Second)
			digest := sha256.Sum256([]byte("verified proof"))
			key := base64.RawURLEncoding.EncodeToString(digest[:])
			var wg sync.WaitGroup
			var wins atomic.Int32
			for i := range 16 {
				wg.Go(func() {
					ok, err := stores[i%2].ReserveDPoPProof(ctx, key, now, expiry)
					if err != nil {
						t.Errorf("reserve: %v", err)
					} else if ok {
						wins.Add(1)
					}
				})
			}
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%d reservations won", wins.Load())
			}
			s := stores[0]
			if ok, err := s.ReserveDPoPProof(ctx, key, expiry.Add(-time.Millisecond), expiry.Add(time.Minute)); ok || err != nil {
				t.Fatal("early reuse", ok, err)
			}
			if ok, err := s.ReserveDPoPProof(ctx, key, expiry, expiry.Add(time.Second)); !ok || err != nil {
				t.Fatal("reuse after expiry", ok, err)
			}
			// A periodic sweep keeps unrelated verification flows intact.
			_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES ('unrelated','password-reset','fixture',?,?,?)`), s.date(expiry), s.date(now), s.date(now))
			if err != nil {
				t.Fatal(err)
			}
			later := expiry.Add(2 * time.Minute)
			another := sha256.Sum256([]byte("another verified proof"))
			if ok, err := s.ReserveDPoPProof(ctx, base64.RawURLEncoding.EncodeToString(another[:]), later, later.Add(time.Minute)); !ok || err != nil {
				t.Fatal(ok, err)
			}
			var count int
			for id, want := range map[string]int{s.verificationReservationID("dpop-proof:" + key): 0, "unrelated": 1} {
				if err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`), id).Scan(&count); err != nil || count != want {
					t.Fatalf("count for %s=%d, want %d: %v", id, count, want, err)
				}
			}
			if ok, err := s.ReserveDPoPProof(ctx, "bad", now, expiry); ok || err == nil {
				t.Fatal("invalid digest", ok, err)
			}
			if ok, err := s.ReserveDPoPProof(ctx, key, expiry, now); ok || err == nil {
				t.Fatal("invalid lifetime", ok, err)
			}
			if err := stores[1].Close(); err != nil {
				t.Fatal(err)
			}
			if ok, err := stores[1].ReserveDPoPProof(ctx, key, now, expiry); ok || err == nil {
				t.Fatal("unavailable database", ok, err)
			}
		})
	}
}
