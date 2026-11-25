package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/twofactor"
)

// WithTwoFactor reports the challenge and remembered browser rows it locked,
// and stores new ones under the IDs the Auth chose, on SQLite, PostgreSQL
// and MySQL. A failed decision and an empty change write nothing.
func TestTwoFactorRowsCarryTheirIDs(t *testing.T) {
	withFactorDatabases(t, twofactor.Options{Issuer: "Auth"}, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		s := h.store
		u := h.enroll()
		now := time.Now().UTC().Truncate(time.Millisecond)
		call := func(sub auth.FactorSubject, change auth.FactorChange) auth.FactorState {
			t.Helper()
			var seen auth.FactorState
			sub.Now = now
			if err := s.WithTwoFactor(ctx, sub, func(st auth.FactorState) (auth.FactorChange, error) { seen = st; return change, nil }); err != nil {
				t.Fatal(err)
			}
			return seen
		}
		row := func(identifier string) (string, time.Time) {
			t.Helper()
			var id string
			var expires time.Time
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "verification" WHERE "identifier"=?`), identifier).Scan(&id, &expires); err != nil {
				t.Fatal(identifier, err)
			}
			return id, expires
		}
		unique := strings.ToLower(rand.Text())

		// A challenge is stored under the Auth's ID and read back with it.
		challenge := "2fa-" + unique
		call(auth.FactorSubject{UserID: u.userID}, auth.FactorChange{CreateChallenge: challenge, ChallengeID: "challenge-" + unique, ChallengeExpires: now.Add(5 * time.Minute)})
		id, expires := row(challenge)
		if id != "challenge-"+unique || !expires.Equal(now.Add(5*time.Minute)) {
			t.Fatal("the challenge was stored as", id, expires)
		}
		if st := call(auth.FactorSubject{Challenge: challenge}, auth.FactorChange{}); st.ChallengeID != id || !st.ChallengeExpires.Equal(expires) || st.ChallengeExpires.Location() != time.UTC {
			t.Fatal("the challenge was reported as", st.ChallengeID, st.ChallengeExpires)
		}
		// So is a remembered browser's grant.
		grant := "trust-device-" + unique
		call(auth.FactorSubject{UserID: u.userID}, auth.FactorChange{CreateTrustedGrant: grant, TrustedGrantID: "grant-" + unique, TrustedUntil: now.Add(time.Hour)})
		id, expires = row(grant)
		if id != "grant-"+unique || !expires.Equal(now.Add(time.Hour)) {
			t.Fatal("the grant was stored as", id, expires)
		}
		if st := call(auth.FactorSubject{UserID: u.userID, TrustedGrant: grant}, auth.FactorChange{}); st.TrustedGrant != grant || st.TrustedGrantID != id || !st.TrustedGrantExpires.Equal(expires) || st.TrustedGrantExpires.Location() != time.UTC {
			t.Fatal("the grant was reported as", st.TrustedGrantID, st.TrustedGrantExpires)
		}
		// Without an ID the store chooses one, which later calls report, as
		// they report rows stored before the Auth chose IDs.
		other := "2fa-other-" + unique
		call(auth.FactorSubject{UserID: u.userID}, auth.FactorChange{CreateChallenge: other, ChallengeExpires: now.Add(time.Minute)})
		if id, _ := row(other); id == "" || call(auth.FactorSubject{Challenge: other}, auth.FactorChange{}).ChallengeID != id {
			t.Fatal("a chosen challenge ID was not reported:", id)
		}
		otherGrant := "trust-device-other-" + unique
		call(auth.FactorSubject{UserID: u.userID}, auth.FactorChange{CreateTrustedGrant: otherGrant, TrustedUntil: now.Add(time.Hour)})
		if id, _ := row(otherGrant); id == "" || call(auth.FactorSubject{UserID: u.userID, TrustedGrant: otherGrant}, auth.FactorChange{}).TrustedGrantID != id {
			t.Fatal("a chosen grant ID was not reported:", id)
		}

		// A failed decision and an empty change write nothing.
		snapshot := func() string {
			t.Helper()
			var out strings.Builder
			rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "id","identifier","value","updatedAt" FROM "verification" ORDER BY "id"`))
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var id, identifier, value string
				var updated time.Time
				if err := rows.Scan(&id, &identifier, &value, &updated); err != nil {
					t.Fatal(err)
				}
				fmt.Fprintln(&out, id, identifier, value, updated.UnixMilli())
			}
			var updated time.Time
			var failures int
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT u."updatedAt",f."failedVerificationCount" FROM "user" u JOIN "twoFactor" f ON f."userId"=u."id" WHERE u."id"=?`), u.userID).Scan(&updated, &failures); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&out, updated.UnixMilli(), failures)
			return out.String()
		}
		before := snapshot()
		refused := errors.New("refused")
		err := s.WithTwoFactor(ctx, auth.FactorSubject{Challenge: challenge, Now: now}, func(st auth.FactorState) (auth.FactorChange, error) {
			record := *st.Record
			record.Failures++
			return auth.FactorChange{SaveRecord: &record, IncrementAttempts: true, ConsumeChallenge: true}, refused
		})
		if !errors.Is(err, refused) || snapshot() != before {
			t.Fatal("a failed decision wrote its change:", err)
		}
		call(auth.FactorSubject{Challenge: challenge}, auth.FactorChange{})
		call(auth.FactorSubject{UserID: u.userID, TrustedGrant: grant}, auth.FactorChange{})
		if snapshot() != before {
			t.Fatal("an empty change wrote something")
		}
	})
}

// A login plan runs the decision twice. When the code a dry run accepted is
// spent before the approved run judges it, the response answers the
// approved run alone.
func TestTwoFactorPlanRunsStartAfresh(t *testing.T) {
	var h *factorHarness
	var armed atomic.Bool
	var proof func()
	hooks := func(o *auth.Options) {
		o.DatabaseHooks.Session.Create.Before = func(context.Context, *auth.SessionRecord, *auth.HookContext) error {
			if armed.CompareAndSwap(true, false) {
				proof()
			}
			return nil
		}
	}
	withConfiguredFactorDatabases(t, twofactor.Options{Issuer: "Auth"}, hooks, func(harness *factorHarness) {
		h = harness
		t := h.t
		ctx := t.Context()
		u := h.enroll()
		signIn := func() string {
			t.Helper()
			w := h.request(h.first, "sign-in/email", map[string]string{"email": u.input.Email, "password": u.input.Password}, 200)
			return h.cookie(w, "two_factor").Value
		}
		first := signIn()
		// Between the first request's dry run and its approved run, the same
		// backup code completes another sign-in.
		proof = func() {
			cookie := h.first.TwoFactorChallengeCookie(auth.LoginChallenge{Identifier: h.first.VerifySignedSessionToken(signIn())})
			h.request(h.second, "two-factor/verify-backup-code", map[string]any{"code": u.backups[0]}, 200, cookie)
		}
		armed.Store(true)
		challenge := h.first.VerifySignedSessionToken(first)
		cookie := h.first.TwoFactorChallengeCookie(auth.LoginChallenge{Identifier: challenge})
		// A dry run's verdict never reaches the response.
		w := h.request(h.first, "two-factor/verify-backup-code", map[string]any{"code": u.backups[0]}, 401, cookie)
		if armed.Load() || !strings.Contains(w.Body.String(), "INVALID_BACKUP_CODE") {
			t.Fatal("the approved run answered", w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if strings.HasSuffix(c.Name, "two_factor") || strings.HasSuffix(c.Name, "session_token") {
				t.Fatal("the response set", c.Name, "from the dry run")
			}
		}
		var attempts string
		if err := h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "2fa-attempts-"+challenge).Scan(&attempts); err != nil || attempts != "1" {
			t.Fatal("the challenge was left with", attempts, err)
		}
	})
}
