// Package storetest checks a plainauth.Store implementation against the
// contract Plain Auth relies on. Call Run from the store's own tests:
//
//	func TestStoreContract(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) plainauth.Store {
//			s := openMyStore(t)
//			t.Cleanup(func() { s.Close() })
//			return s
//		})
//	}
package storetest

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Run checks stores from open against the plainauth.Store contract as subtests
// of t: "Store/<case>" always, and "AccountStore/<case>" and
// "SessionRefreshStore/<case>" when the store implements them (otherwise the
// group is skipped). open is called per case and may return a new store or one
// shared store; cases use fresh random IDs, addresses and tokens and read back
// only their own records. Close the store with t.Cleanup. A store with a
// DeleteFixtureUser(ctx, userID) error method has each case's users deleted
// when the case ends. Store/AuthFlow builds an Auth with default options on
// the store.
func Run(t *testing.T, open func(t *testing.T) auth.Store) {
	t.Helper()
	groups := []struct {
		name  string
		cases []testCase
		has   func(auth.Store) bool
	}{
		{"Store", storeCases, func(auth.Store) bool { return true }},
		{"AccountStore", accountCases, func(s auth.Store) bool { _, ok := s.(auth.AccountStore); return ok }},
		{"SessionRefreshStore", refreshCases, func(s auth.Store) bool { _, ok := s.(auth.SessionRefreshStore); return ok }},
	}
	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			if !g.has(open(t)) {
				t.Skipf("the store does not implement plainauth.%s", g.name)
			}
			for _, c := range g.cases {
				t.Run(c.name, func(t *testing.T) {
					c.run(&fixture{T: t, ctx: t.Context(), store: open(t), now: time.Now().UTC().Truncate(time.Millisecond)})
				})
			}
		})
	}
}

type testCase struct {
	name string
	run  func(*fixture)
}

type fixture struct {
	*testing.T
	ctx   context.Context
	store auth.Store
	now   time.Time
}

// cleanupUser deletes the user when the case ends, if the store can.
func (f *fixture) cleanupUser(id string) {
	if s, ok := f.store.(interface {
		DeleteFixtureUser(context.Context, string) error
	}); ok {
		f.Cleanup(func() { _ = s.DeleteFixtureUser(context.Background(), id) })
	}
}

// user returns an unsaved user with a fresh ID and a lowercase address, as
// Plain Auth sends them.
func (f *fixture) user() auth.User {
	u := auth.User{ID: rand.Text(), Email: "storetest-" + strings.ToLower(rand.Text()[:12]) + "@example.test", Name: "Store Test", CreatedAt: f.now, UpdatedAt: f.now}
	f.cleanupUser(u.ID)
	return u
}

func (f *fixture) session(u auth.User, offset time.Duration) auth.StoredSession {
	at := f.now.Add(offset)
	return auth.StoredSession{Session: auth.Session{ID: rand.Text(), Token: rand.Text(), UserID: u.ID, IPAddress: "192.0.2.1", UserAgent: "storetest", CreatedAt: at, UpdatedAt: at, ExpiresAt: at.Add(time.Hour)}}
}

// signUp stores a new user with the hash "hash-<ID>" and, when withSession is
// set, an initial session.
func (f *fixture) signUp(withSession bool) (auth.User, *auth.StoredSession) {
	f.Helper()
	u := f.user()
	var s *auth.StoredSession
	if withSession {
		row := f.session(u, 0)
		s = &row
	}
	if err := f.store.CreateUser(f.ctx, u, "hash-"+u.ID, s); err != nil {
		f.Fatal("CreateUser:", err)
	}
	return u, s
}

func (f *fixture) sameUser(got, want auth.User) {
	f.Helper()
	image := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return "=" + *p
	}
	if got.ID != want.ID || got.Email != want.Email || got.Name != want.Name || got.EmailVerified != want.EmailVerified || image(got.Image) != image(want.Image) ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		f.Fatalf("user %+v, want %+v", got, want)
	}
}

func (f *fixture) sameSession(got, want auth.Session) {
	f.Helper()
	if got.ID != want.ID || got.UserID != want.UserID || got.Token != want.Token || got.IPAddress != want.IPAddress || got.UserAgent != want.UserAgent ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		f.Fatalf("session %+v, want %+v", got, want)
	}
}

// sessions checks that the user has exactly the given sessions, in any order.
func (f *fixture) sessions(userID string, want ...auth.StoredSession) {
	f.Helper()
	got, err := f.store.ListSessions(f.ctx, userID)
	if err != nil {
		f.Fatal("ListSessions:", err)
	}
	if len(got) != len(want) {
		f.Fatalf("ListSessions returned %d sessions, want %d", len(got), len(want))
	}
	byID := func(a, b auth.StoredSession) int { return strings.Compare(a.ID, b.ID) }
	slices.SortFunc(got, byID)
	want = slices.Clone(want)
	slices.SortFunc(want, byID)
	for i := range got {
		f.sameSession(got[i].Session, want[i].Session)
	}
}

func (f *fixture) gone(token string) {
	f.Helper()
	if _, _, err := f.store.Session(f.ctx, token); !errors.Is(err, auth.ErrNotFound) {
		f.Fatal("a session that should not exist was found:", err)
	}
}

func (f *fixture) owner(token, userID string) {
	f.Helper()
	s, u, err := f.store.Session(f.ctx, token)
	if err != nil || s.UserID != userID || u.ID != userID {
		f.Fatal("the session lost its owner:", err)
	}
}

var storeCases = []testCase{
	{"CreateUser", func(f *fixture) {
		image := "https://example.test/avatar.png"
		u := f.user()
		u.Image, u.EmailVerified = &image, true
		s := f.session(u, 0)
		if err := f.store.CreateUser(f.ctx, u, "hash-"+u.ID, &s); err != nil {
			f.Fatal("CreateUser:", err)
		}
		got, hash, err := f.store.Credential(f.ctx, u.Email)
		if err != nil || hash != "hash-"+u.ID {
			f.Fatal("Credential did not return the stored hash:", err)
		}
		f.sameUser(got, u)
		row, owner, err := f.store.Session(f.ctx, s.Token)
		if err != nil {
			f.Fatal("Session:", err)
		}
		f.sameSession(row.Session, s.Session)
		f.sameUser(owner, u)
		f.sessions(u.ID, s)
		bare, _ := f.signUp(false)
		got, _, err = f.store.Credential(f.ctx, bare.Email)
		if err != nil {
			f.Fatal("Credential:", err)
		}
		f.sameUser(got, bare)
		if list, err := f.store.ListSessions(f.ctx, bare.ID); err != nil || len(list) != 0 {
			f.Fatal("a user without sessions listed some:", len(list), err)
		}
		if _, _, err := f.store.Credential(f.ctx, "storetest-missing-"+strings.ToLower(rand.Text()[:8])+"@example.test"); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("an unknown address was not ErrNotFound:", err)
		}
		f.gone(rand.Text())
	}},
	{"CreateUserAtomic", func(f *fixture) {
		first, initial := f.signUp(true)
		dup := f.user()
		dup.Email = first.Email
		dupSession := f.session(dup, 0)
		if err := f.store.CreateUser(f.ctx, dup, "hash-"+dup.ID, &dupSession); !errors.Is(err, auth.ErrEmailTaken) {
			f.Fatal("a taken address was not ErrEmailTaken:", err)
		}
		f.gone(dupSession.Token)
		other := f.user()
		reused := f.session(other, 0)
		reused.Token = initial.Token
		if err := f.store.CreateUser(f.ctx, other, "hash-"+other.ID, &reused); err == nil {
			f.Fatal("CreateUser accepted a session token that is already stored")
		}
		if _, _, err := f.store.Credential(f.ctx, other.Email); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a failed CreateUser left the user behind:", err)
		}
		f.owner(initial.Token, first.ID)
	}},
	{"CreateSession", func(f *fixture) {
		u, _ := f.signUp(false)
		s := f.session(u, 0)
		if err := f.store.CreateSession(f.ctx, s); err != nil {
			f.Fatal("CreateSession:", err)
		}
		row, owner, err := f.store.Session(f.ctx, s.Token)
		if err != nil {
			f.Fatal("Session:", err)
		}
		f.sameSession(row.Session, s.Session)
		f.sameUser(owner, u)
		missing := f.user()
		orphan := f.session(missing, 0)
		if err := f.store.CreateSession(f.ctx, orphan); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a session for a missing user was not ErrNotFound:", err)
		}
		f.gone(orphan.Token)
		other, _ := f.signUp(false)
		taken := f.session(other, 0)
		taken.Token = s.Token
		if err := f.store.CreateSession(f.ctx, taken); err == nil {
			f.Fatal("CreateSession accepted a token that is already stored")
		}
		f.owner(s.Token, u.ID)
	}},
	{"ListSessions", func(f *fixture) {
		u, _ := f.signUp(false)
		other, _ := f.signUp(false)
		var mine []auth.StoredSession
		for i := range 3 {
			s := f.session(u, time.Duration(i)*time.Second)
			if err := f.store.CreateSession(f.ctx, s); err != nil {
				f.Fatal("CreateSession:", err)
			}
			mine = append(mine, s)
		}
		if err := f.store.CreateSession(f.ctx, f.session(other, 0)); err != nil {
			f.Fatal("CreateSession:", err)
		}
		f.sessions(u.ID, mine...)
		if list, err := f.store.ListSessions(f.ctx, rand.Text()); err != nil || len(list) != 0 {
			f.Fatal("an unknown user listed sessions:", len(list), err)
		}
	}},
	{"DeleteSessions", func(f *fixture) {
		u, _ := f.signUp(false)
		other, _ := f.signUp(false)
		var mine []auth.StoredSession
		for i := range 4 {
			s := f.session(u, time.Duration(i)*time.Second)
			if err := f.store.CreateSession(f.ctx, s); err != nil {
				f.Fatal("CreateSession:", err)
			}
			mine = append(mine, s)
		}
		theirs := f.session(other, 0)
		if err := f.store.CreateSession(f.ctx, theirs); err != nil {
			f.Fatal("CreateSession:", err)
		}
		check := func(err error, what string) {
			f.Helper()
			if err != nil {
				f.Fatal(what+":", err)
			}
		}
		check(f.store.DeleteSession(f.ctx, mine[0].Token), "DeleteSession")
		f.sessions(u.ID, mine[1:]...)
		check(f.store.DeleteUserSession(f.ctx, other.ID, mine[1].Token), "DeleteUserSession for another user")
		f.sessions(u.ID, mine[1:]...)
		check(f.store.DeleteUserSession(f.ctx, u.ID, mine[1].Token), "DeleteUserSession")
		f.sessions(u.ID, mine[2:]...)
		check(f.store.DeleteOtherSessions(f.ctx, u.ID, mine[3].Token), "DeleteOtherSessions")
		f.sessions(u.ID, mine[3])
		f.sessions(other.ID, theirs)
		check(f.store.DeleteOtherSessions(f.ctx, u.ID, ""), "DeleteOtherSessions without a kept token")
		f.sessions(u.ID)
		f.sessions(other.ID, theirs)
		check(f.store.DeleteSession(f.ctx, mine[0].Token), "a repeated DeleteSession")
		check(f.store.DeleteUserSession(f.ctx, u.ID, mine[1].Token), "a repeated DeleteUserSession")
		check(f.store.DeleteSession(f.ctx, rand.Text()), "DeleteSession of an unknown token")
		check(f.store.DeleteOtherSessions(f.ctx, rand.Text(), ""), "DeleteOtherSessions of an unknown user")
	}},
	{"Concurrency", func(f *fixture) {
		email := "storetest-race-" + strings.ToLower(rand.Text()[:12]) + "@example.test"
		type attempt struct {
			user    auth.User
			session auth.StoredSession
			err     error
		}
		attempts := make([]attempt, 8)
		var wg sync.WaitGroup
		for i := range attempts {
			u := f.user()
			u.Email = email
			attempts[i] = attempt{user: u, session: f.session(u, 0)}
			wg.Go(func() {
				attempts[i].err = f.store.CreateUser(f.ctx, attempts[i].user, "hash-"+u.ID, &attempts[i].session)
			})
		}
		wg.Wait()
		var winner *attempt
		for i := range attempts {
			switch err := attempts[i].err; {
			case err == nil && winner == nil:
				winner = &attempts[i]
			case err == nil:
				f.Fatal("two concurrent CreateUser calls with one address both succeeded")
			case !errors.Is(err, auth.ErrEmailTaken):
				f.Fatal("a concurrent CreateUser with a taken address was not ErrEmailTaken:", err)
			}
		}
		if winner == nil {
			f.Fatal("no concurrent CreateUser succeeded")
		}
		got, _, err := f.store.Credential(f.ctx, email)
		if err != nil || got.ID != winner.user.ID {
			f.Fatal("Credential did not return the winner:", err)
		}
		for _, a := range attempts {
			if a.err != nil {
				f.gone(a.session.Token)
			}
		}
		var mu sync.Mutex
		created := []auth.StoredSession{winner.session}
		for range 8 {
			s := f.session(winner.user, 0)
			wg.Go(func() {
				if err := f.store.CreateSession(f.ctx, s); err != nil {
					f.Error("a concurrent CreateSession failed:", err)
					return
				}
				if _, _, err := f.store.Session(f.ctx, s.Token); err != nil {
					f.Error("a concurrently created session was not found:", err)
					return
				}
				mu.Lock()
				created = append(created, s)
				mu.Unlock()
			})
		}
		wg.Wait()
		f.sessions(winner.user.ID, created...)
	}},
	{"AuthFlow", authFlow},
}
