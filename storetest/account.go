package storetest

import (
	"crypto/rand"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

func (f *fixture) account() auth.AccountStore { return f.store.(auth.AccountStore) }

func (f *fixture) hash(email, want string) {
	f.Helper()
	if _, hash, err := f.store.Credential(f.ctx, email); err != nil || hash != want {
		f.Fatalf("the stored hash is %q (%v), want %q", hash, err, want)
	}
}

var accountCases = []testCase{
	{"FindAccountUser", func(f *fixture) {
		u, _ := f.signUp(false)
		got, err := f.account().FindAccountUser(f.ctx, strings.ToUpper(u.Email))
		if err != nil || got.ID != u.ID {
			f.Fatal("FindAccountUser did not match the address case-insensitively:", err)
		}
		if _, err := f.account().FindAccountUser(f.ctx, "storetest-missing-"+strings.ToLower(rand.Text()[:8])+"@example.test"); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("an unknown address was not ErrNotFound:", err)
		}
	}},
	{"CreateCredentialSession", func(f *fixture) {
		u, _ := f.signUp(false)
		stale := f.session(u, 0)
		if err := f.account().CreateCredentialSession(f.ctx, "stale-hash", stale); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a stale hash was not ErrNotFound:", err)
		}
		f.gone(stale.Token)
		s := f.session(u, 0)
		if err := f.account().CreateCredentialSession(f.ctx, "hash-"+u.ID, s); err != nil {
			f.Fatal("CreateCredentialSession:", err)
		}
		f.owner(s.Token, u.ID)
		unsaved := f.user()
		if err := f.account().CreateCredentialSession(f.ctx, "hash-"+unsaved.ID, f.session(unsaved, 0)); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a session for an unsaved user was not ErrNotFound:", err)
		}
	}},
	{"ChangeCredential", func(f *fixture) {
		u, initial := f.signUp(true)
		other, theirs := f.signUp(true)
		if err := f.account().ChangeCredential(f.ctx, u.ID, "stale-hash", "next", nil); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a stale old hash was not ErrNotFound:", err)
		}
		f.hash(u.Email, "hash-"+u.ID)
		if err := f.account().ChangeCredential(f.ctx, u.ID, "hash-"+u.ID, "second", nil); err != nil {
			f.Fatal("ChangeCredential:", err)
		}
		f.hash(u.Email, "second")
		f.sessions(u.ID, *initial)
		replacement := f.session(u, time.Second)
		if err := f.account().ChangeCredential(f.ctx, u.ID, "second", "third", &replacement); err != nil {
			f.Fatal("ChangeCredential with a replacement session:", err)
		}
		f.hash(u.Email, "third")
		f.sessions(u.ID, replacement)
		f.sessions(other.ID, *theirs)
	}},
	{"PasswordReset", func(f *fixture) {
		u, _ := f.signUp(true)
		s := f.account()
		token := auth.PasswordResetToken{ID: rand.Text(), Token: rand.Text(), UserID: u.ID, Email: u.Email, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
		if err := s.SavePasswordResetToken(f.ctx, token); err != nil {
			f.Fatal("SavePasswordResetToken:", err)
		}
		got, err := s.FindPasswordResetToken(f.ctx, token.Token, f.now)
		if err != nil || got.ID != token.ID || got.UserID != u.ID || got.Token != token.Token || got.Email != u.Email || !got.ExpiresAt.Equal(token.ExpiresAt) {
			f.Fatalf("FindPasswordResetToken returned %+v (%v)", got, err)
		}
		if _, err := s.FindPasswordResetToken(f.ctx, token.Token, token.ExpiresAt); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a token was found at its expiry:", err)
		}
		if err := s.FinishPasswordReset(f.ctx, token.Token, "expired", token.ExpiresAt.Add(time.Second), false); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("an expired token reset the password:", err)
		}
		f.hash(u.Email, "hash-"+u.ID)
		if err := s.FinishPasswordReset(f.ctx, token.Token, "reset", f.now, false); err != nil {
			f.Fatal("FinishPasswordReset:", err)
		}
		f.hash(u.Email, "reset")
		if list, err := f.store.ListSessions(f.ctx, u.ID); err != nil || len(list) != 1 {
			f.Fatal("a reset without revocation removed sessions:", len(list), err)
		}
		if err := s.FinishPasswordReset(f.ctx, token.Token, "again", f.now, false); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a spent token reset the password again:", err)
		}
		if _, err := s.FindPasswordResetToken(f.ctx, token.Token, f.now); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a spent token was found:", err)
		}
		second := auth.PasswordResetToken{ID: rand.Text(), Token: rand.Text(), UserID: u.ID, Email: u.Email, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
		if err := s.SavePasswordResetToken(f.ctx, second); err != nil {
			f.Fatal("SavePasswordResetToken:", err)
		}
		if err := s.FinishPasswordReset(f.ctx, second.Token, "revoked", f.now, true); err != nil {
			f.Fatal("FinishPasswordReset with revocation:", err)
		}
		f.sessions(u.ID)
	}},
	{"VerifyAccountEmail", func(f *fixture) {
		u, _ := f.signUp(false)
		later := f.now.Add(time.Minute)
		if err := f.account().VerifyAccountEmail(f.ctx, u.ID, "other-"+u.Email, later); !errors.Is(err, auth.ErrNotFound) {
			f.Fatal("a wrong address verified the email:", err)
		}
		if got, _, _ := f.store.Credential(f.ctx, u.Email); got.EmailVerified {
			f.Fatal("a refused verification marked the email verified")
		}
		if err := f.account().VerifyAccountEmail(f.ctx, u.ID, u.Email, later); err != nil {
			f.Fatal("VerifyAccountEmail:", err)
		}
		got, _, err := f.store.Credential(f.ctx, u.Email)
		if err != nil || !got.EmailVerified || !got.UpdatedAt.Equal(later) {
			f.Fatal("the email was not verified at the given time:", got.EmailVerified, got.UpdatedAt, err)
		}
		if err := f.account().VerifyAccountEmail(f.ctx, u.ID, u.Email, later.Add(time.Minute)); err != nil {
			f.Fatal("a repeated verification failed:", err)
		}
	}},
	{"UpdateProfile", func(f *fixture) {
		u, s := f.signUp(true)
		name, image, later := "Renamed", "https://example.test/new.png", f.now.Add(time.Minute)
		if err := f.account().UpdateProfile(f.ctx, u.ID, auth.ProfileUpdate{Name: &name, Image: &image}, later); err != nil {
			f.Fatal("UpdateProfile:", err)
		}
		got, _, err := f.store.Credential(f.ctx, u.Email)
		if err != nil || got.Name != name || got.Image == nil || *got.Image != image || !got.UpdatedAt.Equal(later) {
			f.Fatalf("the profile was not updated: %+v (%v)", got, err)
		}
		if _, owner, err := f.store.Session(f.ctx, s.Token); err != nil || owner.Name != name {
			f.Fatal("the session owner does not show the new name:", err)
		}
		if err := f.account().UpdateProfile(f.ctx, u.ID, auth.ProfileUpdate{ClearImage: true}, later); err != nil {
			f.Fatal("UpdateProfile clearing the image:", err)
		}
		if got, _, _ := f.store.Credential(f.ctx, u.Email); got.Image != nil {
			f.Fatal("ClearImage left an image")
		}
	}},
}

func (f *fixture) refresh() auth.SessionRefreshStore { return f.store.(auth.SessionRefreshStore) }

var refreshCases = []testCase{
	{"RefreshSession", func(f *fixture) {
		u, s := f.signUp(true)
		next := s.ExpiresAt.Add(time.Hour)
		at := f.now.Add(time.Minute)
		if ok, err := f.refresh().RefreshSession(f.ctx, s.Token, s.ExpiresAt.Add(time.Second), at, next); err != nil || ok {
			f.Fatal("a stale previous expiry refreshed the session:", ok, err)
		}
		if ok, err := f.refresh().RefreshSession(f.ctx, s.Token, s.ExpiresAt, s.ExpiresAt, next); err != nil || ok {
			f.Fatal("a session was refreshed at its expiry:", ok, err)
		}
		if ok, err := f.refresh().RefreshSession(f.ctx, rand.Text(), s.ExpiresAt, at, next); err != nil || ok {
			f.Fatal("an unknown token was refreshed:", ok, err)
		}
		if ok, err := f.refresh().RefreshSession(f.ctx, s.Token, s.ExpiresAt, at, next); err != nil || !ok {
			f.Fatal("RefreshSession:", ok, err)
		}
		row, _, err := f.store.Session(f.ctx, s.Token)
		if err != nil || !row.ExpiresAt.Equal(next) || !row.UpdatedAt.Equal(at) || row.UserID != u.ID {
			f.Fatal("the refreshed session has the wrong times:", row.ExpiresAt, row.UpdatedAt, err)
		}
	}},
	{"DeleteExpiredSession", func(f *fixture) {
		_, s := f.signUp(true)
		if err := f.refresh().DeleteExpiredSession(f.ctx, s.Token, s.ExpiresAt.Add(-time.Millisecond)); err != nil {
			f.Fatal("DeleteExpiredSession:", err)
		}
		if _, _, err := f.store.Session(f.ctx, s.Token); err != nil {
			f.Fatal("a live session was deleted:", err)
		}
		if err := f.refresh().DeleteExpiredSession(f.ctx, s.Token, s.ExpiresAt); err != nil {
			f.Fatal("DeleteExpiredSession:", err)
		}
		f.gone(s.Token)
		if err := f.refresh().DeleteExpiredSession(f.ctx, s.Token, s.ExpiresAt); err != nil {
			f.Fatal("a repeated DeleteExpiredSession failed:", err)
		}
	}},
}
