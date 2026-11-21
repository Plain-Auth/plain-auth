// Package memory provides process-local storage for development and tests.
package memory

import (
	"context"
	"crypto/rand"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

type credential struct {
	guestLinked     bool
	lastLoginMethod string
	accountID       string
	user            auth.User
	hash            string
}

// Store is safe to share among handlers. Its data lasts for the lifetime of the instance.
type Store struct {
	emailOTPs map[mailKey]mailProof
	nextProof uint64
	deletions map[string]auth.PasswordResetToken
	resets    map[string]auth.PasswordResetToken
	mu        sync.RWMutex
	users     map[string]credential
	emailToID map[string]string
	sessions  map[string]auth.StoredSession
}

func New() *Store {
	return &Store{emailOTPs: make(map[mailKey]mailProof), deletions: make(map[string]auth.PasswordResetToken), resets: make(map[string]auth.PasswordResetToken), users: make(map[string]credential), emailToID: make(map[string]string), sessions: make(map[string]auth.StoredSession)}
}

var _ auth.Store = (*Store)(nil)

func copyUser(u auth.User) auth.User {
	if u.UsernameFields != nil {
		u.UsernameFields = cloneUsername(u.UsernameFields, u.DisplayUsernameFields != nil)
	}
	if u.IsAnonymous != nil {
		v := *u.IsAnonymous
		u.IsAnonymous = &v
	}
	if u.Image != nil {
		image := *u.Image
		u.Image = &image
	}
	return u
}

func (s *Store) CreateUser(ctx context.Context, u auth.User, hash string, first *auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if f := u.UsernameFields; f != nil && f.Username != nil && s.usernameOwner(*f.Username) != "" {
		return auth.ErrUsernameTaken
	}
	key := strings.ToLower(u.Email)
	if _, ok := s.emailToID[key]; ok {
		return auth.ErrEmailTaken
	}
	if _, ok := s.users[u.ID]; ok {
		return errors.New("memory: duplicate user ID")
	}
	if first != nil {
		if first.UserID != u.ID {
			return errors.New("memory: session owner differs from account")
		}
		if err := s.insertSession(*first); err != nil {
			return err
		}
	}
	s.users[u.ID] = credential{user: copyUser(u), hash: hash, accountID: rand.Text()}
	s.emailToID[key] = u.ID
	return nil
}

func (s *Store) Credential(ctx context.Context, email string) (auth.User, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.User{}, "", err
	}
	u, ok := s.users[s.emailToID[strings.ToLower(email)]]
	if !ok || u.hash == "" {
		return auth.User{}, "", auth.ErrNotFound
	}
	return copyUser(u.user), u.hash, nil
}

func (s *Store) insertSession(row auth.StoredSession) error {
	if row.Token == "" || row.ID == "" {
		return errors.New("memory: missing session ID or token")
	}
	if _, ok := s.sessions[row.Token]; ok {
		return errors.New("memory: duplicate session token")
	}
	for _, other := range s.sessions {
		if other.ID == row.ID {
			return errors.New("memory: duplicate session ID")
		}
	}
	s.sessions[row.Token] = row
	return nil
}

func (s *Store) CreateSession(ctx context.Context, row auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := s.users[row.UserID]; !ok {
		return auth.ErrNotFound
	}
	return s.insertSession(row)
}

func (s *Store) Session(ctx context.Context, token string) (auth.StoredSession, auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return auth.StoredSession{}, auth.User{}, err
	}
	row, ok := s.sessions[token]
	if !ok {
		return auth.StoredSession{}, auth.User{}, auth.ErrNotFound
	}
	return row, copyUser(s.users[row.UserID].user), nil
}

func (s *Store) ListSessions(ctx context.Context, id string) ([]auth.StoredSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rows []auth.StoredSession
	for _, row := range s.sessions {
		if row.UserID == id {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	return rows, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(s.sessions, token)
	return nil
}

func (s *Store) DeleteUserSession(ctx context.Context, id, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.sessions[token].UserID == id {
		delete(s.sessions, token)
	}
	return nil
}

func (s *Store) DeleteOtherSessions(ctx context.Context, id, keep string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.deleteSessions(id, keep)
	return nil
}

func (s *Store) deleteSessions(id, keep string) {
	for token, row := range s.sessions {
		if row.UserID == id && token != keep {
			delete(s.sessions, token)
		}
	}
}

// RefreshSession extends a live row only while its previously observed expiry still matches.
func (s *Store) RefreshSession(ctx context.Context, token string, oldExpiry, now, nextExpiry time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	row, ok := s.sessions[token]
	if !ok || !row.ExpiresAt.Equal(oldExpiry) || !row.ExpiresAt.After(now) {
		return false, nil
	}
	row.ExpiresAt, row.UpdatedAt = nextExpiry, now
	s.sessions[token] = row
	return true, nil
}
func (s *Store) DeleteExpiredSession(ctx context.Context, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if row, ok := s.sessions[token]; ok && !row.ExpiresAt.After(now) {
		delete(s.sessions, token)
	}
	return nil
}
