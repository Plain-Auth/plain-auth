package storetest_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/storetest"
)

// mapStore is the smallest plainauth.Store: users and sessions in maps under
// one mutex. It implements none of the optional interfaces.
type mapStore struct {
	mu       sync.Mutex
	users    map[string]auth.User    // by ID
	byEmail  map[string]string       // lowercase address to user ID
	hashes   map[string]string       // user ID to password hash
	sessions map[string]auth.Session // by token
}

func newMapStore() *mapStore {
	return &mapStore{users: map[string]auth.User{}, byEmail: map[string]string{}, hashes: map[string]string{}, sessions: map[string]auth.Session{}}
}

func (s *mapStore) CreateUser(_ context.Context, user auth.User, passwordHash string, initial *auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email := strings.ToLower(user.Email)
	if _, ok := s.byEmail[email]; ok {
		return auth.ErrEmailTaken
	}
	if initial != nil {
		s.sessions[initial.Token] = initial.Session
	}
	s.users[user.ID], s.byEmail[email], s.hashes[user.ID] = user, user.ID, passwordHash
	return nil
}

func (s *mapStore) Credential(_ context.Context, email string) (auth.User, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[strings.ToLower(email)]
	if !ok {
		return auth.User{}, "", auth.ErrNotFound
	}
	return s.users[id], s.hashes[id], nil
}

func (s *mapStore) CreateSession(_ context.Context, session auth.StoredSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[session.UserID]; !ok {
		return auth.ErrNotFound
	}
	s.sessions[session.Token] = session.Session
	return nil
}

func (s *mapStore) Session(_ context.Context, token string) (auth.StoredSession, auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[token]
	if !ok {
		return auth.StoredSession{}, auth.User{}, auth.ErrNotFound
	}
	return auth.StoredSession{Session: session}, s.users[session.UserID], nil
}

func (s *mapStore) DeleteSession(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
	return nil
}

func (s *mapStore) ListSessions(_ context.Context, userID string) ([]auth.StoredSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auth.StoredSession
	for _, session := range s.sessions {
		if session.UserID == userID {
			out = append(out, auth.StoredSession{Session: session})
		}
	}
	return out, nil
}

func (s *mapStore) DeleteOtherSessions(_ context.Context, userID, keepToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if session.UserID == userID && token != keepToken {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *mapStore) DeleteUserSession(_ context.Context, userID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[token].UserID == userID {
		delete(s.sessions, token)
	}
	return nil
}

// A store that implements only plainauth.Store passes the core contract,
// including sign-up, sign-in, revocation and sign-out through plainauth.New.
func TestMinimalStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) auth.Store { return newMapStore() })
}
