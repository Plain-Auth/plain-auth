package memory_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
)

func TestAtomicRegistration(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			user := auth.User{ID: fmt.Sprint(i), Email: "ada@example.com"}
			session := auth.StoredSession{Session: auth.Session{ID: user.ID, Token: "s" + user.ID, UserID: user.ID}}
			err := s.CreateUser(ctx, user, "hash", &session)
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, auth.ErrEmailTaken) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("created %d accounts", wins.Load())
	}
	user, _, err := s.Credential(ctx, "ADA@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSessions(ctx, user.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("sessions: %v %v", rows, err)
	}
}

func TestInProcessSessions(t *testing.T) {
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: "0123456789abcdef0123456789abcdef", BaseURL: "https://example.com", EmailAndPassword: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Ada", Email: "ada@example.com", Password: "long-password"}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	req := http.Request{Header: make(http.Header)}
	req.AddCookie(a.SessionCookie(res.Token, true))
	current, err := a.GetSession(ctx, req.Header)
	if err != nil || current == nil || current.User.ID != res.User.ID {
		t.Fatal(current, err)
	}
	if err := a.SignOut(ctx, req.Header); err != nil {
		t.Fatal(err)
	}
	current, err = a.GetSession(ctx, req.Header)
	if err != nil || current != nil {
		t.Fatal(current, err)
	}
}
