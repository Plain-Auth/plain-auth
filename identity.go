package fineauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// LinkedAccount contains fields safe to return to the signed-in account owner.
type LinkedAccount struct {
	ID         string    `json:"id"`
	AccountID  string    `json:"accountId"`
	ProviderID string    `json:"providerId"`
	UserID     string    `json:"userId"`
	Scopes     []string  `json:"scopes"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

var ErrLastAccount = errors.New("auth: cannot unlink last account")

type LinkedAccountStore interface {
	ListUserAccounts(ctx context.Context, userID string) ([]LinkedAccount, error)
	UnlinkAccount(ctx context.Context, userID, recordID string, allowLast bool) error
}

func (a *Auth) ListUserAccounts(ctx context.Context, h http.Header) ([]LinkedAccount, error) {
	session, err := a.requireSession(ctx, h)
	if err != nil {
		return nil, err
	}
	store, ok := a.opts.Store.(LinkedAccountStore)
	if !ok {
		return nil, &APIError{501, "ACCOUNT_STORAGE_UNAVAILABLE", "Account operation is unavailable for this store"}
	}
	return store.ListUserAccounts(ctx, session.User.ID)
}

func (a *Auth) UnlinkAccount(ctx context.Context, h http.Header, recordID string) error {
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return err
	}
	if a.now().Sub(session.Session.CreatedAt) >= a.opts.FreshAge {
		return &APIError{403, "SESSION_NOT_FRESH", "Session is not fresh"}
	}
	store, ok := a.opts.Store.(LinkedAccountStore)
	if !ok {
		return &APIError{501, "ACCOUNT_STORAGE_UNAVAILABLE", "Account operation is unavailable for this store"}
	}
	err = store.UnlinkAccount(ctx, session.User.ID, recordID, a.opts.AllowUnlinkingAll)
	switch {
	case errors.Is(err, ErrLastAccount):
		return &APIError{400, "FAILED_TO_UNLINK_LAST_ACCOUNT", "You can't unlink your last account"}
	case errors.Is(err, ErrNotFound):
		return &APIError{400, "ACCOUNT_NOT_FOUND", "Account not found"}
	}
	return err
}
