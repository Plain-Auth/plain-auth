package betterauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// SessionRefreshStore supports sliding expiration without reviving an expired
// or revoked session. Implementations compare the previously read expiry
// atomically with the update. A lost comparison returns false.
type SessionRefreshStore interface {
	RefreshSession(ctx context.Context, token string, previousExpiry, now, nextExpiry time.Time) (bool, error)
	DeleteExpiredSession(ctx context.Context, token string, now time.Time) error
}

func (a *Auth) sessionHTTP(w http.ResponseWriter, r *http.Request) (any, error) {
	ctx := r.Context()
	token := a.cookieToken(r.Header)
	if token == "" {
		return nil, nil
	}
	row, user, err := a.opts.Store.Session(ctx, token)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	store, canRefresh := a.opts.Store.(SessionRefreshStore)
	deferredRead := a.opts.DeferSessionRefresh && r.Method == http.MethodGet
	if errors.Is(err, ErrNotFound) || !row.ExpiresAt.After(now) {
		a.expireSessionCookies(w, r)
		if err == nil && canRefresh && !deferredRead {
			if err := store.DeleteExpiredSession(ctx, token, now); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	result, err := a.withSessionPlugins(ctx, row.Session, user)
	if err != nil {
		return nil, err
	}
	// Match the reference query's coercion: a nonempty disableRefresh query
	// string requests a read without refreshing the session or reissuing cookies.
	if a.dontRemember(r) || r.URL.Query().Get("disableRefresh") != "" {
		return result, nil
	}
	threshold := row.ExpiresAt.Add(-a.opts.SessionTTL).Add(*a.opts.SessionUpdateAge)
	due := canRefresh && !a.opts.DisableSessionRefresh && !now.Before(threshold)
	if deferredRead {
		return struct {
			*SessionResult
			NeedsRefresh bool `json:"needsRefresh"`
		}{result, due}, nil
	}
	if !due {
		return result, nil
	}
	next := now.Add(a.opts.SessionTTL)
	won, err := store.RefreshSession(ctx, token, row.ExpiresAt, now, next)
	if err != nil {
		return nil, err
	}
	if !won {
		// A simultaneous refresh may have won. If a revoke won, expire the
		// cookie and leave the deleted session absent.
		current, err := a.GetSession(ctx, r.Header)
		if err != nil {
			return nil, err
		}
		if current == nil {
			a.expireSessionCookies(w, r)
			return nil, &APIError{401, "FAILED_TO_GET_SESSION", "Failed to get session"}
		}
		return current, nil
	}
	result.Session.ExpiresAt = next
	result.Session.UpdatedAt = now
	a.setSessionCookie(w, r, token, true)
	return result, nil
}
