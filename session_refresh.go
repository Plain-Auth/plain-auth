package stonewrit

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

func (a *Auth) sessionHTTP(headers http.Header, r *http.Request) (body any, responseErr error) {
	ctx := r.Context()
	if identity, _ := ctx.Value(credentialSessionKey{a}).(*SessionResult); identity != nil {
		if a.opts.SessionCookieCache == nil {
			a.expireStoredSessionData(headers, r, false)
		}
		return identity, nil
	}
	token := a.cookieToken(r.Header)
	if token == "" {
		if a.opts.SessionCookieCache == nil {
			a.expireStoredSessionData(headers, r, false)
		}
		return nil, nil
	}
	allowCache := a.canCacheSessionView(r)
	readCache := allowCache && r.URL.Query().Get("disableCookieCache") == ""
	if readCache {
		if cached := a.cachedSessionView(r, token); cached != nil {
			return cached, nil
		}
	}
	row, user, err := a.opts.Store.Session(ctx, token)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	store, canRefresh := a.opts.Store.(SessionRefreshStore)
	deferredRead := a.opts.DeferSessionRefresh && r.Method == http.MethodGet
	if errors.Is(err, ErrNotFound) || !row.ExpiresAt.After(now) {
		a.expireSessionCookieHeaders(headers, r)
		if err == nil && canRefresh && !deferredRead {
			if err := store.DeleteExpiredSession(ctx, token, now); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	if !allowCache {
		a.expireStoredSessionData(headers, r, false)
	}
	result, err := a.withSessionPlugins(ctx, row.Session, user)
	if err != nil {
		return nil, err
	}
	if a.serviceJWT != nil && !a.serviceJWT.DisableHeader && row.ImpersonatedBy == nil {
		defer func() {
			if responseErr != nil || body == nil {
				return
			}
			token, err := a.signSessionJWT(ctx, *result)
			if err != nil {
				body, responseErr = nil, err
				return
			}
			headers.Set("Set-Auth-Jwt", token)
			headers.Add("Access-Control-Expose-Headers", "set-auth-jwt")
		}()
	}
	// Match the reference query's coercion: a nonempty disableRefresh query
	// string requests a read without refreshing the session or reissuing cookies.
	if row.ImpersonatedBy != nil || a.dontRemember(r) || r.URL.Query().Get("disableRefresh") != "" {
		if readCache {
			a.expireStoredSessionData(headers, r, false)
		}
		return result, nil
	}
	threshold := row.ExpiresAt.Add(-a.opts.SessionTTL).Add(*a.opts.SessionUpdateAge)
	due := canRefresh && !a.opts.DisableSessionRefresh && !now.Before(threshold)
	if deferredRead || !due {
		if allowCache {
			a.writeCachedSessionView(headers, r, *result, true)
		}
		if deferredRead {
			result.NeedsRefresh = &due
		}
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
			a.expireSessionCookieHeaders(headers, r)
			return nil, &APIError{401, "FAILED_TO_GET_SESSION", "Failed to get session"}
		}
		result = current
		if allowCache {
			a.writeCachedSessionView(headers, r, *current, true)
		}
		return current, nil
	}
	result.Session.ExpiresAt = next
	result.Session.UpdatedAt = now
	a.emitSessionCookieHeaders(headers, r, a.sessionCookie(token, true))
	if allowCache {
		a.writeCachedSessionView(headers, r, *result, true)
	}
	return result, nil
}
