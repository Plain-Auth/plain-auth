package plainauth

import (
	"context"
	"net/http"
	"sync/atomic"
)

// ErrorContext contains the request and the user authenticated for this request,
// when available. Reporting an error never triggers authentication.
type ErrorContext struct {
	Request *http.Request
	User    *User
}

// LocalizedError exposes the translated APIError and its original server message.
type LocalizedError struct {
	*APIError
	OriginalMessage string `json:"originalMessage"`
}

func (e *LocalizedError) Unwrap() error { return e.APIError }

type errorContextKey struct{ auth *Auth }
type errorIdentity struct {
	headers http.Header
	user    atomic.Pointer[User]
}

func (a *Auth) withErrorContext(r *http.Request) *http.Request {
	state := &errorIdentity{headers: r.Header}
	return r.WithContext(context.WithValue(r.Context(), errorContextKey{a}, state))
}

func (a *Auth) noteErrorUser(ctx context.Context, token string, user User) {
	state, _ := ctx.Value(errorContextKey{a}).(*errorIdentity)
	if state != nil && token != "" && token == a.cookieToken(state.headers) {
		state.user.Store(&user)
	}
}

func (a *Auth) errorContext(r *http.Request) ErrorContext {
	c := ErrorContext{Request: r}
	if ss, _ := r.Context().Value(credentialSessionKey{a}).(*SessionResult); ss != nil {
		c.User = &ss.User
	} else if state, _ := r.Context().Value(errorContextKey{a}).(*errorIdentity); state != nil {
		c.User = state.user.Load()
	}
	return c
}

// A failure in the host reporter must leave the original client response intact.
func (a *Auth) reportAPIError(r *http.Request, original error) {
	defer func() {
		if recover() != nil {
			a.Logger().ErrorContext(r.Context(), "Authentication error reporter panicked")
		}
	}()
	if err := a.opts.OnAPIError(a.errorContext(r), original); err != nil {
		a.Logger().ErrorContext(r.Context(), "Authentication error reporter failed")
	}
}
