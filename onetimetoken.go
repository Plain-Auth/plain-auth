package fineauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type OneTimeTokenOptions struct {
	ExpiresIn                                                            time.Duration
	DisableClientRequest, DisableSetSessionCookie, SetHeaderOnNewSession bool
	HashTokens                                                           bool
	HashToken                                                            func(context.Context, string) (string, error)
	GenerateToken                                                        func(context.Context, SessionResult) (string, error)
}

type OneTimeTokenStore interface {
	SaveOneTimeToken(ctx context.Context, key string, source Session, now, expires time.Time) error
	ConsumeOneTimeToken(ctx context.Context, key string, now time.Time) (SessionResult, error)
}

var (
	ErrTransferSessionExpired = errors.New("one-time token session expired")
	ErrTransferSessionMissing = errors.New("one-time token session absent")
)

func NewOneTimeToken(opts OneTimeTokenOptions) (Plugin, error) {
	if opts.ExpiresIn < 0 {
		return Plugin{}, errors.New("one-time token lifetime must be positive")
	}
	if opts.ExpiresIn == 0 {
		opts.ExpiresIn = 3 * time.Minute
	}
	if opts.HashTokens && opts.HashToken != nil {
		return Plugin{}, errors.New("choose one one-time token hasher")
	}
	return Plugin{
		ID: "one-time-token", oneTime: &opts,
		ValidateStore: func(s Store) error {
			if _, ok := s.(OneTimeTokenStore); !ok {
				return errors.New("one-time token requires a OneTimeTokenStore")
			}
			return nil
		},
		Endpoints: []Endpoint{
			{Method: http.MethodGet, Path: "/one-time-token/generate", Handler: func(c EndpointContext) (any, error) {
				if opts.DisableClientRequest {
					return nil, &APIError{400, "BAD_REQUEST", "Client requests are disabled"}
				}
				token, err := c.Auth.GenerateOneTimeToken(c.Request.Context(), c.Request.Header)
				if err != nil {
					return nil, err
				}
				return map[string]string{"token": token}, nil
			}},
			{Method: http.MethodPost, Path: "/one-time-token/verify", Handler: func(c EndpointContext) (any, error) {
				token, err := requiredString(c.Body, "token")
				if err != nil {
					return nil, err
				}
				s, err := c.Auth.VerifyOneTimeToken(c.Request.Context(), token)
				if err != nil {
					return nil, err
				}
				if !opts.DisableSetSessionCookie {
					c.Auth.writeSessionCookieHeaders(c.ResponseHeader, c.Request, s.Session.Token, true)
				}
				return s, nil
			}},
		},
	}, nil
}

func (o OneTimeTokenOptions) storedKey(ctx context.Context, token string) (string, error) {
	key := token
	if o.HashToken != nil {
		var err error
		key, err = o.HashToken(ctx, token)
		if err != nil {
			return "", err
		}
	} else if o.HashTokens {
		sum := sha256.Sum256([]byte(token))
		key = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if key == "" || len(key) > 238 {
		return "", errors.New("invalid one-time token storage key")
	}
	return key, nil
}

// GenerateOneTimeToken creates a short-lived transfer credential for the caller's active session.
func (a *Auth) GenerateOneTimeToken(ctx context.Context, h http.Header) (string, error) {
	opts := a.oneTimeToken
	if opts == nil {
		return "", &APIError{404, "NOT_FOUND", "One-time token plugin is not enabled"}
	}
	session, err := a.requireSession(ctx, h)
	if err != nil {
		return "", err
	}
	return a.newOneTimeToken(ctx, opts, *session)
}
func (a *Auth) newOneTimeToken(ctx context.Context, opts *OneTimeTokenOptions, session SessionResult) (string, error) {
	token := randomID()
	if opts.GenerateToken != nil {
		var err error
		token, err = opts.GenerateToken(ctx, session)
		if err != nil {
			return "", err
		}
	}
	if token == "" || len(token) > 238 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("invalid generated one-time token")
	}
	key, err := opts.storedKey(ctx, token)
	if err != nil {
		return "", err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	if err = a.opts.Store.(OneTimeTokenStore).SaveOneTimeToken(ctx, key, session.Session, now, now.Add(opts.ExpiresIn)); err != nil {
		return "", err
	}
	return token, nil
}

// VerifyOneTimeToken consumes one transfer credential and resolves its original active session.
func (a *Auth) VerifyOneTimeToken(ctx context.Context, token string) (*SessionResult, error) {
	opts := a.oneTimeToken
	if opts == nil {
		return nil, &APIError{404, "NOT_FOUND", "One-time token plugin is not enabled"}
	}
	if token == "" || len(token) > 238 {
		return nil, &APIError{400, "BAD_REQUEST", "Invalid token"}
	}
	key, err := opts.storedKey(ctx, token)
	if err != nil {
		return nil, err
	}
	s, err := a.opts.Store.(OneTimeTokenStore).ConsumeOneTimeToken(ctx, key, a.now().UTC())
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, &APIError{400, "BAD_REQUEST", "Invalid token"}
	case errors.Is(err, ErrTransferSessionExpired):
		return nil, &APIError{400, "BAD_REQUEST", "Session expired"}
	case errors.Is(err, ErrTransferSessionMissing):
		return nil, &APIError{400, "BAD_REQUEST", "Session not found"}
	case err != nil:
		return nil, err
	}
	return a.withSessionPlugins(ctx, s.Session, s.User)
}

func (a *Auth) addOneTimeTokenHeader(headers http.Header, r *http.Request, token string) {
	opts := a.oneTimeToken
	if opts == nil || !opts.SetHeaderOnNewSession {
		return
	}
	// Use the newly created session. The incoming cookie can belong to an older account.
	row, u, err := a.opts.Store.Session(r.Context(), token)
	if err != nil {
		slog.ErrorContext(r.Context(), "Could not resolve the new session for token transfer")
		return
	}
	session, err := a.withSessionPlugins(r.Context(), row.Session, u)
	if err != nil {
		slog.ErrorContext(r.Context(), "Could not read the new session for token transfer")
		return
	}
	transfer, err := a.newOneTimeToken(r.Context(), opts, *session)
	if err != nil {
		slog.ErrorContext(r.Context(), "Could not issue an optional one-time token header")
		return
	}
	headers.Set("Set-Ott", transfer)
	for _, line := range headers.Values("Access-Control-Expose-Headers") {
		for field := range strings.SplitSeq(line, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "set-ott") {
				return
			}
		}
	}
	headers.Add("Access-Control-Expose-Headers", "set-ott")
}
