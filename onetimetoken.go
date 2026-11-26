package plainauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

type OneTimeTokenOptions struct {
	ExpiresIn time.Duration
	// ExpireImmediately explicitly selects a zero lifetime. An unset ExpiresIn uses three minutes.
	ExpireImmediately                                                    bool
	DisableClientRequest, DisableSetSessionCookie, SetHeaderOnNewSession bool
	HashTokens                                                           bool
	HashToken                                                            func(context.Context, string) (string, error)
	GenerateToken                                                        func(context.Context, SessionResult) (string, error)
	// GenerateTokenWithRequest receives request metadata for HTTP issuance and nil for native calls.
	GenerateTokenWithRequest func(context.Context, SessionResult, *http.Request) (string, error)
}

// OneTimeTokenStore keeps single-use session transfers. ConsumeOneTimeToken
// spends the token also when it returns ErrTransferSessionMissing or
// ErrTransferSessionExpired. Verification delete hooks rely on this. key is
// the token as stored, after OneTimeTokenOptions.HashTokens or HashToken and
// then Options.StoreVerificationIdentifier.
type OneTimeTokenStore interface {
	SaveOneTimeToken(ctx context.Context, key string, source Session, now, expires time.Time) error
	ConsumeOneTimeToken(ctx context.Context, key string, now time.Time) (SessionResult, error)
}

// OneTimeTokenFinder reads a one-time token without spending it, for
// verification delete hooks. For the newest token stored under key that is
// live at now, it returns the user whose session it transfers, empty when
// that is unknown, and the token's expiry. It judges only the stored token: one whose
// session has ended, or whose key another live token shares, is still found,
// and ConsumeOneTimeToken refuses it. A token unknown or expired at now is
// ErrNotFound.
type OneTimeTokenFinder interface {
	FindOneTimeToken(ctx context.Context, key string, now time.Time) (userID string, expiresAt time.Time, err error)
}

var (
	ErrTransferSessionExpired = errors.New("one-time token session expired")
	ErrTransferSessionMissing = errors.New("one-time token session absent")
)

func NewOneTimeToken(opts OneTimeTokenOptions) (Plugin, error) {
	if opts.ExpiresIn < 0 {
		return Plugin{}, errors.New("one-time token lifetime must be positive")
	}
	if opts.ExpireImmediately && opts.ExpiresIn != 0 {
		return Plugin{}, errors.New("choose one one-time token lifetime")
	}
	if opts.ExpiresIn == 0 && !opts.ExpireImmediately {
		opts.ExpiresIn = 3 * time.Minute
	}
	if opts.HashTokens && opts.HashToken != nil {
		return Plugin{}, errors.New("choose one one-time token hasher")
	}
	if opts.GenerateToken != nil && opts.GenerateTokenWithRequest != nil {
		return Plugin{}, errors.New("choose one one-time token generator")
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
				token, err := c.Auth.generateOneTimeToken(c.Request.Context(), c.Request.Header, c.Request)
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
					persistent := !c.Auth.dontRemember(c.Request)
					if err := c.Auth.writeSessionCookieHeaders(c.ResponseHeader, c.Request, s.Session.Token, persistent); err != nil {
						return nil, err
					}
					c.Auth.writeRememberPreference(c.ResponseHeader, c.Request, persistent)
				}
				return s, nil
			}},
		},
	}, nil
}

// hostCallback runs a host callback that may run after a login has
// committed: a panic becomes the failure error instead of unwinding the
// request, and a context that ends during the call wins over its result.
func hostCallback(ctx context.Context, failure string, fn func() (string, error)) (value string, err error) {
	if err = ctx.Err(); err != nil {
		return "", err
	}
	defer func() {
		if recover() != nil {
			value = ""
			err = errors.New(failure)
		}
	}()
	value, err = fn()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return value, err
}

func (o OneTimeTokenOptions) storedKey(ctx context.Context, token string) (string, error) {
	key := token
	if o.HashToken != nil {
		var err error
		key, err = hostCallback(ctx, "one-time token callback failed", func() (string, error) { return o.HashToken(ctx, token) })
		if err != nil {
			return "", err
		}
	} else if o.HashTokens {
		sum := sha256.Sum256([]byte(token))
		key = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	if !validTransferKey(key) {
		return "", errors.New("invalid one-time token storage key")
	}
	return key, nil
}

func validTransferKey(key string) bool {
	return key != "" && len("one-time-token:")+len(key) <= 255 && utf8.ValidString(key) && !strings.ContainsRune(key, 0)
}

// GenerateOneTimeToken creates a short-lived transfer credential for the
// caller's active session. A token a verification create hook declines is
// still returned, but was never stored, so it cannot be redeemed; a hook that
// should fail the call returns an APIError.
func (a *Auth) GenerateOneTimeToken(ctx context.Context, h http.Header) (string, error) {
	return a.generateOneTimeToken(ctx, h, nil)
}

func (a *Auth) generateOneTimeToken(ctx context.Context, h http.Header, request *http.Request) (string, error) {
	opts := a.oneTimeToken
	if opts == nil {
		return "", &APIError{404, "NOT_FOUND", "One-time token plugin is not enabled"}
	}
	session, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return "", err
	}
	if request != nil && opts.DisableClientRequest {
		return "", &APIError{400, "BAD_REQUEST", "Client requests are disabled"}
	}
	return a.newOneTimeToken(ctx, opts, *session, request)
}
func (a *Auth) newOneTimeToken(ctx context.Context, opts *OneTimeTokenOptions, session SessionResult, request *http.Request) (string, error) {
	if err := session.Session.RequireOwner(); err != nil {
		return "", err
	}
	var token string
	var err error
	switch {
	case opts.GenerateTokenWithRequest != nil:
		token, err = hostCallback(ctx, "one-time token callback failed", func() (string, error) {
			return opts.GenerateTokenWithRequest(ctx, session, accountObserverRequest(ctx, request))
		})
	case opts.GenerateToken != nil:
		token, err = hostCallback(ctx, "one-time token callback failed", func() (string, error) { return opts.GenerateToken(ctx, session) })
	default:
		token = randomID()
	}
	if err != nil {
		return "", err
	}
	if token == "" || len(token) > maxBodyBytes || !utf8.ValidString(token) || !httpguts.ValidHeaderFieldValue(token) || strings.TrimSpace(token) != token {
		return "", errors.New("invalid generated one-time token")
	}
	key, err := opts.storedKey(ctx, token)
	if err != nil {
		return "", err
	}
	if key, err = a.verificationKey(ctx, oneTimeTokenPrefix, key); err != nil {
		return "", err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(opts.ExpiresIn)
	// A token a create hook declines is still returned, as an unusable one:
	// it was never stored, so it redeems nothing.
	if _, err := a.createVerification(ctx, oneTimeTokenRecord(key, session.Session.UserID, expires), func() error {
		return a.opts.Store.(OneTimeTokenStore).SaveOneTimeToken(ctx, key, session.Session, now, expires)
	}); err != nil {
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
	if token == "" || len(token) > maxBodyBytes || !utf8.ValidString(token) || (opts.HashToken == nil && !opts.HashTokens && !validTransferKey(token)) {
		return nil, &APIError{400, "BAD_REQUEST", "Invalid token"}
	}
	key, err := opts.storedKey(ctx, token)
	if err != nil {
		return nil, err
	}
	if key, err = a.verificationKey(ctx, oneTimeTokenPrefix, key); err != nil {
		return nil, err
	}
	store := a.opts.Store.(OneTimeTokenStore)
	find := func() (VerificationRecord, error) {
		finder, ok := store.(OneTimeTokenFinder)
		if !ok {
			return VerificationRecord{}, ErrNotFound
		}
		userID, expires, err := finder.FindOneTimeToken(ctx, key, a.now().UTC())
		return oneTimeTokenRecord(key, userID, expires), err
	}
	var s SessionResult
	// A token whose session has ended or expired is spent all the same, so
	// its after hooks run before the refusal.
	var denied error
	refused, err := a.spendVerification(ctx, find, func() (err error) {
		// A fresh time, so slow before hooks cannot extend the token's life.
		s, err = store.ConsumeOneTimeToken(ctx, key, a.now().UTC())
		if errors.Is(err, ErrTransferSessionExpired) || errors.Is(err, ErrTransferSessionMissing) {
			denied, err = err, nil
		}
		return err
	})
	switch {
	case err != nil:
		return nil, err
	case refused:
		return nil, &APIError{400, "BAD_REQUEST", "Invalid token"}
	case errors.Is(denied, ErrTransferSessionExpired):
		return nil, &APIError{400, "BAD_REQUEST", "Session expired"}
	case denied != nil:
		return nil, &APIError{400, "BAD_REQUEST", "Session not found"}
	}
	return a.withSessionPlugins(ctx, s.Session, s.User)
}

func (a *Auth) addOneTimeTokenHeader(headers http.Header, r *http.Request, token string) {
	opts := a.oneTimeToken
	if opts == nil || !opts.SetHeaderOnNewSession {
		return
	}
	// Bind to the published session. The incoming cookie can identify a different account.
	row, u, err := a.opts.Store.Session(r.Context(), token)
	if err != nil {
		a.Logger().ErrorContext(r.Context(), "Could not resolve the published session for token transfer")
		return
	}
	session, err := a.withSessionPlugins(r.Context(), row.Session, u)
	if err != nil {
		a.Logger().ErrorContext(r.Context(), "Could not read the published session for token transfer")
		return
	}
	transfer, err := a.newOneTimeToken(r.Context(), opts, *session, r)
	if err != nil {
		a.Logger().ErrorContext(r.Context(), "Could not issue an optional one-time token header")
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
