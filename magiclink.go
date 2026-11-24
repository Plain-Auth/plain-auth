package plainauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MagicLinkMessage contains private authentication material for delivery to Email.
type MagicLinkMessage struct {
	Email, URL, Token string
	Metadata          map[string]any
	// Request contains independent HTTP request metadata for the delivery callback.
	// It is excluded when serializing the message for an email queue.
	Request *http.Request `json:"-"`
}

// MagicLinkOptions configures delivery, token storage and registration.
type MagicLinkOptions struct {
	Send          func(context.Context, MagicLinkMessage) error
	ExpiresIn     time.Duration
	DisableSignUp bool
	HashTokens    bool
	HashToken     func(context.Context, string) (string, error)
	GenerateToken func(ctx context.Context, email string) (string, error)
	RateLimit     *RateLimitRule
}

// MagicLinkChallenge describes a mailbox proof under a purpose-specific key.
// Key is the stored token representation, without its database namespace.
type MagicLinkChallenge struct {
	Key, Email, Name     string
	CreatedAt, ExpiresAt time.Time
}

// MagicLinkStore consumes a mailbox proof atomically with user promotion and session creation.
type MagicLinkStore interface {
	SaveMagicLink(context.Context, MagicLinkChallenge) error
	CompleteMagicLink(ctx context.Context, key, newUserID string, session StoredSession, allowSignUp bool) (User, bool, error)
}

// MagicLinkUserFieldStore writes registration defaults in the transaction
// that proves mailbox ownership and creates the first session. Existing users
// keep their stored values, including when a required field has no default.
type MagicLinkUserFieldStore interface {
	CompleteMagicLinkWithUserFields(ctx context.Context, key, newUserID string, session StoredSession, defaults RegistrationUserFields) (User, bool, error)
}

var ErrMagicLinkSignUpDisabled = errors.New("magic link registration disabled")

// NewMagicLink registers mail delivery and one-time mailbox verification endpoints.
func NewMagicLink(options MagicLinkOptions) (Plugin, error) {
	if options.Send == nil {
		return Plugin{}, errors.New("magic link requires a mail sender")
	}
	if options.ExpiresIn < 0 {
		return Plugin{}, errors.New("magic link lifetime must be positive")
	}
	if options.ExpiresIn == 0 {
		options.ExpiresIn = 5 * time.Minute
	}
	if options.HashTokens && options.HashToken != nil {
		return Plugin{}, errors.New("choose one magic link token hasher")
	}
	rule := RateLimitRule{Max: 5, Window: time.Minute}
	if options.RateLimit != nil {
		rule = *options.RateLimit
	}
	if rule.Max < 1 || rule.Window <= 0 {
		return Plugin{}, errors.New("invalid magic link rate limit")
	}
	return Plugin{
		ID: "magic-link", magicLinkRegistration: !options.DisableSignUp,
		ValidateStore: func(s Store) error {
			if _, ok := s.(MagicLinkStore); !ok {
				return errors.New("magic link requires a MagicLinkStore")
			}
			return nil
		},
		Endpoints: []Endpoint{
			{Method: http.MethodPost, Path: "/sign-in/magic-link", Handler: options.request, RateLimit: &rule},
			{Method: http.MethodGet, Path: "/magic-link/verify", Handler: options.verify, RateLimit: &rule},
		},
	}, nil
}

func (o MagicLinkOptions) storedKey(ctx context.Context, token string) (string, error) {
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
	if len(key) == 0 || len(key) > 240 {
		return "", errors.New("invalid magic link storage key")
	}
	return key, nil
}

func (o MagicLinkOptions) request(c EndpointContext) (any, error) {
	a, ctx := c.Auth, c.Request.Context()
	email, err := requiredString(c.Body, "email")
	if err != nil {
		return nil, err
	}
	if len(email) > 254 || !emailPattern.MatchString(email) || strings.Contains(email, "..") {
		return nil, validationError("[body.email] Invalid email address")
	}
	name := ""
	if v, ok := c.Body["name"]; ok {
		var valid bool
		name, valid = v.(string)
		if !valid || len([]rune(name)) > 255 {
			return nil, validationError("[body.name] Invalid name")
		}
	}
	var metadata map[string]any
	if v, ok := c.Body["metadata"]; ok {
		var valid bool
		metadata, valid = v.(map[string]any)
		if !valid {
			return nil, validationError("[body.metadata] Invalid metadata")
		}
	}
	token := randomID()
	if o.GenerateToken != nil {
		token, err = o.GenerateToken(ctx, email)
		if err != nil {
			return nil, err
		}
	}
	if token == "" || len(token) > 240 {
		return nil, errors.New("invalid generated magic link token")
	}
	key, err := o.storedKey(ctx, token)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	ch := MagicLinkChallenge{Key: key, Email: strings.ToLower(email), Name: name, CreatedAt: now, ExpiresAt: now.Add(o.ExpiresIn)}
	if err := a.opts.Store.(MagicLinkStore).SaveMagicLink(ctx, ch); err != nil {
		return nil, err
	}
	q := url.Values{"token": {token}, "callbackURL": {"/"}}
	for _, key := range []string{"callbackURL", "newUserCallbackURL", "errorCallbackURL"} {
		if v, ok := c.Body[key].(string); ok && v != "" {
			q.Set(key, v)
		}
	}
	link := a.opts.BaseURL + strings.TrimRight(a.opts.BasePath, "/") + "/magic-link/verify?" + q.Encode()
	if err := o.Send(ctx, MagicLinkMessage{Email: ch.Email, Token: token, URL: link, Metadata: metadata, Request: accountObserverRequest(ctx, c.Request)}); err != nil {
		return nil, err
	}
	return map[string]bool{"status": true}, nil
}

func (o MagicLinkOptions) verify(c EndpointContext) (any, error) {
	a, r := c.Auth, c.Request
	c.ResponseHeader.Set("Referrer-Policy", "no-referrer")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, validationError("Invalid verification query")
	}
	callbacks := wireBody{}
	for _, field := range []string{"token", "callbackURL", "newUserCallbackURL", "errorCallbackURL"} {
		values := q[field]
		if len(values) > 1 {
			return nil, validationError("Duplicate " + field)
		}
		if field != "token" && len(values) == 1 {
			callbacks[field] = values[0]
		}
	}
	if err := a.validateCallbacks(callbacks, nil); err != nil {
		return nil, err
	}
	callback, err := a.CallbackURL(q.Get("callbackURL"))
	if err != nil {
		return nil, err
	}
	errorURL := callback
	if raw := q.Get("errorCallbackURL"); raw != "" {
		errorURL, err = a.CallbackURL(raw)
		if err != nil {
			return nil, err
		}
	}
	token := q.Get("token")
	if token == "" || len(token) > 240 {
		return redirectQuery(errorURL, "error", "INVALID_TOKEN"), nil
	}
	session, _ := a.newSession("", RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()})
	key, err := o.storedKey(r.Context(), token)
	if err != nil {
		return nil, err
	}
	var user User
	var created bool
	newUserID := randomID()
	var gate *signInGate
	if !o.DisableSignUp {
		gate = &signInGate{method: "magic-link"}
	}
	err = a.planSignIn(r.Context(), gate, func(ctx context.Context) (err error) {
		if !o.DisableSignUp && len(a.opts.UserAdditionalFields) > 0 {
			store := a.opts.Store.(MagicLinkUserFieldStore)
			user, created, err = store.CompleteMagicLinkWithUserFields(ctx, key, newUserID, session, a.registrationUserFields())
		} else {
			user, created, err = a.opts.Store.(MagicLinkStore).CompleteMagicLink(ctx, key, newUserID, session, !o.DisableSignUp)
		}
		return err
	})
	if errors.Is(err, errPlannedUserSkipped) {
		return redirectQuery(errorURL, "error", "failed_to_create_user"), nil
	}
	if errors.Is(err, errPlannedSessionSkipped) {
		return redirectQuery(errorURL, "error", "failed_to_create_session"), nil
	}
	var refused *APIError
	if errors.As(err, &refused) && refused.Code != "" {
		// A hook's refusal returns the browser to the error page, as in the reference.
		target := redirectQuery(errorURL, "error", refused.Code)
		return redirectQuery(string(target), "error_description", refused.Message), nil
	}
	if errors.Is(err, ErrNotFound) {
		return redirectQuery(errorURL, "error", "INVALID_TOKEN"), nil
	}
	if errors.Is(err, ErrMagicLinkSignUpDisabled) {
		return redirectQuery(errorURL, "error", "new_user_signup_disabled"), nil
	}
	if err == nil {
		err = a.afterDecidedSignIn(r.Context(), user, created, session.Token)
	}
	if err != nil {
		return nil, err
	}
	session.UserID = user.ID
	if len(a.dbHooks.session.create.before) > 0 {
		// Return the session as the hooks left it.
		if stored, _, err := a.opts.Store.Session(r.Context(), session.Token); err == nil {
			stored.Token = session.Token
			session.Session = stored.Session
		}
	}
	// A profile read or plugin may reject the public session after the database
	// has consumed the proof. Publish credentials only with a successful response.
	issued := c.ResponseHeader.Clone()
	if err := a.addSessionCookieHeaders(issued, r, session.Token, true); err != nil {
		return nil, err
	}
	var output any = Redirect(callback)
	if q.Get("callbackURL") == "" {
		result, err := a.withSessionPlugins(r.Context(), session.Session, user)
		if err != nil {
			return nil, err
		}
		output = struct {
			*SessionResult
			Token string `json:"token"`
		}{result, session.Token}
	} else if created && q.Get("newUserCallbackURL") != "" {
		callback, err = a.CallbackURL(q.Get("newUserCallbackURL"))
		if err != nil {
			return nil, err
		}
		output = Redirect(callback)
	}
	clear(c.ResponseHeader)
	maps.Copy(c.ResponseHeader, issued)
	return output, nil
}
