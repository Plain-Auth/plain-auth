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
// Key is the stored token representation, after MagicLinkOptions.HashTokens
// or HashToken and then Options.StoreVerificationIdentifier, without its
// database namespace.
type MagicLinkChallenge struct {
	Key, Email, Name     string
	CreatedAt, ExpiresAt time.Time
}

// MagicLinkStore consumes a mailbox proof atomically with user promotion and session creation.
// CompleteMagicLink and CompleteMagicLinkWithUserFields spend the link when
// they sign in, and when they refuse a new address with
// ErrMagicLinkSignUpDisabled or with the error of defaults.Columns.
// Verification delete hooks rely on this.
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

// MagicLinkFinder reads a magic link without spending it, for verification
// delete hooks. It returns the Key, Email, Name and ExpiresAt of the newest
// well-formed link stored under key that is live at now. It judges only the
// stored row: a link whose address another account now owns is still found,
// and CompleteMagicLink refuses it. Anything else is ErrNotFound.
type MagicLinkFinder interface {
	FindMagicLink(ctx context.Context, key string, now time.Time) (MagicLinkChallenge, error)
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
	// A generated token is capped at 240 bytes, the room a raw stored key
	// has in the verification identifier. The other runtime sets no cap.
	if token == "" || len(token) > 240 {
		return nil, errors.New("invalid generated magic link token")
	}
	key, err := o.storedKey(ctx, token)
	if err != nil {
		return nil, err
	}
	if key, err = a.verificationKey(ctx, magicLinkPrefix, key); err != nil {
		return nil, err
	}
	q := url.Values{"token": {token}, "callbackURL": {"/"}}
	for _, field := range []string{"callbackURL", "newUserCallbackURL", "errorCallbackURL"} {
		if v, ok := c.Body[field].(string); ok && v != "" {
			q.Set(field, v)
		}
	}
	base, err := a.publicURL(ctx)
	if err != nil {
		return nil, err
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	// The address is stored and delivered in lower case, as accounts match
	// it. GenerateToken above receives it as the request sent it.
	ch := MagicLinkChallenge{Key: key, Email: strings.ToLower(email), Name: name, CreatedAt: now, ExpiresAt: now.Add(o.ExpiresIn)}
	// A declined link answers as a sent one, with nothing stored or mailed.
	declined, err := a.createVerification(ctx, magicLinkRecord(key, ch.ExpiresAt), func() error {
		return a.opts.Store.(MagicLinkStore).SaveMagicLink(ctx, ch)
	})
	if err != nil {
		return nil, err
	}
	if !declined {
		link := base + "/magic-link/verify?" + q.Encode()
		if err := o.Send(ctx, MagicLinkMessage{Email: ch.Email, Token: token, URL: link, Metadata: metadata, Request: accountObserverRequest(ctx, c.Request)}); err != nil {
			return nil, err
		}
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
	if err := a.validateCallbacks(r.Context(), callbacks, nil); err != nil {
		return nil, err
	}
	callback, err := a.callbackURL(r.Context(), q.Get("callbackURL"))
	if err != nil {
		return nil, err
	}
	errorURL := callback
	if raw := q.Get("errorCallbackURL"); raw != "" {
		errorURL, err = a.callbackURL(r.Context(), raw)
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
	if key, err = a.verificationKey(r.Context(), magicLinkPrefix, key); err != nil {
		return nil, err
	}
	// The link's delete before hooks run first, on a read that does not
	// spend it, at the time the sign-in judges its expiry.
	spent, refusedSpend, err := a.beforeSpendVerification(r.Context(), func() (VerificationRecord, error) {
		finder, ok := a.opts.Store.(MagicLinkFinder)
		if !ok {
			return VerificationRecord{}, ErrNotFound
		}
		link, err := finder.FindMagicLink(r.Context(), key, session.CreatedAt)
		return magicLinkRecord(key, link.ExpiresAt), err
	})
	if err != nil {
		return nil, err
	}
	if refusedSpend {
		// A declined spend keeps the link usable.
		return redirectQuery(errorURL, "error", "INVALID_TOKEN"), nil
	}
	var user User
	var created bool
	newUserID := randomID()
	var gate *signInGate
	if !o.DisableSignUp {
		gate = &signInGate{method: "magic-link"}
	}
	withFields := !o.DisableSignUp && len(a.opts.UserAdditionalFields) > 0
	var defaults RegistrationUserFields
	if withFields {
		defaults = a.registrationUserFields()
	}
	// spentLink reports that the store's last run spent the link: it signed
	// in, or refused a new address because sign-up is closed or a
	// registration default is missing. A hook's error never sets it.
	var spentLink bool
	err = a.planSignIn(r.Context(), gate, func(ctx context.Context) (err error) {
		if withFields {
			user, created, err = a.opts.Store.(MagicLinkUserFieldStore).CompleteMagicLinkWithUserFields(ctx, key, newUserID, session, defaults)
		} else {
			user, created, err = a.opts.Store.(MagicLinkStore).CompleteMagicLink(ctx, key, newUserID, session, !o.DisableSignUp)
		}
		spentLink = err == nil || errors.Is(err, ErrMagicLinkSignUpDisabled) || defaults.err != nil && errors.Is(err, defaults.err)
		return err
	})
	// The link's after hooks run before the user's and session's. Their
	// error, or a spend the before hooks never saw, is never read as a
	// refusal.
	if spentLink {
		unseen, hookErr := a.afterSpendVerification(r.Context(), spent)
		if (unseen || hookErr != nil) && err == nil {
			hookErr = a.discardUnpublishedSession(r.Context(), session.Token, hookErr)
		}
		switch {
		case hookErr != nil:
			return nil, hookErr
		case unseen:
			return redirectQuery(errorURL, "error", "INVALID_TOKEN"), nil
		}
	}
	if errors.Is(err, errPlannedUserSkipped) {
		return redirectQuery(errorURL, "error", "failed_to_create_user"), nil
	}
	if errors.Is(err, errPlannedSessionSkipped) {
		return redirectQuery(errorURL, "error", "failed_to_create_session"), nil
	}
	var refused *APIError
	if errors.As(err, &refused) && refused.Code != "" {
		// A user or session hook's refusal, or ValidateUserInfo's, returns
		// the browser to the error page, as in the reference.
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
		callback, err = a.callbackURL(r.Context(), q.Get("newUserCallbackURL"))
		if err != nil {
			return nil, err
		}
		output = Redirect(callback)
	}
	// A profile read or plugin may reject the public session after the
	// database has consumed the proof. Publish credentials, and mint any
	// Set-Ott token, only once the response is built.
	issued := c.ResponseHeader.Clone()
	if err := a.addSessionCookieHeaders(issued, r, session.Token, true); err != nil {
		return nil, err
	}
	clear(c.ResponseHeader)
	maps.Copy(c.ResponseHeader, issued)
	return output, nil
}
