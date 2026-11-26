package plainauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"
)

type AnonymousOptions struct {
	EmailDomainName            string
	GenerateRandomEmail        func(context.Context) (string, error)
	GenerateName               func(context.Context, *http.Request) (string, error)
	OnLinkAccount              func(context.Context, AnonymousLink) error
	DisableDeleteAnonymousUser bool
}

// AnonymousLink is delivered when a live guest session becomes a verified
// permanent session. SQL callbacks can transfer application records with Tx.
type AnonymousLink struct {
	AnonymousUser, NewUser SessionResult
	Request                *http.Request
	Tx                     *sql.Tx
}

type AnonymousStore interface {
	CheckAnonymousSchema(context.Context) error
	IsAnonymous(ctx context.Context, userID string) (bool, error)
	CreateAnonymous(ctx context.Context, user User, session StoredSession) error
	// DeleteAnonymous removes the guest's user, its sessions and its other
	// account rows together; when it returns an error it has removed
	// nothing. It returns ErrNotAnonymous when the user is not a guest, and
	// ErrNotFound when the session is no longer live or not the user's.
	DeleteAnonymous(ctx context.Context, userID, token string, now time.Time) error
	LinkAnonymous(ctx context.Context, sourceToken, targetToken string, now time.Time, retain bool, callback func(context.Context, AnonymousLink) error) error
}

var ErrNotAnonymous = errors.New("user is not anonymous")

func NewAnonymous(o AnonymousOptions) (Plugin, error) {
	if o.EmailDomainName != "" && (!emailPattern.MatchString("temp@"+o.EmailDomainName) || strings.ContainsAny(o.EmailDomainName, "@ /\\") || strings.Contains(o.EmailDomainName, "..")) {
		return Plugin{}, errors.New("authn: invalid anonymous email domain")
	}
	return Plugin{ID: "anonymous", StoredUserFields: map[string]UserField{"isAnonymous": {Type: FieldBoolean}}, anonymous: &o, ValidateStore: func(s Store) error {
		db, ok := s.(AnonymousStore)
		if !ok {
			return errors.New("authn: anonymous sign-in requires an AnonymousStore")
		}
		return db.CheckAnonymousSchema(context.Background())
	},
		Endpoints: []Endpoint{
			{Method: "POST", Path: "/sign-in/anonymous", Handler: o.signIn},
			{Method: "POST", Path: "/delete-anonymous-user", Handler: o.delete},
		}}, nil
}

func (o AnonymousOptions) signIn(c EndpointContext) (any, error) {
	ctx, a := c.Request.Context(), c.Auth
	current, err := a.GetSession(ctx, c.Request.Header)
	if err != nil {
		return nil, err
	}
	if current != nil && current.User.IsAnonymous != nil && *current.User.IsAnonymous {
		return nil, &APIError{400, "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY", "Anonymous users cannot sign in again anonymously"}
	}
	if a.opts.DisableSignUp {
		return nil, &APIError{403, "SIGN_UP_DISABLED", "Sign-up is disabled"}
	}
	email := ""
	if o.GenerateRandomEmail != nil {
		email, err = o.GenerateRandomEmail(ctx)
		if err != nil {
			return nil, err
		}
	}
	if email == "" {
		if o.EmailDomainName != "" {
			email = "temp-" + randomID() + "@" + o.EmailDomainName
		} else {
			email = randomID() + "@anonymous.placeholder.invalid"
		}
	}
	email = strings.ToLower(email)
	if !emailPattern.MatchString(email) || len(email) > 254 || strings.Contains(email, "..") {
		return nil, &APIError{400, "INVALID_EMAIL_FORMAT", "Email was not generated in a valid format"}
	}
	name := ""
	if o.GenerateName != nil {
		name, err = o.GenerateName(ctx, c.Request)
		if err != nil {
			return nil, err
		}
	}
	if name == "" {
		name = "Anonymous"
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	flag := true
	u := User{ID: randomID(), Name: name, Email: email, IsAnonymous: &flag, CreatedAt: now, UpdatedAt: now}
	if a.admin != nil {
		u.AdminUserFields = &AdminUserFields{Role: a.admin.DefaultRole}
	}
	if a.factorStore != nil {
		enabled := false
		u.TwoFactorEnabled = &enabled
	}
	ss, _ := a.newSession(u.ID, RequestMeta{IPAddress: a.clientIP(c.Request), UserAgent: c.Request.UserAgent()})
	if err := a.ValidateUserInfo(ctx, UserInfoValidation{Action: UserInfoCreateUser, Method: "anonymous", User: UserRecord{User: u}, Request: c.Request}); err != nil {
		return nil, err
	}
	u, userFields, err := a.beforeUserCreate(ctx, u, nil)
	if errors.Is(err, ErrSkipWrite) {
		return nil, &APIError{500, "FAILED_TO_CREATE_USER", "Failed to create user"}
	}
	if err == nil && len(userFields) > 0 {
		// Guest accounts store no additional user fields.
		err = errDatabaseHookEdit
	}
	if err != nil {
		return nil, err
	}
	ss, sessionFields, err := a.beforeSessionCreate(ctx, ss, nil, &APIError{400, "COULD_NOT_CREATE_SESSION", "Could not create session"})
	if err != nil {
		return nil, err
	}
	if err := c.Store().(AnonymousStore).CreateAnonymous(ctx, u, ss); err != nil {
		return nil, err
	}
	if err := a.afterUserCreate(ctx, u, userFields); err != nil {
		return nil, a.discardUnpublishedSession(ctx, ss.Token, err)
	}
	if err := a.afterSessionCreate(ctx, ss, sessionFields); err != nil {
		return nil, err
	}
	if err := a.addSessionCookieHeaders(c.ResponseHeader, c.Request, ss.Token, true); err != nil {
		return nil, err
	}
	return AuthResult{User: u, Token: ss.Token}, nil
}

func (o AnonymousOptions) delete(c EndpointContext) (any, error) {
	current, err := c.Auth.requireSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if o.DisableDeleteAnonymousUser {
		return nil, &APIError{400, "DELETE_ANONYMOUS_USER_DISABLED", "Deleting anonymous users is disabled"}
	}
	ctx := c.Request.Context()
	switch err = c.Store().(AnonymousStore).DeleteAnonymous(ctx, current.User.ID, current.Session.Token, c.Auth.now()); {
	case errors.Is(err, ErrNotAnonymous):
		return nil, &APIError{403, "USER_IS_NOT_ANONYMOUS", "User is not anonymous"}
	case errors.Is(err, ErrNotFound):
		return nil, &APIError{401, "UNAUTHORIZED", "Unauthorized"}
	case err != nil:
		// The store deletes the guest's sessions and user in one call, so a
		// failure leaves the guest whole and signed in: there is no separate
		// answer for sessions deleted ahead of a user that could not be.
		c.Auth.Logger().ErrorContext(ctx, "Failed to delete anonymous user", "error", err)
		return nil, errors.Join(&APIError{500, "FAILED_TO_DELETE_ANONYMOUS_USER", "Failed to delete anonymous user"}, err)
	}
	c.Auth.expireSessionCookieHeaders(c.ResponseHeader, c.Request)
	return map[string]bool{"success": true}, nil
}

type anonymousSourceKey struct{}

func (a *Auth) guestToken(r *http.Request) (string, error) {
	if a.anonymous == nil {
		return "", nil
	}
	s, err := a.GetSession(r.Context(), r.Header)
	if err != nil {
		return "", err
	}
	if s == nil || s.User.IsAnonymous == nil || !*s.User.IsAnonymous {
		return "", nil
	}
	return s.Session.Token, nil
}

func (a *Auth) finishAnonymous(r *http.Request, target string) error {
	if a.anonymous == nil {
		return nil
	}
	route := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(a.opts.BasePath, "/"))
	switch {
	case route == "/sign-in/anonymous":
		return nil
	case strings.HasPrefix(route, "/sign-in/"), strings.HasPrefix(route, "/sign-up/"), strings.HasPrefix(route, "/callback/"), strings.HasPrefix(route, "/two-factor/verify-"):
	case route == "/sso/callback", strings.HasPrefix(route, "/sso/callback/"), route == "/magic-link/verify", route == "/email-otp/verify-email", route == "/one-tap/callback", route == "/passkey/verify-authentication", route == "/verify-email":
	default:
		return nil
	}
	source, _ := r.Context().Value(anonymousSourceKey{}).(string)
	if source == "" {
		source = a.cookieToken(r.Header)
	}
	if source == "" || source == target {
		return nil
	}
	var callback func(context.Context, AnonymousLink) error
	if a.anonymous.OnLinkAccount != nil {
		callback = func(ctx context.Context, e AnonymousLink) error {
			e.Request = r
			return a.anonymous.OnLinkAccount(ctx, e)
		}
	}
	err := a.opts.Store.(AnonymousStore).LinkAnonymous(r.Context(), source, target, a.now(), a.anonymous.DisableDeleteAnonymousUser, callback)
	if err != nil {
		// This is a newly issued session. Keep the browser's original guest
		// identity and prevent the unused target token from remaining active.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		return errors.Join(err, a.opts.Store.DeleteSession(ctx, target))
	}
	return nil
}

func (a *Auth) readGuestFlag(ctx context.Context, u *User) error {
	if a.anonymous == nil || u.ID == "" {
		return nil
	}
	flag, err := a.opts.Store.(AnonymousStore).IsAnonymous(ctx, u.ID)
	if err == nil {
		u.IsAnonymous = &flag
	}
	return err
}

// revokeGuestContinuation cancels the original guest session when a browser
// signs out during an MFA challenge that temporarily cleared its main cookie.
func (a *Auth) revokeGuestContinuation(ctx context.Context, h http.Header) error {
	if a.anonymous == nil || a.factorOptions == nil {
		return nil
	}
	r := http.Request{Header: h}
	f, err := r.Cookie(a.factorCookie("", 0).Name)
	if err != nil {
		return nil
	}
	challenge := a.VerifySignedSessionToken(f.Value)
	if !strings.HasPrefix(challenge, "2fa-") {
		return nil
	}
	c, err := r.Cookie(a.oauthCookie("guest_continuation", "", 0).Name)
	if err != nil {
		return nil
	}
	source, err := a.openRecord("guest-mfa:"+challenge, c.Value)
	if err != nil {
		return nil
	}
	return a.opts.Store.DeleteSession(ctx, string(source))
}
