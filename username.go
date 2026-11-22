package plainauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf16"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// UsernameFields preserves the distinction between an optional public name and a disabled plugin.
type UsernameFields struct {
	Username *string `json:"username"`
	*DisplayUsernameFields
}

type DisplayUsernameFields struct {
	DisplayUsername *string `json:"displayUsername"`
}

type UsernameOptions struct {
	MinLength, MaxLength                                                 int
	Validate, ValidateDisplay                                            func(context.Context, string) bool
	Normalize, NormalizeDisplay                                          func(string) string
	DisableNormalization, DisableDisplay, Immutable, DisableAvailability bool
	ValidateAfterNormalization, ValidateDisplayAfterNormalization        bool
}

type UsernameStore interface {
	CheckUsernameSchema(context.Context, bool) error
	UpdateUsernameProfile(context.Context, string, string, ProfileUpdate, time.Time, bool) error
	UsernameExists(context.Context, string) (bool, error)
	UsernameCredential(context.Context, string) (User, string, error)
	ReadUsername(context.Context, string, bool) (*UsernameFields, error)
}

var defaultUsername = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)
var ErrUsernameTaken = errors.New("plainauth: username already taken")
var ErrUsernameImmutable = errors.New("plainauth: username is immutable")

func NewUsername(options UsernameOptions) (Plugin, error) {
	if options.MinLength == 0 {
		options.MinLength = 3
	}
	if options.MaxLength == 0 {
		options.MaxLength = 30
	}
	if options.MinLength < 1 || options.MaxLength < options.MinLength || options.DisableNormalization && options.Normalize != nil {
		return Plugin{}, errors.New("plainauth: invalid username configuration")
	}
	p := Plugin{ID: "username", username: &options, ValidateStore: func(s Store) error {
		db, ok := s.(UsernameStore)
		if !ok {
			return errors.New("plainauth: username requires a UsernameStore")
		}
		return db.CheckUsernameSchema(context.Background(), !options.DisableDisplay)
	}}
	p.Endpoints = []Endpoint{
		{Method: http.MethodPost, Path: "/sign-in/username", Handler: func(c EndpointContext) (any, error) { return c.Auth.usernameLoginHTTP(c) }},
	}
	if !options.DisableAvailability {
		p.Endpoints = append(p.Endpoints, Endpoint{Method: http.MethodPost, Path: "/is-username-available", Handler: func(c EndpointContext) (any, error) {
			name, err := requiredString(c.Body, "username")
			if err != nil {
				return nil, err
			}
			available, err := c.Auth.IsUsernameAvailable(c.Request.Context(), name)
			return map[string]bool{"available": available}, err
		}})
	}
	return p, nil
}

func (o *UsernameOptions) normalized(name string) string {
	if o.DisableNormalization {
		return name
	}
	if o.Normalize != nil {
		return o.Normalize(name)
	}
	return cases.Lower(language.Und).String(name)
}

func (o *UsernameOptions) validated(ctx context.Context, input string, status int) (string, error) {
	v := input
	if o.ValidateAfterNormalization {
		v = o.normalized(input)
	}
	var n int
	for _, r := range v {
		n += utf16.RuneLen(r)
	}
	switch {
	case n < o.MinLength:
		return "", &APIError{status, "USERNAME_TOO_SHORT", "Username is too short"}
	case n > o.MaxLength:
		return "", &APIError{status, "USERNAME_TOO_LONG", "Username is too long"}
	case o.Validate != nil && !o.Validate(ctx, v) || o.Validate == nil && !defaultUsername.MatchString(v):
		return "", &APIError{status, "INVALID_USERNAME", "Username is invalid"}
	}
	if o.ValidateAfterNormalization {
		return v, nil
	}
	return o.normalized(input), nil
}

func (o *UsernameOptions) fields(ctx context.Context, username, display *string, signup bool) (*UsernameFields, error) {
	f := &UsernameFields{}
	if username == nil && signup && display != nil {
		if normalized, err := o.validated(ctx, *display, 400); err == nil {
			f.Username = &normalized
		}
	}
	if username != nil {
		normalized, err := o.validated(ctx, *username, 400)
		if err != nil {
			return nil, err
		}
		f.Username = &normalized
	}
	if o.DisableDisplay {
		return f, nil
	}
	f.DisplayUsernameFields = &DisplayUsernameFields{}
	if display != nil {
		value := *display
		if o.ValidateDisplayAfterNormalization && o.NormalizeDisplay != nil {
			value = o.NormalizeDisplay(value)
		}
		if o.ValidateDisplay != nil && !o.ValidateDisplay(ctx, value) {
			return nil, &APIError{400, "INVALID_DISPLAY_USERNAME", "Display username is invalid"}
		}
		if !o.ValidateDisplayAfterNormalization && o.NormalizeDisplay != nil {
			value = o.NormalizeDisplay(value)
		}
		f.DisplayUsername = &value
	}
	// The signup fallback runs after validation of any explicitly supplied display text.
	if signup && (display == nil || *display == "") && username != nil {
		value := *username
		if o.NormalizeDisplay != nil {
			value = o.NormalizeDisplay(value)
		}
		f.DisplayUsername = &value
	}
	return f, nil
}

func usernameWriteError(err error) error {
	switch {
	case errors.Is(err, ErrUsernameTaken):
		return &APIError{400, "USERNAME_IS_ALREADY_TAKEN", "Username is already taken. Please try another."}
	case errors.Is(err, ErrUsernameImmutable):
		return &APIError{400, "USERNAME_IS_IMMUTABLE", "Username cannot be updated"}
	default:
		return err
	}
}

func (a *Auth) IsUsernameAvailable(ctx context.Context, name string) (bool, error) {
	if a.username == nil {
		return false, &APIError{404, "NOT_FOUND", "Not found"}
	}
	if name == "" {
		return false, &APIError{422, "INVALID_USERNAME", "Username is invalid"}
	}
	n, err := a.username.validated(ctx, name, 422)
	if err != nil {
		return false, err
	}
	exists, err := a.opts.Store.(UsernameStore).UsernameExists(ctx, n)
	if err != nil {
		return false, err
	}
	return !exists, nil
}

type UsernameSignInInput struct {
	Username, Password string
	RememberMe         *bool
}

func (a *Auth) SignInUsername(ctx context.Context, in UsernameSignInInput, meta RequestMeta) (AuthResult, error) {
	if a.username == nil {
		return AuthResult{}, &APIError{404, "NOT_FOUND", "Not found"}
	}
	if !a.opts.EmailAndPassword {
		return AuthResult{}, &APIError{400, "EMAIL_PASSWORD_DISABLED", "Email and password is not enabled"}
	}
	denied := &APIError{401, "INVALID_USERNAME_OR_PASSWORD", "Invalid username or password"}
	if in.Username == "" || in.Password == "" {
		return AuthResult{}, denied
	}
	if meta.CallbackURL != "" && !a.trustedURL(meta.CallbackURL, true) {
		return AuthResult{}, &APIError{403, "INVALID_CALLBACK_URL", "Invalid callbackURL"}
	}
	name, err := a.username.validated(ctx, in.Username, 422)
	if err != nil {
		return AuthResult{}, err
	}
	if err := a.validatePasswordLength(in.Password, false); err != nil {
		return AuthResult{}, err
	}
	user, hash, err := a.opts.Store.(UsernameStore).UsernameCredential(ctx, name)
	if in.RememberMe != nil {
		meta.RememberMe = in.RememberMe
	}
	return a.completeCredentialSignIn(ctx, user, hash, err, in.Password, meta, denied)
}

func (a *Auth) readUsername(ctx context.Context, user *User) error {
	if user.ID == "" {
		return nil
	}
	if a.username == nil {
		user.UsernameFields = nil
		return nil
	}
	f, err := a.opts.Store.(UsernameStore).ReadUsername(ctx, user.ID, !a.username.DisableDisplay)
	if err == nil {
		user.UsernameFields = f
	}
	return err
}

func (a *Auth) usernameLoginHTTP(c EndpointContext) (any, error) {
	name, err := requiredString(c.Body, "username")
	if err != nil {
		return nil, err
	}
	password, err := requiredString(c.Body, "password")
	if err != nil {
		return nil, err
	}
	var remember *bool
	if v, ok := c.Body["rememberMe"]; ok {
		value, ok := v.(bool)
		if !ok {
			return nil, fieldTypeError("rememberMe", "boolean", c.Body)
		}
		remember = &value
	}
	callback, _ := c.Body["callbackURL"].(string)
	meta := RequestMeta{IPAddress: a.clientIP(c.Request), UserAgent: c.Request.UserAgent(), RememberMe: remember, CallbackURL: callback}
	if cookie, err := c.Request.Cookie(a.TrustedDeviceCookieName()); err == nil {
		meta.TrustedDeviceCookie = cookie.Value
	}
	res, err := a.SignInUsername(c.Request.Context(), UsernameSignInInput{name, password, remember}, meta)
	if err != nil {
		return nil, err
	}
	return a.writeCredentialResult(c.ResponseHeader, c.Request, c.Body, res, remember, false)
}

func (p ProfileUpdate) hasUsernameChange() bool {
	return p.Username != nil || p.DisplayUsername != nil || p.ClearUsername || p.ClearDisplayUsername
}

func usernamePatch(body map[string]any) (ProfileUpdate, error) {
	var p ProfileUpdate
	read := func(field string, dest **string, clear *bool) error {
		v, ok := body[field]
		if !ok {
			return nil
		}
		if v == nil {
			*clear = true
			return nil
		}
		text, err := requiredString(body, field)
		if err == nil {
			*dest = &text
		}
		return err
	}
	if err := read("username", &p.Username, &p.ClearUsername); err != nil {
		return p, err
	}
	err := read("displayUsername", &p.DisplayUsername, &p.ClearDisplayUsername)
	return p, err
}

func usernameInput(body map[string]any) (*string, *string, error) {
	value := func(field string) (*string, error) {
		if _, exists := body[field]; !exists {
			return nil, nil
		}
		v, err := requiredString(body, field)
		if err != nil {
			return nil, err
		}
		return &v, nil
	}
	username, err := value("username")
	if err != nil {
		return nil, nil, err
	}
	display, err := value("displayUsername")
	return username, display, err
}

// readPublicUserFields fills fields from optional plugins after an authentication
// method has retrieved its core profile. A pending challenge has no public user.
func (a *Auth) readPublicUserFields(ctx context.Context, user *User) error {
	if err := a.readPhone(ctx, user); err != nil {
		return err
	}
	if err := a.readGuestFlag(ctx, user); err != nil {
		return err
	}
	return a.readUsername(ctx, user)
}
