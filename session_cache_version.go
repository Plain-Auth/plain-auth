package stonewrit

import (
	"context"
	"errors"
	"net/http"
)

var errSessionCacheVersionChanged = errors.New("auth: browser session cache version changed")

func (o *SessionCookieCacheOptions) versionFor(ctx context.Context, data SessionResult) (version string, err error) {
	if o.VersionFor == nil {
		return o.Version, nil
	}
	// Core profiles can contain an optional image pointer. Keep callback inputs
	// independent of the profile we store or return to the caller.
	u := data.User
	if u.Image != nil {
		image := *u.Image
		u.Image = &image
	}
	defer func() {
		if recover() != nil {
			version, err = "", errors.New("auth: session cache version callback panicked")
		}
	}()
	return o.VersionFor(ctx, data.Session, u)
}

func sessionVersionReadError(err error) error {
	var public *APIError
	if errors.As(err, &public) {
		return err
	}
	return errors.Join(&APIError{500, "FAILED_TO_GET_SESSION", "Failed to get session"}, err)
}

func sessionVersionIssueError(err error) error {
	var public *APIError
	if errors.As(err, &public) {
		return err
	}
	return errors.Join(StatusOnlyError(http.StatusInternalServerError), err)
}

type signupCacheKey struct{}

type signupCacheVersion struct {
	input   versionInput
	version string
}

// Only ordinary profiles reach this point. Normalize temporal locations and the
// optional image so equality compares the values the callback actually saw.
type versionInput struct {
	session  Session
	user     User
	image    string
	hasImage bool
}

func signupVersionInput(data SessionResult) versionInput {
	s, u := data.Session, data.User
	s.CreatedAt, s.UpdatedAt, s.ExpiresAt = s.CreatedAt.UTC(), s.UpdatedAt.UTC(), s.ExpiresAt.UTC()
	u.CreatedAt, u.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	key := versionInput{session: s, user: u}
	if u.Image != nil {
		key.image, key.hasImage, key.user.Image = *u.Image, true, nil
	}
	return key
}

// Registration commits the account, password, and first session together.
// Compute the version before that commit. The cookie writer rechecks storage
// and uses this version only for the same resulting session and owner.
func (a *Auth) browserSignUpEmail(r *http.Request, in SignUpInput, meta RequestMeta) (AuthResult, *http.Request, error) {
	cache := a.opts.SessionCookieCache
	if cache == nil || cache.VersionFor == nil || a.opts.RequireEmailVerification || a.opts.DisableAutoSignIn || !a.canCacheSessionView(r) {
		result, err := a.signUpEmail(r.Context(), in, meta, r, nil)
		return result, r, err
	}
	prepared := signupCacheVersion{}
	result, err := a.signUpEmail(r.Context(), in, meta, r, func(data SessionResult) error {
		// Preserve the registration response for existing users even if the
		// host's version source is down. CreateUser still resolves any race.
		var lookupErr error
		if accounts, ok := a.opts.Store.(signUpUserFinder); ok {
			_, lookupErr = accounts.FindAccountUser(r.Context(), data.User.Email)
		} else {
			_, _, lookupErr = a.opts.Store.Credential(r.Context(), data.User.Email)
		}
		if lookupErr == nil {
			return duplicateSignupError()
		}
		if !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if !ordinaryCacheFields(data.Session, data.User) {
			return nil
		}
		version, err := cache.versionFor(r.Context(), data)
		if err != nil {
			return sessionVersionIssueError(err)
		}
		prepared = signupCacheVersion{input: signupVersionInput(data), version: version}
		return nil
	})
	if err == nil && prepared.input.session.Token != "" {
		r = r.WithContext(context.WithValue(r.Context(), signupCacheKey{}, prepared))
	}
	return result, r, err
}
