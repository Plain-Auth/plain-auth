package plainauth

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
)

// UserInfoAction says what a ValidateUserInfo check is about to admit.
type UserInfoAction string

const (
	// UserInfoCreateUser checks a user about to be created.
	UserInfoCreateUser UserInfoAction = "create-user"
	// UserInfoLinkAccount checks a provider identity about to be linked to
	// an existing user.
	UserInfoLinkAccount UserInfoAction = "link-account"
	// UserInfoSignIn checks an existing user signing in again through a
	// provider, with the provider's fresh profile.
	UserInfoSignIn UserInfoAction = "sign-in"
)

// UserInfoValidation describes an identity that Options.ValidateUserInfo
// admits or refuses.
type UserInfoValidation struct {
	Action UserInfoAction
	// Method says how the user arrives: "email-password", "oauth",
	// "sso-oidc", "sso-saml", "magic-link", "email-otp", "phone-number",
	// "anonymous", "siwe", "admin", "scim", "passkey" or a plugin's own name.
	Method string
	// Provider is the social, generic OAuth or SSO provider ID for the
	// "oauth", "sso-oidc" and "sso-saml" methods.
	Provider string
	// Profile is the provider's raw profile, when there is one, with JSON
	// numbers as json.Number.
	Profile map[string]any
	// User is the user about to be created or, for a link or a provider
	// sign-in, the provider's fresh profile with the existing user's ID.
	// Fields holds its additional-field input.
	User UserRecord
	// Request is a copy of the request without its body, or nil for a
	// direct Go call.
	Request *http.Request
}

// userInfoRejection marks a refusal so browser flows can render it before
// any other error mapping.
type userInfoRejection struct{ *APIError }

func (e *userInfoRejection) Unwrap() error { return e.APIError }

var errUserInfoPanic = errors.New("auth: ValidateUserInfo panicked")

// ValidateUserInfo runs Options.ValidateUserInfo for code that creates users
// or links identities itself. It returns nil when the option is unset or
// admits the identity, and otherwise a 403 *APIError.
func (a *Auth) ValidateUserInfo(ctx context.Context, v UserInfoValidation) error {
	if a.opts.ValidateUserInfo == nil {
		return nil
	}
	switch {
	case v.Method == "":
		return &userInfoRejection{&APIError{403, "validation_source_missing", "User validation source is required"}}
	case v.Method == "oauth" && v.Provider == "":
		return &userInfoRejection{&APIError{403, "validation_source_missing", "OAuth user validation source requires a provider ID"}}
	case (v.Method == "sso-oidc" || v.Method == "sso-saml") && v.Provider == "":
		return &userInfoRejection{&APIError{403, "validation_source_missing", "SSO user validation source requires a provider ID"}}
	}
	if v.Request == nil {
		if c := a.hookContext(ctx); c != nil {
			v.Request = c.Request
		}
	}
	if v.Request != nil {
		v.Request = accountObserverRequest(ctx, v.Request)
	}
	v.User.Fields = cloneFields(v.User.Fields)
	v.Profile = maps.Clone(v.Profile)
	err := func() (err error) {
		defer func() {
			if recover() != nil {
				err = errUserInfoPanic
			}
		}()
		return a.opts.ValidateUserInfo(ctx, v)
	}()
	if err == nil {
		return nil
	}
	var problem *APIError
	if errors.As(err, &problem) && problem != nil && problem.Code != "" {
		return &userInfoRejection{&APIError{403, problem.Code, cmp.Or(problem.Message, problem.Code)}}
	}
	a.Logger().ErrorContext(ctx, "auth: ValidateUserInfo failed")
	return &userInfoRejection{&APIError{403, "validation_failed", "User validation failed"}}
}

// profileMap returns a deep copy of a provider's raw profile as a JSON
// object, with numbers as json.Number so a direct and a proxied sign-in give
// the same values, or nil when it is not a JSON object.
func profileMap(data any) map[string]any {
	if data == nil {
		return nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m map[string]any
	if d.Decode(&m) != nil {
		return nil
	}
	return m
}

// UserInfoRefusal returns the 403 error of a ValidateUserInfo refusal, or nil
// when err is not one, so a plugin can render it before its own mappings.
func UserInfoRefusal(err error) *APIError {
	var refused *userInfoRejection
	if errors.As(err, &refused) {
		return refused.APIError
	}
	return nil
}

// HasUserInfoValidation reports whether Options.ValidateUserInfo is set, so a
// wrapping handler that creates users can refuse a host it does not gate.
func (a *Auth) HasUserInfoValidation() bool { return a.opts.ValidateUserInfo != nil }

// checkUserInfoValidation refuses ValidateUserInfo alongside flows that
// create users or link identities without running it yet.
func (a *Auth) checkUserInfoValidation() error {
	if a.opts.ValidateUserInfo == nil {
		return nil
	}
	if _, ok := a.opts.Store.(signUpUserFinder); !ok && a.opts.EmailAndPassword && !a.opts.DisableSignUp {
		return errors.New("auth: ValidateUserInfo for email sign-up requires a store implementing FindAccountUser")
	}
	// These sign-ins decide inside the store's transaction whether to create
	// or reach a user, so the gate runs between a dry run and the real one.
	if _, plans := a.opts.Store.(LoginPlanner); !plans {
		var decided []string
		if len(a.opts.SocialProviders) > 0 {
			decided = append(decided, "social sign-in")
		}
		for _, id := range []string{"magic-link", "email-otp", "one-tap", "sso"} {
			if a.HasPlugin(id) {
				decided = append(decided, id)
			}
		}
		if len(decided) > 0 {
			return fmt.Errorf("auth: ValidateUserInfo for %s needs a store implementing LoginPlanner", strings.Join(decided, ", "))
		}
	}
	return nil
}
