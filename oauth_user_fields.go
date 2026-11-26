package plainauth

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// writableProfileFields keeps the declared user fields a provider may set.
func (a *Auth) writableProfileFields(profile OAuthProfile) map[string]any {
	writable := make(map[string]any)
	for name, value := range profile.AdditionalFields {
		if field, declared := a.opts.UserAdditionalFields[name]; declared && !field.ServerOnly {
			writable[name] = value
		}
	}
	return writable
}

// The resolver supplies the mapped profile. Browser state, raw provider data and
// provider tokens are never inputs to the declared user fields.
func (a *Auth) socialProfileCompletion(profile OAuthProfile, syncProfile, requireVerifiedEmail bool) (OAuthCompletion, error) {
	writable := a.writableProfileFields(profile)
	prepare := func(create bool) (UserFieldValues, error) {
		values, err := a.prepareUserFields(writable, create, false)
		if err != nil {
			return UserFieldValues{}, oauthProfileFieldError{err}
		}
		return values, nil
	}
	create := func() (UserFieldValues, error) { return prepare(true) }
	if syncProfile || requireVerifiedEmail {
		fields := OAuthProfileFields{Create: create}
		if syncProfile {
			fields.Update = func() (UserFieldValues, error) { return prepare(false) }
		}
		var complete func(context.Context, string, string, OAuthTokens, User, StoredSession, OAuthLoginOptions, OAuthProfileFields) (User, bool, error)
		if requireVerifiedEmail {
			store, ok := a.opts.Store.(OAuthVerifiedEmailStore)
			if !ok {
				// A stricter production callback can also request this policy.
				return nil, errors.New("auth: verified provider email requires an OAuthVerifiedEmailStore")
			}
			complete = store.CompleteOAuthVerifiedEmail
		} else {
			complete = a.opts.Store.(OAuthProfileSyncStore).CompleteOAuthProfile
		}
		return func(ctx context.Context, id, subject string, tokens OAuthTokens, user User, session StoredSession, options OAuthLoginOptions) (User, bool, error) {
			return complete(ctx, id, subject, tokens, user, session, options, fields)
		}, nil
	}
	store := a.opts.Store.(OAuthRegistrationStore)
	return func(ctx context.Context, id, subject string, tokens OAuthTokens, user User, session StoredSession, options OAuthLoginOptions) (User, bool, error) {
		return store.CompleteOAuthRegistration(ctx, id, subject, tokens, user, session, options, create)
	}, nil
}

// enterpriseProfileFields prepares the declared user fields an enterprise
// profile writes before the store's transaction starts, so a host's field
// default never runs inside it. It is nil when the host declares no user
// fields and the profile does not override the owner's.
func (a *Auth) enterpriseProfileFields(p OAuthProfile, override bool) *OAuthProfileFields {
	if len(a.opts.UserAdditionalFields) == 0 && !override {
		return nil
	}
	writable := a.writableProfileFields(p)
	for name, value := range writable {
		if fitted, ok := enterpriseFieldValue(a.opts.UserAdditionalFields[name], value); ok {
			writable[name] = fitted
		} else {
			delete(writable, name)
			a.Logger().Warn("enterprise provider sent several values for a user field; none was written", "field", name)
		}
	}
	prepared := func(create bool) func() (UserFieldValues, error) {
		values, err := a.prepareUserFields(writable, create, false)
		return func() (UserFieldValues, error) {
			if err != nil {
				return UserFieldValues{}, oauthProfileFieldError{err}
			}
			return values, nil
		}
	}
	fields := &OAuthProfileFields{Create: prepared(true)}
	if override {
		fields.Update = prepared(false)
	}
	return fields
}

// enterpriseFieldValue fits a provider value to a scalar user field. A list
// with one value uses it and a list with several is refused, and a string
// becomes a number or boolean for those field types, because SAML
// attributes are always strings.
func enterpriseFieldValue(field UserField, value any) (any, bool) {
	if list, ok := value.([]any); ok {
		if len(list) != 1 {
			return nil, false
		}
		value = list[0]
	}
	text, ok := value.(string)
	if !ok {
		return value, true
	}
	switch field.Type {
	case FieldNumber:
		if n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 32); err == nil {
			return n, true
		}
	case FieldBoolean:
		if b, err := strconv.ParseBool(strings.TrimSpace(text)); err == nil {
			return b, true
		}
	}
	return value, true
}
