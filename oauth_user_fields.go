package plainauth

import (
	"context"
	"errors"
)

// The resolver supplies the mapped profile. Browser state, raw provider data and
// provider tokens are never inputs to the declared user fields.
func (a *Auth) socialProfileCompletion(profile OAuthProfile, syncProfile, requireVerifiedEmail bool) (OAuthCompletion, error) {
	writable := make(map[string]any)
	for name, value := range profile.AdditionalFields {
		if field, declared := a.opts.UserAdditionalFields[name]; declared && !field.ServerOnly {
			writable[name] = value
		}
	}
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
