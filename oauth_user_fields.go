package plainauth

import "context"

// The resolver supplies the mapped profile. Browser state, raw provider data and
// provider tokens are never inputs to the declared user fields.
func (a *Auth) socialProfileCompletion(profile OAuthProfile, syncProfile bool) OAuthCompletion {
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
	if syncProfile {
		store := a.opts.Store.(OAuthProfileSyncStore)
		fields := OAuthProfileFields{Create: create, Update: func() (UserFieldValues, error) { return prepare(false) }}
		return func(ctx context.Context, id, subject string, tokens OAuthTokens, user User, session StoredSession, options OAuthLoginOptions) (User, bool, error) {
			return store.CompleteOAuthProfile(ctx, id, subject, tokens, user, session, options, fields)
		}
	}
	store := a.opts.Store.(OAuthRegistrationStore)
	return func(ctx context.Context, id, subject string, tokens OAuthTokens, user User, session StoredSession, options OAuthLoginOptions) (User, bool, error) {
		return store.CompleteOAuthRegistration(ctx, id, subject, tokens, user, session, options, create)
	}
}
