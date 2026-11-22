package plainauth

import "context"

// The resolver supplies the mapped profile. Browser state, raw provider data and
// provider tokens are never inputs to the declared user fields.
func (a *Auth) socialRegistrationWithFields(profile OAuthProfile) OAuthCompletion {
	store := a.opts.Store.(OAuthRegistrationStore)
	prepare := func() (UserFieldValues, error) {
		writable := make(map[string]any)
		for name, value := range profile.AdditionalFields {
			if field, declared := a.opts.UserAdditionalFields[name]; declared && !field.ServerOnly {
				writable[name] = value
			}
		}
		values, err := a.prepareUserFields(writable, true, false)
		if err != nil {
			return UserFieldValues{}, oauthRegistrationFieldError{err}
		}
		return values, nil
	}
	return func(ctx context.Context, id, subject string, tokens OAuthTokens, user User, session StoredSession, options OAuthLoginOptions) (User, bool, error) {
		return store.CompleteOAuthRegistration(ctx, id, subject, tokens, user, session, options, prepare)
	}
}
