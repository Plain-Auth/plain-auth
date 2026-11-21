package stonewrit

import "context"

// Bind each credential to its provider, subject and column. The storage layer
// can carry the resulting opaque strings through its normal transactions.
func (a *Auth) transformOAuthTokens(provider, subject string, tokens OAuthTokens, encrypt bool) (OAuthTokens, error) {
	prefix := "oauth/" + provider + "\x00" + subject + "\x00"
	fields := []struct {
		name  string
		value *string
	}{{"access", &tokens.AccessToken}, {"refresh", &tokens.RefreshToken}, {"identity", &tokens.IDToken}}
	for _, field := range fields {
		if *field.value == "" {
			continue
		}
		purpose := prefix + field.name
		if encrypt {
			value, err := a.sealRecord(purpose, []byte(*field.value))
			if err != nil {
				return OAuthTokens{}, err
			}
			*field.value = value
		} else {
			value, err := a.openRecord(purpose, *field.value)
			if err != nil {
				return OAuthTokens{}, err
			}
			*field.value = string(value)
		}
	}
	return tokens, nil
}

type encryptedProviderStore struct {
	ProviderCredentialStore
	auth *Auth
}

func (s encryptedProviderStore) transform(row ProviderAccountCredential, encrypt bool) (ProviderAccountCredential, error) {
	tokens, err := s.auth.transformOAuthTokens(row.ProviderID, row.Subject, row.OAuthTokens, encrypt)
	if err != nil {
		return ProviderAccountCredential{}, err
	}
	row.OAuthTokens = tokens
	return row, nil
}

func (s encryptedProviderStore) ProviderCredential(ctx context.Context, userID, id string) (ProviderAccountCredential, error) {
	row, err := s.ProviderCredentialStore.ProviderCredential(ctx, userID, id)
	if err != nil {
		return ProviderAccountCredential{}, err
	}
	return s.transform(row, false)
}

func (s encryptedProviderStore) UpdateProviderCredential(ctx context.Context, userID, id string, update func(ProviderAccountCredential) (ProviderAccountCredential, bool, error)) (ProviderAccountCredential, error) {
	stored, err := s.ProviderCredentialStore.UpdateProviderCredential(ctx, userID, id, func(stored ProviderAccountCredential) (ProviderAccountCredential, bool, error) {
		row, err := s.transform(stored, false)
		if err != nil {
			return stored, false, err
		}
		row, changed, err := update(row)
		if err != nil || !changed {
			return stored, false, err
		}
		next, err := s.transform(row, true)
		return next, err == nil, err
	})
	if err != nil {
		return ProviderAccountCredential{}, err
	}
	return s.transform(stored, false)
}
