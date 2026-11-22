package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

func (s *Store) CompleteSAMLLogin(ctx context.Context, reference string, provision, verified bool, provider, subject string, receipt sso.AssertionReceipt, u auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
	// Existing users may link by email only under the provider's live DNS proof.
	opts.AllowVerifiedEmailLink = false
	return s.completeEnterpriseLogin(ctx, reference, provision, provider, subject, auth.OAuthTokens{}, u, session, opts, verified, &receipt)
}
func (s *Store) consumeSAMLAssertion(ctx context.Context, tx *sql.Tx, p sso.BrowserProvider, r sso.AssertionReceipt, now time.Time) error {
	if r.ID == "" || len(r.ID) > 512 || r.Issuer != p.SAML.IDPMetadata.EntityID {
		return sso.ErrInvalidSAML
	}
	key, _ := json.Marshal([]string{"saml-assertion", r.Issuer, r.ID})
	err := s.claimIDToken(ctx, tx, p.ProviderID, sha256.Sum256(key), now, now.Add(24*time.Hour))
	if errors.Is(err, auth.ErrIDTokenUsed) {
		return sso.ErrAssertionUsed
	}
	return err
}
