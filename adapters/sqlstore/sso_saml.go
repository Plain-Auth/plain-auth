package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

func (s *Store) CompleteSAMLLogin(ctx context.Context, reference string, role string, verified bool, provider, subject string, receipt sso.AssertionReceipt, u auth.User, session auth.StoredSession, opts auth.OAuthLoginOptions) (auth.User, bool, error) {
	// Existing users may link by email only under the provider's live DNS proof.
	opts.AllowVerifiedEmailLink, opts.TrustedProvider, opts.AllowDifferentEmails = false, false, false
	return s.completeEnterpriseLogin(ctx, reference, role, provider, subject, auth.OAuthTokens{}, u, session, opts, verified, &receipt)
}
func (s *Store) consumeSAMLAssertion(ctx context.Context, tx *sql.Tx, p sso.BrowserProvider, r sso.AssertionReceipt, now time.Time) error {
	if !p.SAML.MetadataValidAt(now) || r.ID == "" || len(r.ID) > 512 || r.Issuer != p.SAML.IdentityProviderEntityID() {
		return sso.ErrInvalidSAML
	}
	// The receipt is scoped to the IdP and kept for 24 hours; another
	// runtime keys it by assertion ID alone until NotOnOrAfter plus skew.
	key, _ := json.Marshal([]string{"saml-assertion", r.Issuer, r.ID})
	err := s.claimIDToken(ctx, tx, p.ProviderID, sha256.Sum256(key), now, now.Add(24*time.Hour))
	if errors.Is(err, auth.ErrIDTokenUsed) {
		return sso.ErrAssertionUsed
	}
	return err
}
