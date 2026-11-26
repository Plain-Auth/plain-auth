package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.ProviderUpdateStore = (*Store)(nil)

// UpdateSSOProvider applies change to the locked provider and writes its
// issuer, domain and OIDC configuration. change runs against the locked row,
// so a concurrent client secret rotation is never overwritten.
func (s *Store) UpdateSSOProvider(ctx context.Context, actor sso.Actor, id, recordID string, change sso.ProviderChange, guard sso.MutationGuard) (sso.Provider, error) {
	var result sso.Provider
	if recordID == "" {
		return result, sso.ErrChanged
	}
	var err error
	for range 3 {
		err = s.withManagedSSOProvider(ctx, actor, id, func(tx *sql.Tx, current sso.BrowserProvider) error {
			if current.ID != recordID {
				return sso.ErrChanged
			}
			next, identityChanged, e := change(current.Provider)
			if e != nil {
				return e
			}
			var links int
			query := `SELECT COUNT(*) FROM "account" WHERE ` + s.scimExact(`"providerId"`) + `=?`
			if e = tx.QueryRowContext(ctx, s.bind(query), id).Scan(&links); e != nil {
				return e
			}
			if guard != nil {
				mutation := sso.ProviderMutation{Action: "update", ID: recordID, ProviderID: id, OrganizationID: current.OrganizationID, Reference: current.Reference, LinkedAccounts: links, AuthenticationBoundaryChanged: identityChanged}
				if e = guard(ctx, mutation); e != nil {
					return sso.ErrMutationRejected
				}
			}
			if identityChanged && links != 0 {
				return sso.ErrLinkedIdentity
			}
			var raw []byte
			if next.SAML != nil {
				raw, e = s.marshalSAMLConfig(next.SAML)
			} else {
				raw, e = json.Marshal(next.OIDC)
			}
			if e != nil {
				return e
			}
			reference, e := enterpriseReference(next, string(raw))
			if e != nil {
				return e
			}
			required, e := s.requiresSSODomain(ctx, tx, current.Provider)
			if e != nil {
				return e
			}
			verified := false
			if required {
				if verified, e = s.domainVerified(ctx, tx, current.Provider, current.Reference); e != nil {
					return e
				}
			}
			if next.SAML != nil {
				_, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "domain"=? WHERE `+s.scimExact(`"id"`)+`=?`), next.Domain, recordID)
			} else {
				_, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "issuer"=?,"domain"=?,"oidcConfig"=? WHERE `+s.scimExact(`"id"`)+`=?`), next.Issuer, next.Domain, string(raw), recordID)
			}
			if e != nil {
				return e
			}
			result = next
			if !required || reference == current.Reference {
				return nil
			}
			if _, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), originDigest("dc-", recordID)); e != nil {
				return e
			}
			// Carry a proven domain across other edits, as a SAML certificate
			// rotation does; a new domain or identity needs a fresh proof.
			if verified && next.Domain == current.Domain && !identityChanged {
				return s.putOriginRecord(ctx, tx, originDigest("dp-", recordID), "enterprise-domain-proof", "verified:"+reference)
			}
			if _, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE `+s.scimExact(`"id"`)+`=?`), false, recordID); e != nil {
				return e
			}
			return s.putOriginRecord(ctx, tx, originDigest("dp-", recordID), "enterprise-domain-proof", "pending:"+reference)
		})
		if !retryIdentity(err) {
			break
		}
	}
	if err != nil {
		return sso.Provider{}, err
	}
	return result, nil
}
