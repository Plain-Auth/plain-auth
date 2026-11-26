package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.ProviderUpdateStore = (*Store)(nil)

// UpdateSSOProvider applies change to the locked provider and writes its
// issuer, domain and OIDC configuration. change runs against the locked row,
// so a concurrent client secret rotation is never overwritten, and guard
// reviews the planned mutation outside the transaction.
func (s *Store) UpdateSSOProvider(ctx context.Context, actor sso.Actor, id, recordID string, change sso.ProviderChange, guard sso.MutationGuard) (sso.Provider, error) {
	var result sso.Provider
	if recordID == "" {
		return result, sso.ErrChanged
	}
	var err error
	for range 3 {
		err = guarded(ctx, guard, func(g *providerGuard) error {
			return s.withManagedSSOProvider(ctx, actor, id, func(tx *sql.Tx, current sso.BrowserProvider) error {
				if current.ID != recordID {
					return sso.ErrChanged
				}
				next, identityChanged, e := change(current.Provider)
				if e != nil {
					return e
				}
				linked, e := s.linkedAccounts(ctx, tx, id)
				if e != nil {
					return e
				}
				links := len(linked)
				// A SAML certificate rotation changes the trust anchor without
				// changing the identity, and the guard still hears of it.
				boundary := identityChanged || current.SAML != nil && next.SAML != nil && sso.SAMLTrustChanged(*current.SAML, *next.SAML)
				mutation := sso.ProviderMutation{Action: "update", ID: recordID, ProviderID: id, OrganizationID: current.OrganizationID, Reference: current.Reference, LinkedAccounts: links, AuthenticationBoundaryChanged: boundary}
				if e = g.check(mutation, linkDigest(linked)); e != nil {
					return e
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
				column := `"oidcConfig"`
				if next.SAML != nil {
					column = `"samlConfig"`
				}
				set, args := `"issuer"=?,"domain"=?,`+column+`=?`, []any{next.Issuer, next.Domain, string(raw)}
				extra, values := s.providerFieldWrite(next.AdditionalFields, false)
				for i, field := range extra {
					set += "," + field + "=?"
					args = append(args, values[i])
				}
				_, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET `+set+` WHERE `+s.scimExact(`"id"`)+`=?`), append(args, recordID)...)
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
				// rotation does. A new domain, identity or claim mapping needs a
				// fresh proof: the mapping chooses the email the proof vouches for.
				if verified && next.Domain == current.Domain && !identityChanged && sameMapping(current.Provider, next) {
					return s.putOriginRecord(ctx, tx, originDigest("dp-", recordID), "enterprise-domain-proof", "verified:"+reference)
				}
				if _, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "domainVerified"=? WHERE `+s.scimExact(`"id"`)+`=?`), false, recordID); e != nil {
					return e
				}
				return s.putOriginRecord(ctx, tx, originDigest("dp-", recordID), "enterprise-domain-proof", "pending:"+reference)
			})
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

// sameMapping reports whether an update leaves the OIDC claim mapping as it
// was.
func sameMapping(a, b sso.Provider) bool {
	if a.SAML != nil && b.SAML != nil {
		return reflect.DeepEqual(a.SAML.Mapping, b.SAML.Mapping)
	}
	if a.OIDC == nil || b.OIDC == nil {
		return a.OIDC == b.OIDC
	}
	return reflect.DeepEqual(a.OIDC.Mapping, b.OIDC.Mapping)
}
