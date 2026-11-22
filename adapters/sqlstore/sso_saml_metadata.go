package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Plain-Auth/plain-auth/plugins/sso"
)

// Use a compact JSON string to retain the metadata document verbatim. The
// canonical MySQL schema uses TEXT, which holds 65,535 encoded bytes.
func (s *Store) marshalSAMLConfig(cfg *sso.SAMLConfig) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	raw := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	if s.dialect == "mysql" && len(raw) > 65535 {
		return nil, sso.ErrMetadataStorageSize
	}
	return raw, nil
}

func (s *Store) UpdateSSOMetadata(ctx context.Context, actor sso.Actor, id, recordID, expected, metadata string, guard sso.MutationGuard) (sso.Provider, error) {
	var result sso.Provider
	if recordID == "" || expected == "" {
		return result, sso.ErrChanged
	}
	var err error
	for range 3 {
		err = s.withManagedSSOProvider(ctx, actor, id, func(tx *sql.Tx, current sso.BrowserProvider) error {
			if current.SAML == nil || current.ID != recordID || expected != current.Reference {
				return sso.ErrChanged
			}
			next, e := current.SAML.WithIDPMetadata(metadata)
			if e != nil {
				return e
			}
			if !next.MetadataValidAt(time.Now()) {
				return sso.ErrInvalidSAML
			}
			identityChanged := !sso.SameSAMLIdentity(*current.SAML, *next)
			var links int
			query := `SELECT COUNT(*) FROM "account" WHERE ` + s.scimExact(`"providerId"`) + `=?`
			if e = tx.QueryRowContext(ctx, s.bind(query), id).Scan(&links); e != nil {
				return e
			}
			if guard != nil {
				mutation := sso.ProviderMutation{Action: "update", ID: recordID, ProviderID: id, OrganizationID: current.OrganizationID, Reference: expected, LinkedAccounts: links, AuthenticationBoundaryChanged: identityChanged || sso.SAMLTrustChanged(*current.SAML, *next)}
				if e = guard(ctx, mutation); e != nil {
					return sso.ErrMutationRejected
				}
			}
			if identityChanged && links != 0 {
				return sso.ErrLinkedIdentity
			}
			raw, e := s.marshalSAMLConfig(next)
			if e != nil {
				return e
			}
			result = current.Provider
			result.SAML = next
			reference, e := enterpriseReference(result, string(raw))
			if e != nil || reference == expected {
				return e
			}
			required, e := s.requiresSSODomain(ctx, tx, current.Provider)
			if e != nil {
				return e
			}
			verified := false
			if required {
				verified, e = s.domainVerified(ctx, tx, current.Provider, expected)
				if e != nil {
					return e
				}
			}
			if _, e = tx.ExecContext(ctx, s.bind(`UPDATE "ssoProvider" SET "samlConfig"=? WHERE `+s.scimExact(`"id"`)+`=?`), string(raw), recordID); e != nil {
				return e
			}
			if !required {
				return nil
			}
			// A cert-only rotation carries a proven domain forward; pending, expired
			// and replaced identities must prove the new configuration independently.
			if _, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), originDigest("dc-", recordID)); e != nil {
				return e
			}
			if verified && !identityChanged {
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
