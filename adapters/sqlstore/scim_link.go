package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
)

var _ scim.ActiveUserLinkStore = (*Store)(nil)

// activeSCIMUserWhere selects an active SCIM User by connection and exact
// externalId whose connection is active, whose account exists and whose
// externalId has no tombstone.
func (s *Store) activeSCIMUserWhere() string {
	return s.scimExact(`u."connectionId"`) + `=? AND ` + s.scimExact(`u."externalIdKey"`) + `=? AND ` + s.scimExact(`u."externalId"`) + `=? AND u."active"=?` +
		` AND EXISTS (SELECT 1 FROM "scimConnectionBinding" b WHERE ` + s.scimExact(`b."connectionId"`) + `=u."connectionId" AND b."provisioningDomainId"=u."provisioningDomainId" AND b."decommissionStatus"='active')` +
		` AND EXISTS (SELECT 1 FROM "scimSubject" j WHERE j."userId"=u."userId") AND EXISTS (SELECT 1 FROM "user" a WHERE a."id"=u."userId")` +
		` AND NOT EXISTS (SELECT 1 FROM "scimIdentityTombstone" t WHERE ` + s.scimExact(`t."connectionId"`) + `=u."connectionId" AND ` + s.scimExact(`t."externalIdKey"`) + `=u."externalIdKey")`
}

func (s *Store) SCIMActiveUserLink(ctx context.Context, ref scim.UserExternalIDReference) (scim.ActiveUserLink, error) {
	var link scim.ActiveUserLink
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT u."id",u."userId" FROM "scimUser" u WHERE `+s.activeSCIMUserWhere()),
		ref.ConnectionID, scimKey("scim-user-external-id", ref.ConnectionID, ref.ExternalID), ref.ExternalID, true).Scan(&link.SCIMUserID, &link.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return link, scim.ErrNotFound
	}
	return link, err
}

// requireActiveSCIMUser confirms, under the selected user's lock, that the
// SCIM User is still active and links to userID. The resolver read the link
// outside this transaction; check it again under the account's lock. Every
// SCIM mutation and retirement batch takes that lock before it commits.
func (s *Store) requireActiveSCIMUser(ctx context.Context, tx *sql.Tx, ref authn.SCIMUserReference, userID string) error {
	var id string
	err := tx.QueryRowContext(ctx, s.bind(`SELECT u."id" FROM "scimUser" u WHERE `+s.activeSCIMUserWhere()+` AND u."userId"=?`),
		ref.ConnectionID, scimKey("scim-user-external-id", ref.ConnectionID, ref.ExternalID), ref.ExternalID, true, userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrSCIMUserInactive
	}
	return err
}
