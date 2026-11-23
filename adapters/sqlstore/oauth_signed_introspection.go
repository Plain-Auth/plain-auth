package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.SignedAccessIntrospectionStore = (*Store)(nil)

func (s *Store) InspectSignedAccessGrant(ctx context.Context, callerID, userInfoURL string, grant op.SignedAccessGrant) (op.MachineClient, *op.SignedGrantClient, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return op.MachineClient{}, nil, err
	}
	defer tx.Rollback()
	current, err := scanMachineClient(tx.QueryRowContext(ctx, s.bind(machineClientSelect), callerID), callerID)
	if err != nil {
		return current, nil, err
	}
	owner, err := s.readSignedGrant(ctx, tx, callerID, userInfoURL, grant)
	if err != nil {
		return current, nil, err
	}
	return current, owner, tx.Commit()
}

func (s *Store) readSignedGrant(ctx context.Context, tx *sql.Tx, callerID, userInfoURL string, grant op.SignedAccessGrant) (*op.SignedGrantClient, error) {
	var subject sql.NullString
	var redirects []byte
	var sessionExpiry sql.NullTime
	q := `SELECT c."subjectType",c."redirectUris",s."expiresAt" FROM "oauthClient" c LEFT JOIN "session" s ON s."id"=` + s.exactSQLValue("?") + `
		WHERE c."clientId"=` + s.exactSQLValue("?") + ` AND (c."clientDiscoveryId" IS NULL OR c."clientDiscoveryId"='') AND (c."disabled"=FALSE OR c."disabled" IS NULL)`
	err := tx.QueryRowContext(ctx, s.bind(q), grant.SessionID, grant.ClientID).Scan(&subject, &redirects, &sessionExpiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if grant.SessionID != "" && !sessionExpiry.Time.After(time.Now()) {
		return nil, nil
	}
	ok, _, err := s.resolveAccessAudiences(ctx, tx, callerID, grant.ClientID, userInfoURL, grant.Audiences, false)
	if !ok || err != nil {
		return nil, err
	}
	owner := &op.SignedGrantClient{SubjectType: subject.String}
	if subject.String == "pairwise" && len(redirects) > 0 {
		if err := json.Unmarshal(redirects, &owner.RedirectURIs); err != nil {
			return nil, err
		}
	}
	return owner, nil
}
