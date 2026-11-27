package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.OpaqueAccessIntrospectionStore = (*Store)(nil)

func (s *Store) InspectOpaqueAccessToken(ctx context.Context, callerID, digest, userInfoURL string) (op.MachineClient, *op.OpaqueAccessTokenRecord, bool, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return op.MachineClient{}, nil, false, err
	}
	defer tx.Rollback()
	current, err := scanMachineClient(tx.QueryRowContext(ctx, s.bind(machineClientSelect), callerID, op.ResolvedDiscovery(ctx, callerID)), callerID)
	if err != nil || digest == "" {
		return current, nil, false, err
	}
	record, known, err := s.readOpaqueGrant(ctx, tx, &callerID, digest, userInfoURL)
	if err != nil {
		return current, nil, known, err
	}
	return current, record, known, tx.Commit()
}

func (s *Store) readOpaqueGrant(ctx context.Context, tx *sql.Tx, callerID *string, digest, userInfoURL string) (*op.OpaqueAccessTokenRecord, bool, error) {
	q := `SELECT t."clientId",t."revoked",t."createdAt",t."expiresAt",t."scopes",t."resources",t."confirmation",t."requestedUserInfoClaims",
		t."userId",u."id",t."sessionId",s."expiresAt",c."id",c."subjectType",c."redirectUris",c."disabled"
		FROM "oauthAccessToken" t LEFT JOIN "oauthClient" c ON c."clientId"=` + s.exactSQLValue(`t."clientId"`) + ` AND (c."clientDiscoveryId" IS NULL OR c."clientDiscoveryId"='')
		LEFT JOIN "user" u ON u."id"=` + s.exactSQLValue(`t."userId"`) + `
		LEFT JOIN "session" s ON s."id"=` + s.exactSQLValue(`t."sessionId"`) + ` AND (t."userId" IS NULL OR s."userId"=` + s.exactSQLValue(`t."userId"`) + `)
		WHERE t."token"=` + s.exactSQLValue("?")
	r := op.OpaqueAccessTokenRecord{}
	var clientRow, subject, owner, user, sid sql.NullString
	var revoked, sessionEnd sql.NullTime
	var disabled sql.NullBool
	var scopes, resources, confirmation, redirects, requested []byte
	err := tx.QueryRowContext(ctx, s.bind(q), digest).Scan(&r.ClientID, &revoked, &r.IssuedAt, &r.ExpiresAt, &scopes, &resources, &confirmation, &requested,
		&owner, &user, &sid, &sessionEnd, &clientRow, &subject, &redirects, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	if revoked.Valid || !clientRow.Valid || disabled.Bool || !r.ExpiresAt.After(now) || (owner.Valid && !user.Valid) || (sid.Valid && !sessionEnd.Time.After(now)) {
		return nil, true, nil
	}
	r.StoredToken, r.SubjectType, r.UserID, r.SessionID, r.SessionExpiresAt = digest, subject.String, user.String, sid.String, sessionEnd.Time
	if len(resources) > 0 && json.Unmarshal(resources, &r.Resources) != nil {
		return nil, true, nil
	}
	// The issuer's UserInfo endpoint reads the grant directly. Introspection
	// must separately authorize its authenticated caller against the audiences.
	reader := r.ClientID
	if callerID != nil {
		reader = *callerID
	} else if len(requested) > 0 {
		if err := json.Unmarshal(requested, &r.RequestedUserInfoClaims); err != nil {
			return nil, true, err
		}
	}
	ok, policy, err := s.resolveAccessAudiences(ctx, tx, reader, r.ClientID, userInfoURL, r.Resources, true)
	r.ResourceClaims = policy
	if err != nil || !ok {
		return nil, true, err
	}
	if err := json.Unmarshal(scopes, &r.Scopes); err != nil {
		return nil, true, err
	}
	if r.SubjectType == "pairwise" && r.UserID != "" && len(redirects) > 0 {
		if err := json.Unmarshal(redirects, &r.RedirectURIs); err != nil {
			return nil, true, err
		}
	}
	if len(confirmation) > 0 {
		if err := json.Unmarshal(confirmation, &r.Confirmation); err != nil {
			return nil, true, err
		}
	}
	return &r, true, nil
}

func (s *Store) resolveAccessAudiences(ctx context.Context, tx *sql.Tx, callerID, ownerID, userInfoURL string, audiences []string, includePolicy bool) (bool, map[string]json.RawMessage, error) {
	if len(audiences) > 64 {
		return false, nil, nil
	}
	authorized := callerID == ownerID
	resources := slices.DeleteFunc(slices.Clone(audiences), func(id string) bool { return id == userInfoURL })
	if len(resources) == 0 {
		return authorized, nil, nil
	}
	// Existing tokens retain disabled resources. Deletion invalidates every
	// token naming the missing audience, even when another audience still exists.
	found := make(map[string][]byte, len(resources))
	list, args := s.deviceTokenParameters(resources)
	column := "NULL"
	if includePolicy {
		column = `r."customClaims"`
	}
	q := `SELECT r."identifier",` + column + `,EXISTS(SELECT 1 FROM "oauthClientResource" l WHERE l."resourceId"=` + s.exactSQLValue(`r."identifier"`) + ` AND l."clientId"=` + s.exactSQLValue("?") + `) FROM "oauthResource" r WHERE r."identifier" IN (` + list + `)`
	rows, err := tx.QueryContext(ctx, s.bind(q), append([]any{callerID}, args...)...)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var claims []byte
		var linked bool
		if err := rows.Scan(&id, &claims, &linked); err != nil {
			return false, nil, err
		}
		found[id] = claims
		authorized = authorized || linked
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}
	if !authorized {
		return false, nil, nil
	}
	for _, id := range resources {
		if _, ok := found[id]; !ok {
			return false, nil, nil
		}
	}
	if !includePolicy {
		return true, nil, nil
	}
	var policy map[string]json.RawMessage
	for _, id := range resources {
		if raw := found[id]; len(raw) > 0 {
			var claims map[string]json.RawMessage
			if err := json.Unmarshal(raw, &claims); err != nil {
				return false, nil, err
			}
			if policy == nil {
				policy = claims
			} else {
				maps.Copy(policy, claims)
			}
		}
	}
	return true, policy, nil
}
