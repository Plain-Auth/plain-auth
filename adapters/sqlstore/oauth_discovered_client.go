package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.DiscoveredClientStore = (*Store)(nil)

const discoveredClientSelect = `SELECT ` + clientDetailsColumns + `,"id","clientDiscoveryId","createdAt","updatedAt" FROM "oauthClient" WHERE "clientId"=?`

func scanDiscoveredClient(row rowScanner, clientID string) (op.DiscoveredClient, error) {
	var c op.DiscoveredClient
	var discovery sql.NullString
	var created, updated sql.NullTime
	details, err := scanClientDetails(row, &c.RowID, &discovery, &created, &updated)
	if err == nil && details.ClientID != clientID {
		err = op.ErrClientNotFound
	}
	if err != nil {
		return op.DiscoveredClient{}, err
	}
	c.ClientDetails, c.DiscoveryID = details, discovery.String
	c.CreatedAt, c.UpdatedAt = created.Time.UTC(), updated.Time.UTC()
	return c, nil
}

func (s *Store) LookupDiscoveredClient(ctx context.Context, clientID string) (op.DiscoveredClient, error) {
	return scanDiscoveredClient(s.db.QueryRowContext(ctx, s.bind(discoveredClientSelect), clientID), clientID)
}

// SaveDiscoveredClient chooses create or replace under the row lock. Two
// first saves of one client race on its unique client ID, so the loser is
// retried once and replaces the winner's row; the other runtime retries the
// registration instead, with the same outcome.
func (s *Store) SaveDiscoveredClient(ctx context.Context, r op.DiscoveredClientRecord) (op.DiscoveredClient, bool, error) {
	if r.DiscoveryID == "" {
		return op.DiscoveredClient{}, false, errors.New("sqlstore: a discovered client needs its discovery ID")
	}
	for attempt := 0; ; attempt++ {
		c, created, err := s.saveDiscoveredClient(ctx, r)
		if attempt == 1 || !duplicateConstraint(err) && !lockConflict(err) {
			return c, created, err
		}
	}
}

func (s *Store) saveDiscoveredClient(ctx context.Context, r op.DiscoveredClientRecord) (op.DiscoveredClient, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.DiscoveredClient{}, false, err
	}
	defer tx.Rollback()
	if err := s.lockClientResources(ctx, tx, r.Metadata.Resources); err != nil {
		return op.DiscoveredClient{}, false, err
	}
	var rowID string
	var owner sql.NullString
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","clientDiscoveryId" FROM "oauthClient" WHERE "clientId"=?`), r.ClientID).Scan(&rowID, &owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return op.DiscoveredClient{}, false, err
	}
	found := err == nil
	switch {
	case !found && r.Existing != nil:
		return op.DiscoveredClient{}, false, &auth.OAuthError{Status: 400, Code: "invalid_client", Description: "client no longer exists"}
	case found && owner.String != r.DiscoveryID:
		return op.DiscoveredClient{}, false, &auth.OAuthError{Status: 400, Code: "invalid_client", Description: "client_id is already owned by a different registration source"}
	}
	cols, args, err := documentColumns(r, found)
	if err != nil {
		return op.DiscoveredClient{}, false, err
	}
	if found {
		// Only the fields the document owns are replaced; createdAt stays.
		cols, args = append(cols, `"updatedAt"`), append(args, s.date(r.Now))
		q := `UPDATE "oauthClient" SET ` + strings.Join(cols, "=?,") + `=? WHERE "id"=?`
		if _, err := tx.ExecContext(ctx, s.bind(q), append(args, rowID)...); err != nil {
			return op.DiscoveredClient{}, false, err
		}
	} else {
		// A new row has no owner and no secret, and an empty machine-scope ceiling.
		cols = append(cols, `"id"`, `"clientId"`, `"clientDiscoveryId"`, `"disabled"`, `"clientCredentialsScopes"`, `"createdAt"`, `"updatedAt"`)
		args = append(args, r.ID, r.ClientID, r.DiscoveryID, false, "[]", s.date(r.Now), s.date(r.Now))
		q := `INSERT INTO "oauthClient" (` + strings.Join(cols, ",") + `) VALUES (?` + strings.Repeat(",?", len(cols)-1) + `)`
		if _, err := tx.ExecContext(ctx, s.bind(q), args...); err != nil {
			return op.DiscoveredClient{}, false, err
		}
	}
	resources := slices.Clone(r.Metadata.Resources)
	slices.Sort(resources)
	for _, id := range slices.Compact(resources) {
		var linked bool
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "oauthClientResource" WHERE "clientId"=? AND "resourceId"=?)`), r.ClientID, id).Scan(&linked); err != nil {
			return op.DiscoveredClient{}, false, err
		}
		if !linked {
			if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "oauthClientResource" ("id","clientId","resourceId","createdAt") VALUES (?,?,?,?)`), rand.Text(), r.ClientID, id, s.date(r.Now)); err != nil {
				return op.DiscoveredClient{}, false, err
			}
		}
	}
	c, err := scanDiscoveredClient(tx.QueryRowContext(ctx, s.bind(discoveredClientSelect), r.ClientID), r.ClientID)
	if err != nil {
		return op.DiscoveredClient{}, false, err
	}
	return c, !found, tx.Commit()
}

// documentColumns lists the columns a metadata document owns. A replacement
// clears an omitted list to [] and an omitted value to NULL, as the other
// runtime does; a new row leaves an omitted optional list NULL. The subject
// type is written only when the document states it, since a change alters
// every subject the client sees.
func documentColumns(r op.DiscoveredClientRecord, replace bool) ([]string, []any, error) {
	m := r.Metadata
	var cols []string
	var args []any
	put := func(col string, value any) { cols, args = append(cols, `"`+col+`"`), append(args, value) }
	for _, f := range []struct {
		col      string
		value    []string
		required bool
	}{
		{"redirectUris", m.RedirectURIs, true}, {"grantTypes", m.GrantTypes, true}, {"scopes", r.Scopes, true},
		{"contacts", m.Contacts, false}, {"postLogoutRedirectUris", m.PostLogoutRedirectURIs, false}, {"responseTypes", m.ResponseTypes, false},
	} {
		switch {
		case f.value != nil:
		case f.required || replace:
			f.value = []string{}
		default:
			put(f.col, nil)
			continue
		}
		raw, err := json.Marshal(f.value)
		if err != nil {
			return nil, nil, err
		}
		put(f.col, string(raw))
	}
	for _, f := range []struct {
		col   string
		value *string
	}{
		{"name", m.Name}, {"uri", m.URI}, {"icon", m.LogoURI}, {"tos", m.TermsURI}, {"policy", m.PolicyURI}, {"jwksUri", m.JWKSURI},
		{"softwareId", m.SoftwareID}, {"softwareVersion", m.SoftwareVersion}, {"softwareStatement", m.SoftwareStatement},
	} {
		var value any
		if f.value != nil {
			value = *f.value
		}
		put(f.col, value)
	}
	nullable := func(col, value string) {
		if value == "" {
			put(col, nil)
		} else {
			put(col, value)
		}
	}
	nullable("tokenEndpointAuthMethod", m.TokenEndpointAuthMethod)
	nullable("applicationType", m.ApplicationType)
	var keys, bound any
	if len(m.JWKS) > 0 {
		keys = string(m.JWKS)
	}
	if m.DPoPBoundAccessTokens != nil {
		bound = *m.DPoPBoundAccessTokens
	}
	put("jwks", keys)
	put("dpopBoundAccessTokens", bound)
	if m.SubjectType != "" {
		put("subjectType", m.SubjectType)
	}
	return cols, args, nil
}
