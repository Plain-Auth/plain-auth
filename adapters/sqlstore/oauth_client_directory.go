package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.ClientDirectoryStore = (*Store)(nil)

const clientDisplayColumns = `"clientId","name","uri","icon","contacts","tos","policy"`

// clientFilter matches a client row by its ID: a local row, or one owned by
// the discovery that resolved the ID in this request. Its arguments are the
// ID and op.ResolvedDiscovery for it.
const clientFilter = ` WHERE "clientId"=? AND ("clientDiscoveryId" IS NULL OR "clientDiscoveryId"='' OR "clientDiscoveryId"=?)`

// The database only returns the presence of a stored secret, never the value.
const clientDetailsColumns = clientDisplayColumns + `,"userId","referenceId","createdAt",
	CASE WHEN LENGTH("clientSecret")>0 THEN 0 ELSE NULL END,
	"softwareId","softwareVersion","softwareStatement","jwks","jwksUri",
	"redirectUris","postLogoutRedirectUris","backchannelLogoutUri","backchannelLogoutSessionRequired",
	"tokenEndpointAuthMethod","grantTypes","responseTypes","applicationType","subjectType",
	"disabled","skipConsent","enableEndSession","requirePKCE","dpopBoundAccessTokens","scopes","metadata","clientCredentialsScopes"`

const clientDetailsSelect = `SELECT ` + clientDetailsColumns + ` FROM "oauthClient"`

func (s *Store) PublicOAuthClient(ctx context.Context, id string) (op.PublicClient, error) {
	q := `SELECT ` + clientDisplayColumns + ` FROM "oauthClient"` + clientFilter + ` AND ("disabled" IS NULL OR "disabled"=FALSE)`
	var c op.PublicClient
	var contacts []byte
	err := s.db.QueryRowContext(ctx, s.bind(q), id, op.ResolvedDiscovery(ctx, id)).Scan(&c.ClientID, &c.Name, &c.URI, &c.LogoURI, &contacts, &c.TermsURI, &c.PolicyURI)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && c.ClientID != id) {
		return op.PublicClient{}, op.ErrClientNotFound
	}
	if err != nil {
		return op.PublicClient{}, err
	}
	if contacts != nil {
		if err := json.Unmarshal(contacts, &c.Contacts); err != nil {
			return op.PublicClient{}, err
		}
	}
	c.RedirectURIs = []string{}
	return c, nil
}

// scanClientDetails reads the clientDetailsColumns, then any extra columns
// into extra.
func scanClientDetails(row rowScanner, extra ...any) (op.ClientDetails, error) {
	var c op.ClientDetails
	var issued *time.Time
	var contacts, scopes, redirects, logoutRedirects, grants, responses, keys, metadata, machine []byte
	err := row.Scan(append([]any{&c.ClientID, &c.Name, &c.URI, &c.LogoURI, &contacts, &c.TermsURI, &c.PolicyURI,
		&c.UserID, &c.ReferenceID, &issued, &c.SecretExpiresAt,
		&c.SoftwareID, &c.SoftwareVersion, &c.SoftwareStatement, &keys, &c.JWKSURI,
		&redirects, &logoutRedirects, &c.BackchannelLogoutURI, &c.BackchannelLogoutSessionRequired,
		&c.TokenEndpointAuthMethod, &grants, &responses, &c.ApplicationType, &c.SubjectType,
		&c.Disabled, &c.SkipConsent, &c.EnableEndSession, &c.RequirePKCE, &c.DPoPBoundAccessTokens, &scopes, &metadata, &machine}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return c, op.ErrClientNotFound
	}
	if err != nil {
		return c, err
	}
	if issued != nil {
		seconds := issued.Add(500 * time.Millisecond).Unix()
		c.IssuedAt = &seconds
	}
	var scopeList []string
	for _, f := range []struct {
		raw  []byte
		dest *[]string
	}{
		{contacts, &c.Contacts}, {redirects, &c.RedirectURIs}, {logoutRedirects, &c.PostLogoutRedirectURIs}, {grants, &c.GrantTypes}, {responses, &c.ResponseTypes}, {scopes, &scopeList},
		{machine, &c.ClientCredentialsScopes},
	} {
		if f.raw != nil {
			if err := json.Unmarshal(f.raw, f.dest); err != nil {
				return op.ClientDetails{}, err
			}
		}
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if scopeList != nil {
		scope := strings.Join(scopeList, " ")
		c.Scope = &scope
	}
	if len(keys) > 0 {
		if !json.Valid(keys) {
			return op.ClientDetails{}, errors.New("sqlstore: invalid stored OAuth client JWK set")
		}
		c.JWKS = keys
	}
	if len(metadata) > 0 {
		if err := c.SetMetadataExtensions(metadata); err != nil {
			return op.ClientDetails{}, err
		}
	}
	return c, nil
}

func (s *Store) LookupOAuthClient(ctx context.Context, id string) (op.ClientDetails, error) {
	c, err := scanClientDetails(s.db.QueryRowContext(ctx, s.bind(clientDetailsSelect+clientFilter), id, op.ResolvedDiscovery(ctx, id)))
	if err == nil && id != c.ClientID {
		return op.ClientDetails{}, op.ErrClientNotFound
	}
	return c, err
}

func (s *Store) ListOAuthClients(ctx context.Context, userID, ref string) ([]op.ClientDetails, error) {
	result := []op.ClientDetails{}
	if userID == "" {
		return result, nil
	}
	filter := ` WHERE "userId"=?`
	args := []any{userID}
	if ref != "" {
		filter = ` WHERE "referenceId"=? AND ("userId" IS NULL OR "userId"='' OR "userId"=?)`
		args = []any{ref, userID}
	}
	rows, err := s.db.QueryContext(ctx, s.bind(clientDetailsSelect+filter+` ORDER BY "clientId"`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanClientDetails(rows)
		if err != nil {
			return nil, err
		}
		// Some SQL collations compare IDs case-insensitively. Ownership is exact.
		if c.UserID != nil && *c.UserID != "" && *c.UserID != userID {
			continue
		}
		if ref != "" && (c.ReferenceID == nil || *c.ReferenceID != ref) {
			continue
		}
		if ref == "" && (c.UserID == nil || *c.UserID != userID) {
			continue
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
