package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.RegistrationStore = (*Store)(nil)

func (s *Store) CreateRegisteredClient(ctx context.Context, r op.ClientRegistrationRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	m := r.Metadata
	// Lock resources in a stable order before inserting any rows. This keeps
	// concurrent registrations and policy changes consistent across SQL engines.
	resources := slices.Clone(m.Resources)
	slices.Sort(resources)
	for _, id := range slices.Compact(resources) {
		var disabled sql.NullBool
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "disabled" FROM "oauthResource" WHERE "identifier"=?`), id).Scan(&disabled)
		if errors.Is(err, sql.ErrNoRows) {
			return &auth.OAuthError{Status: 400, Code: "invalid_target", Description: "requested resource " + id + " does not exist"}
		}
		if err != nil {
			return err
		}
		if disabled.Bool {
			return &auth.OAuthError{Status: 400, Code: "invalid_target", Description: "requested resource " + id + " is disabled"}
		}
	}
	var cols []string
	var args []any
	put := func(col string, value any) { cols = append(cols, `"`+col+`"`); args = append(args, value) }
	put("id", r.ID)
	put("clientId", r.ClientID)
	put("createdAt", s.date(r.CreatedAt))
	put("disabled", false)
	for _, f := range []struct{ key, val string }{
		{"userId", r.UserID}, {"referenceId", r.ReferenceID}, {"clientSecret", r.StoredSecret}, {"applicationType", m.ApplicationType},
		{"tokenEndpointAuthMethod", m.TokenEndpointAuthMethod}, {"subjectType", m.SubjectType},
	} {
		if f.val != "" {
			put(f.key, f.val)
		}
	}
	for _, f := range []struct {
		key string
		val *string
	}{
		{"name", m.Name}, {"uri", m.URI}, {"icon", m.LogoURI}, {"tos", m.TermsURI}, {"policy", m.PolicyURI}, {"softwareId", m.SoftwareID},
		{"softwareVersion", m.SoftwareVersion}, {"softwareStatement", m.SoftwareStatement}, {"backchannelLogoutUri", m.BackchannelLogoutURI}, {"jwksUri", m.JWKSURI},
	} {
		if f.val != nil {
			put(f.key, *f.val)
		}
	}
	for _, f := range []struct {
		key string
		val []string
	}{
		{"redirectUris", m.RedirectURIs}, {"postLogoutRedirectUris", m.PostLogoutRedirectURIs}, {"contacts", m.Contacts},
		{"grantTypes", m.GrantTypes}, {"responseTypes", m.ResponseTypes}, {"scopes", r.Scopes}, {"clientCredentialsScopes", []string{}},
	} {
		if f.val != nil {
			raw, err := json.Marshal(f.val)
			if err != nil {
				return err
			}
			put(f.key, string(raw))
		}
	}
	if len(m.JWKS) > 0 {
		put("jwks", string(m.JWKS))
	}
	if m.DPoPBoundAccessTokens != nil {
		put("dpopBoundAccessTokens", *m.DPoPBoundAccessTokens)
	}
	if m.BackchannelLogoutSessionRequired != nil {
		put("backchannelLogoutSessionRequired", *m.BackchannelLogoutSessionRequired)
	}
	if r.RequirePKCE != nil {
		put("requirePKCE", *r.RequirePKCE)
	}
	q := `INSERT INTO "oauthClient" (` + strings.Join(cols, ",") + ") VALUES (?" + strings.Repeat(",?", len(cols)-1) + ")"
	if _, err = tx.ExecContext(ctx, s.bind(q), args...); err != nil {
		return err
	}
	for _, id := range m.Resources {
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "oauthClientResource" ("id","clientId","resourceId","createdAt") VALUES (?,?,?,?)`), rand.Text(), r.ClientID, id, s.date(r.CreatedAt)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
