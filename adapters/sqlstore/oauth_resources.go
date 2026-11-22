package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.ResourceStore = (*Store)(nil)

const resourceSelect = `SELECT "id","identifier","name","accessTokenTtl","refreshTokenTtl","signingAlgorithm","signingKeyId","allowedScopes","customClaims","dpopBoundAccessTokensRequired","disabled","policyVersion","metadata","createdAt","updatedAt" FROM "oauthResource"`
const resourceByID = resourceSelect + ` WHERE "identifier"=?`

func scanOAuthResource(row rowScanner) (op.Resource, error) {
	var r op.Resource
	var scopes, claims, metadata []byte
	var bound, disabled sql.NullBool
	var version sql.NullInt64
	var created, updated sql.NullTime
	err := row.Scan(&r.ID, &r.Identifier, &r.Name, &r.AccessTokenTTL, &r.RefreshTokenTTL,
		&r.SigningAlgorithm, &r.SigningKeyID, &scopes, &claims, &bound, &disabled, &version, &metadata, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return op.Resource{}, auth.ErrNotFound
	}
	if err != nil {
		return op.Resource{}, err
	}
	r.DPoPBoundAccessTokensRequired, r.Disabled = bound.Bool, disabled.Bool
	r.PolicyVersion = int(version.Int64)
	r.CreatedAt, r.UpdatedAt = created.Time.UTC(), updated.Time.UTC()
	for _, field := range []struct {
		raw []byte
		dst any
	}{{scopes, &r.AllowedScopes}, {claims, &r.CustomClaims}, {metadata, &r.Metadata}} {
		if field.raw != nil {
			if err := json.Unmarshal(field.raw, field.dst); err != nil {
				return op.Resource{}, err
			}
		}
	}
	return r, nil
}

func (s *Store) OAuthResource(ctx context.Context, identifier string) (op.Resource, error) {
	return scanOAuthResource(s.db.QueryRowContext(ctx, s.bind(resourceByID), identifier))
}

func (s *Store) ListOAuthResources(ctx context.Context) ([]op.Resource, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(resourceSelect+` ORDER BY "identifier"`))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []op.Resource{}
	for rows.Next() {
		r, err := scanOAuthResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// On create write every field. On patch write only supplied fields, including SQL
// NULL for an explicit clear. Independent writers can safely change different fields.
func resourceColumns(r op.Resource, patch *op.ResourcePatch) ([]string, []any, error) {
	var p op.ResourcePatch
	if patch != nil {
		p = *patch
	}
	var columns []string
	var args []any
	put := func(column string, omitted bool, value any) {
		if patch == nil || !omitted {
			columns = append(columns, column)
			args = append(args, value)
		}
	}
	put(`"name"`, p.Name.IsZero(), r.Name)
	put(`"accessTokenTtl"`, p.AccessTokenTTL.IsZero(), r.AccessTokenTTL)
	put(`"refreshTokenTtl"`, p.RefreshTokenTTL.IsZero(), r.RefreshTokenTTL)
	put(`"signingAlgorithm"`, p.SigningAlgorithm.IsZero(), r.SigningAlgorithm)
	put(`"signingKeyId"`, p.SigningKeyID.IsZero(), r.SigningKeyID)
	put(`"dpopBoundAccessTokensRequired"`, p.DPoPBoundAccessTokensRequired.IsZero(), r.DPoPBoundAccessTokensRequired)
	put(`"disabled"`, p.Disabled.IsZero(), r.Disabled)
	for _, field := range []struct {
		column string
		absent bool
		value  any
	}{
		{`"allowedScopes"`, p.AllowedScopes.IsZero(), r.AllowedScopes},
		{`"customClaims"`, p.CustomClaims.IsZero(), r.CustomClaims},
		{`"metadata"`, p.Metadata.IsZero(), r.Metadata},
	} {
		if patch != nil && field.absent {
			continue
		}
		raw, err := json.Marshal(field.value)
		if err != nil {
			return nil, nil, err
		}
		var param any
		if string(raw) != "null" {
			param = string(raw)
		}
		put(field.column, false, param)
	}
	return columns, args, nil
}

func (s *Store) CreateOAuthResource(ctx context.Context, r op.Resource) error {
	cols, args, err := resourceColumns(r, nil)
	if err != nil {
		return err
	}
	cols = append(cols, `"id"`, `"identifier"`, `"policyVersion"`, `"createdAt"`, `"updatedAt"`)
	args = append(args, r.ID, r.Identifier, r.PolicyVersion, s.date(r.CreatedAt), s.date(r.UpdatedAt))
	query := `INSERT INTO "oauthResource" (` + strings.Join(cols, ",") + ") VALUES (?" + strings.Repeat(",?", len(args)-1) + ")"
	_, err = s.db.ExecContext(ctx, s.bind(query), args...)
	if duplicateConstraint(err) {
		return op.ErrResourceExists
	}
	return err
}

func (s *Store) UpdateOAuthResource(ctx context.Context, id string, patch op.ResourcePatch, now time.Time) (op.Resource, error) {
	var r op.Resource
	if err := patch.Apply(&r); err != nil {
		return r, err
	}
	cols, args, err := resourceColumns(r, &patch)
	if err != nil {
		return op.Resource{}, err
	}
	cols = append(cols, `"updatedAt"`)
	args = append(args, s.date(now), id)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op.Resource{}, err
	}
	defer tx.Rollback()
	query := `UPDATE "oauthResource" SET ` + strings.Join(cols, "=?,") + `=? WHERE "identifier"=?`
	if _, err = tx.ExecContext(ctx, s.bind(query), args...); err != nil {
		return op.Resource{}, err
	}
	r, err = scanOAuthResource(tx.QueryRowContext(ctx, s.bind(resourceByID), id))
	if err != nil {
		return op.Resource{}, err
	}
	if err := tx.Commit(); err != nil {
		return op.Resource{}, err
	}
	return r, nil
}

func (s *Store) DeleteOAuthResource(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "oauthResource" WHERE "identifier"=?`), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return auth.ErrNotFound
	}
	return err
}

func (s *Store) LinkOAuthClientResource(ctx context.Context, id, client string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// Lock the parents in a consistent order across callers until the link commits.
	// SQLite's immediate transaction takes the equivalent write lock at BeginTx.
	for _, parent := range []struct {
		query, key string
		missing    error
	}{
		{`SELECT "id" FROM "oauthResource" WHERE "identifier"=?`, id, auth.ErrNotFound},
		{`SELECT "id" FROM "oauthClient" WHERE "clientId"=?`, client, op.ErrClientNotFound},
	} {
		var key string
		err := tx.QueryRowContext(ctx, s.readForUpdate(parent.query), parent.key).Scan(&key)
		if errors.Is(err, sql.ErrNoRows) {
			return false, parent.missing
		}
		if err != nil {
			return false, err
		}
	}
	var exists bool
	err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "oauthClientResource" WHERE "resourceId"=? AND "clientId"=?)`), id, client).Scan(&exists)
	if err != nil {
		return false, err
	}
	if !exists {
		query := `INSERT INTO "oauthClientResource" ("id","resourceId","clientId","createdAt") VALUES (?,?,?,?)`
		if _, err = tx.ExecContext(ctx, s.bind(query), rand.Text(), id, client, s.date(now)); err != nil {
			return false, err
		}
	}
	return exists, tx.Commit()
}

func (s *Store) UnlinkOAuthClientResource(ctx context.Context, id, client string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "oauthClientResource" WHERE "resourceId"=? AND "clientId"=?`), id, client)
	return err
}
