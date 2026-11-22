package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"slices"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

var _ auth.UserFieldStore = (*Store)(nil)

func (s *Store) appendUserFieldUpdates(fields []string, args []any, columns map[string]any) ([]string, []any) {
	for _, column := range slices.Sorted(maps.Keys(columns)) {
		fields = append(fields, `"`+column+`"=?`)
		args = append(args, s.fieldParameter(columns[column]))
	}
	return fields, args
}

func (s *Store) CreateUserWithFields(ctx context.Context, user auth.User, hash string, first *auth.StoredSession, values auth.UserFieldValues) error {
	return s.createUser(ctx, user, &hash, first, values.Columns())
}

func (s *Store) ReadUserFields(ctx context.Context, id string, fields map[string]auth.UserField) (map[string]any, error) {
	fields, err := sessionfields.NormalizeUser(fields)
	if err != nil {
		return nil, err
	}
	cols := `u."id"`
	var found string
	dest := []any{&found}
	var visible []string
	for _, key := range sessionfields.Names(fields) {
		f := fields[key]
		if f.Hidden {
			continue
		}
		visible = append(visible, f.Column)
		cols += `,u."` + f.Column + `"`
		dest = append(dest, scalarDestination(f.Type))
	}
	err = s.db.QueryRowContext(ctx, s.bind(`SELECT `+cols+` FROM "user" u WHERE `+s.scimExact(`u."id"`)+`=?`), id).Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(visible))
	for i, col := range visible {
		out[col] = scannedScalar(dest[i+1])
	}
	return out, nil
}

func (s *Store) UpdateUserFields(ctx context.Context, id string, actor *auth.Session, patch auth.ProfileUpdate, now time.Time) error {
	if len(patch.PhysicalUserFields()) == 0 {
		return errors.New("sqlstore: empty user field update")
	}
	started := time.Now()
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := `SELECT "id" FROM "user" WHERE ` + s.scimExact(`"id"`) + `=?`
	if s.dialect != "sqlite" {
		q += " FOR UPDATE"
	}
	var found string
	err = tx.QueryRowContext(ctx, s.bind(q), id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrNotFound
	}
	if err != nil {
		return err
	}
	if actor != nil {
		if actor.UserID != id || actor.RequireOwner() != nil {
			return auth.ErrNotFound
		}
		if err := s.lockActiveAccount(ctx, tx, id, actor.Token, now.Add(time.Since(started))); err != nil {
			return err
		}
		param, _ := s.deviceTokenParameters([]string{actor.Token})
		var sessionID string
		var expires time.Time
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "session" WHERE "token"=`+param), actor.Token).Scan(&sessionID, &expires); err != nil {
			return err
		}
		if sessionID != actor.ID || !expires.After(now.Add(time.Since(started))) {
			return auth.ErrNotFound
		}
	}
	if err := s.updateProfile(ctx, tx, id, patch, now); err != nil {
		return err
	}
	return tx.Commit()
}
