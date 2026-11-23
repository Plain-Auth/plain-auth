package sqlstore

import (
	"context"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

func (s *Store) AdminCreateTransaction(ctx context.Context, now time.Time, fn func(auth.AdminUserCreator) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(&adminTX{s: s, ctx: ctx, tx: tx, now: now}); err != nil {
		return err
	}
	return tx.Commit()
}

// The transaction selects the configured columns alongside the core user row.
func (t *adminTX) SelectAdminUserFields(fields map[string]auth.UserField, project func(*auth.User, map[string]any) error) error {
	normalized, err := sessionfields.NormalizeUser(fields)
	if err != nil {
		return err
	}
	for _, name := range sessionfields.Names(normalized) {
		field := normalized[name]
		if !field.Hidden {
			t.profileFields = append(t.profileFields, field)
		}
	}
	t.projectProfile = project
	return nil
}
