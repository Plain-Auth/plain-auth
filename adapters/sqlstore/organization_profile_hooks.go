package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var _ org.ObservedProfileStore = (*Store)(nil)

func (s *Store) PrepareOrganizationProfile(ctx context.Context, actor auth.Session, requestedID string, slug *string) (org.ProfileScope, error) {
	var scope org.ProfileScope
	var err error
	for range 3 {
		scope, err = s.prepareOrganizationProfile(ctx, actor, requestedID, slug)
		if !retryIdentity(err) {
			break
		}
	}
	return scope, err
}

// The short preparation transaction validates the supplied slug before delivering the callback.
func (s *Store) prepareOrganizationProfile(ctx context.Context, actor auth.Session, requestedID string, slug *string) (org.ProfileScope, error) {
	var scope org.ProfileScope
	if actor.RequireOwner() != nil || actor.UserID == "" || actor.Token == "" {
		return scope, org.ErrUnauthenticated
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return scope, err
	}
	defer tx.Rollback()
	row, member, err := s.lockProfile(ctx, tx, actor.UserID, actor.Token, requestedID)
	if err != nil {
		return scope, err
	}
	scope = org.ProfileScope{RequestedID: requestedID, OrganizationID: row.ID, OrganizationCreatedAt: row.CreatedAt, Member: member}
	account, err := s.organizationSessionAccount(ctx, tx, actor)
	if err != nil {
		return org.ProfileScope{}, err
	}
	scope.SessionID, scope.SessionCreatedAt, scope.User = account.id, account.createdAt, account.user
	if slug != nil {
		var occupied bool
		err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "organization" WHERE "slug"=? AND "id"<>`+s.exactSQLValue("?")+`)`), *slug, row.ID).Scan(&occupied)
		if err != nil {
			return org.ProfileScope{}, err
		}
		if occupied {
			return org.ProfileScope{}, org.ErrSlugTaken
		}
	}
	return scope, tx.Commit()
}

// Read the live session again after any wait for the organization lock.
func (s *Store) organizationSessionAccount(ctx context.Context, tx *sql.Tx, actor auth.Session) (orgSessionAccount, error) {
	var account orgSessionAccount
	q := `SELECT ss."id",ss."createdAt",` + userColumns + ` FROM "session" ss JOIN "user" u ON u."id"=ss."userId" WHERE ss."token"=` + s.exactSQLValue("?") + ` AND ss."expiresAt">?`
	err := tx.QueryRowContext(ctx, s.bind(q), actor.Token, s.date(time.Now())).Scan(append([]any{&account.id, &account.createdAt}, userFields(&account.user)...)...)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (actor.ID != "" && account.id != actor.ID || account.user.ID != actor.UserID) {
		return orgSessionAccount{}, org.ErrUnauthenticated
	}
	return account, err
}

type orgSessionAccount struct {
	id        string
	createdAt time.Time
	user      auth.User
}

func (s *Store) CommitOrganizationProfile(ctx context.Context, actor auth.Session, original org.ProfileScope, update org.ProfileUpdate) (*org.Organization, error) {
	update, err := update.Snapshot()
	if err != nil {
		return nil, err
	}
	var row *org.Organization
	for range 3 {
		row, err = s.commitOrganizationProfile(ctx, actor, original, update)
		if !retryIdentity(err) {
			break
		}
	}
	return row, err
}

func (s *Store) commitOrganizationProfile(ctx context.Context, actor auth.Session, original org.ProfileScope, update org.ProfileUpdate) (*org.Organization, error) {
	if actor.RequireOwner() != nil || original.SessionID == "" || (actor.ID != "" && actor.ID != original.SessionID) || actor.UserID != original.User.ID {
		return nil, org.ErrUnauthenticated
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row, member, err := s.lockProfile(ctx, tx, actor.UserID, actor.Token, original.RequestedID)
	if err != nil {
		return nil, err
	}
	if row.ID != original.OrganizationID || !row.CreatedAt.Equal(original.OrganizationCreatedAt) {
		return nil, org.ErrNotFound
	}
	if member.ID != original.Member.ID || member.UserID != original.Member.UserID || member.OrganizationID != original.Member.OrganizationID || member.Role != original.Member.Role || !member.CreatedAt.Equal(original.Member.CreatedAt) {
		return nil, org.ErrUpdateDenied
	}
	current, err := s.organizationSessionAccount(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	if current.id != original.SessionID || !current.createdAt.Equal(original.SessionCreatedAt) || !current.user.CreatedAt.Equal(original.User.CreatedAt) {
		return nil, org.ErrUnauthenticated
	}
	if err = s.applyOrganizationProfile(ctx, tx, actor.UserID, actor.Token, row, update); err != nil {
		return nil, err
	}
	saved, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=?`), row.ID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return saved, nil
}
