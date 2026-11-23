package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var _ org.ProfileStore = (*Store)(nil)

func (s *Store) OrganizationSlugAvailable(ctx context.Context, slug string) (bool, error) {
	var taken bool
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "organization" WHERE "slug"=?)`), slug).Scan(&taken)
	return !taken && err == nil, err
}

// UpdateOrganizationProfile serializes membership, active selection and profile writes.
// A unique constraint resolves competing claims on the same slug across organizations.
func (s *Store) UpdateOrganizationProfile(ctx context.Context, userID, token, group string, change org.ProfileUpdate) (*org.Organization, error) {
	var row *org.Organization
	var err error
	for range 3 {
		row, err = s.updateOrganizationProfileOnce(ctx, userID, token, group, change)
		if !retryIdentity(err) {
			break
		}
	}
	return row, err
}

func (s *Store) updateOrganizationProfileOnce(ctx context.Context, userID, token, group string, change org.ProfileUpdate) (*org.Organization, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	row, _, err := s.lockProfile(ctx, tx, userID, token, group)
	if err != nil {
		return nil, err
	}
	if err = s.applyOrganizationProfile(ctx, tx, userID, token, row, change); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return row, nil
}

func (s *Store) lockProfile(ctx context.Context, tx *sql.Tx, userID, token, group string) (*org.Organization, org.Member, error) {
	group, err := s.lockMembershipScope(ctx, tx, userID, token, group)
	if errors.Is(err, org.ErrNoActiveOrg) {
		return nil, org.Member{}, org.ErrNotFound
	}
	if err != nil {
		return nil, org.Member{}, err
	}
	actor, err := s.lockMembershipActor(ctx, tx, userID, group)
	if errors.Is(err, org.ErrMemberMissing) {
		return nil, org.Member{}, org.ErrUpdateNotMember
	}
	if err != nil {
		return nil, org.Member{}, err
	}
	if !s.organizationRoles.HasAction(actor.Role, "organization", "update") {
		return nil, org.Member{}, org.ErrUpdateDenied
	}
	row, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=?`), group))
	if err != nil {
		return nil, org.Member{}, err
	}
	return row, actor.Member, nil
}

func (s *Store) applyOrganizationProfile(ctx context.Context, tx *sql.Tx, userID, token string, row *org.Organization, change org.ProfileUpdate) error {
	if change.Name != nil {
		row.Name = *change.Name
	}
	if change.Slug != nil {
		row.Slug = *change.Slug
	}
	if change.ClearLogo {
		row.Logo = nil
	} else if change.Logo != nil {
		row.Logo = change.Logo
	}
	if change.Metadata != nil {
		raw, e := json.Marshal(change.Metadata)
		if e != nil {
			return e
		}
		row.Metadata = raw
	}
	var data any
	if len(row.Metadata) > 0 {
		data = string(row.Metadata)
	}
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "organization" SET "name"=?,"slug"=?,"logo"=?,"metadata"=? WHERE "id"=?`), row.Name, row.Slug, row.Logo, data, row.ID)
	if duplicateConstraint(err) {
		return org.ErrSlugTaken
	}
	if err != nil {
		return err
	}
	// Recheck expiry after waiting for the organization or its unique slug.
	if err = s.lockActiveAccount(ctx, tx, userID, token, time.Now()); errors.Is(err, auth.ErrNotFound) {
		return org.ErrUnauthenticated
	} else if err != nil {
		return err
	}
	return nil
}
