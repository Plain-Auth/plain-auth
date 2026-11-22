package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"

	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
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
	group, err = s.lockMembershipScope(ctx, tx, userID, token, group)
	if errors.Is(err, org.ErrNoActiveOrg) {
		return nil, org.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	actor, err := s.lockMembershipActor(ctx, tx, userID, group)
	if errors.Is(err, org.ErrMemberMissing) {
		return nil, org.ErrUpdateNotMember
	}
	if err != nil {
		return nil, err
	}
	if !membershipHasRole(actor.Role, "owner") && !membershipHasRole(actor.Role, "admin") {
		return nil, org.ErrUpdateDenied
	}
	row, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=?`), group))
	if err != nil {
		return nil, err
	}
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
			return nil, e
		}
		row.Metadata = raw
	}
	var data any
	if len(row.Metadata) > 0 {
		data = string(row.Metadata)
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "organization" SET "name"=?,"slug"=?,"logo"=?,"metadata"=? WHERE "id"=?`), row.Name, row.Slug, row.Logo, data, group)
	if duplicateConstraint(err) {
		return nil, org.ErrSlugTaken
	}
	if err != nil {
		return nil, err
	}
	// Recheck expiry after waiting for the organization or its unique slug.
	if err = s.lockActiveAccount(ctx, tx, userID, token, time.Now()); errors.Is(err, auth.ErrNotFound) {
		return nil, org.ErrUnauthenticated
	} else if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return row, nil
}
