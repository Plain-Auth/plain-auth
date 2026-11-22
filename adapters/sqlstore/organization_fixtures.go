package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// SaveFixtureOrganization creates only the supplied row in a dedicated test database.
func (s *Store) SaveFixtureOrganization(ctx context.Context, o org.Organization) (org.Organization, error) {
	var zero org.Organization
	if o.ID == "" || o.Name == "" || o.Slug == "" || o.CreatedAt.IsZero() || len(o.Metadata) > 0 && !json.Valid(o.Metadata) {
		return zero, errors.New("sqlstore: organization fixture requires an ID, name, slug, timestamp and valid optional metadata")
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	var metadata any
	if len(o.Metadata) > 0 {
		metadata = string(o.Metadata)
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "organization" ("id","name","slug","logo","metadata","createdAt") VALUES (?,?,?,?,?,?)`), o.ID, o.Name, o.Slug, o.Logo, metadata, s.date(o.CreatedAt))
	if err != nil {
		if duplicateConstraint(err) {
			return zero, org.ErrDuplicate
		}
		return zero, err
	}
	found, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE `+s.scimExact(`o."id"`)+`=?`), o.ID))
	if err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return *found, nil
}

// DeleteFixtureOrganization removes local fixture data under the shared
// organization lock, including when only a different process enables teams.
func (s *Store) DeleteFixtureOrganization(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("sqlstore: an organization fixture ID is required")
	}
	var err error
	for range 3 {
		err = s.deleteFixtureOrganization(ctx, id)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) deleteFixtureOrganization(ctx context.Context, id string) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockOrganization(ctx, tx, id); errors.Is(err, org.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	hasDirectories, err := s.hasKeyOwnerTable(ctx, tx, "ssoProvider")
	if err != nil {
		return err
	}
	if hasDirectories {
		var used bool
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "ssoProvider" WHERE `+s.scimExact(`"organizationId"`)+`=?)`), id).Scan(&used); err != nil {
			return err
		}
		if used {
			return errors.New("authtest: delete the organization's managed SSO providers before its fixture")
		}
	}
	if err = s.cleanupFixtureOrganizationBilling(ctx, tx, id); err != nil {
		return err
	}
	if err = s.cleanupFixtureOrganizationKeys(ctx, tx, id); err != nil {
		return err
	}
	eqOrg := s.scimExact(`"organizationId"`) + `=?`
	activeOrg := s.scimExact(`"activeOrganizationId"`) + `=?`
	teams, err := s.hasKeyOwnerTable(ctx, tx, "team")
	if err != nil {
		return err
	}
	clearSelected := `UPDATE "session" SET "activeOrganizationId"=NULL WHERE ` + activeOrg
	if teams {
		clearSelected = `UPDATE "session" SET "activeOrganizationId"=NULL,"activeTeamId"=NULL WHERE ` + activeOrg
		ids := `SELECT "id" FROM "team" WHERE ` + eqOrg
		if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeTeamId"=NULL WHERE `+s.scimExact(`"activeTeamId"`)+` IN (`+ids+`)`), id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "teamMember" WHERE `+s.scimExact(`"teamId"`)+` IN (`+ids+`)`), id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "team" WHERE `+eqOrg), id); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, s.bind(clearSelected), id); err != nil {
		return err
	}
	for _, table := range []string{"invitation", "member"} {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "`+table+`" WHERE `+eqOrg), id); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "organization" WHERE `+s.scimExact(`"id"`)+`=?`), id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) cleanupFixtureOrganizationKeys(ctx context.Context, tx *sql.Tx, id string) error {
	exists, err := s.hasKeyOwnerTable(ctx, tx, "apikey")
	if err != nil || !exists {
		return err
	}
	where := s.scimExact(`"apikey"."referenceId"`) + `=?`
	classified := `SELECT 1 FROM "verification" v WHERE ` + s.scimExact(`v."value"`) + `=` + s.scimExact(`"apikey"."configId"`)
	var unknown bool
	err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "apikey" WHERE `+where+` AND NOT EXISTS (`+classified+` AND v."identifier" IN ('apikey-user-config','apikey-org-config')))`), id).Scan(&unknown)
	if err != nil {
		return err
	}
	if unknown {
		return errors.New("authtest: classify the owner namespace of imported API keys before deleting the organization")
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "apikey" WHERE `+where+` AND EXISTS (`+classified+` AND v."identifier"='apikey-org-config')`), id)
	return err
}

func (s *Store) cleanupFixtureOrganizationBilling(ctx context.Context, tx *sql.Tx, id string) error {
	// Only organization-prefixed verification identifiers belong to this tenant.
	keys := []string{"stripe-org-checkout:", "stripe-org-sync:", "stripe-org-event:", "stripe-org-return:", seatsDue, seatsIdle}
	args := make([]any, 0, len(keys))
	for _, key := range keys {
		args = append(args, key+id)
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+s.scimExact(`"identifier"`)+` IN (?,?,?,?,?,?)`), args...); err != nil {
		return err
	}
	billing, err := s.organizationBillingColumn(ctx, tx)
	if err != nil || !billing {
		return err
	}
	var customer sql.NullString
	if err = tx.QueryRowContext(ctx, s.bind(`SELECT "stripeCustomerId" FROM "organization" WHERE `+s.scimExact(`"id"`)+`=?`), id).Scan(&customer); err != nil {
		return err
	}
	ref := s.scimExact(`"referenceId"`) + `=?`
	var customerShared bool
	if customer.Valid && customer.String != "" {
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE `+s.scimExact(`"stripeCustomerId"`)+`=?) OR EXISTS(SELECT 1 FROM "organization" WHERE `+s.scimExact(`"stripeCustomerId"`)+`=? AND `+s.scimExact(`"id"`)+`<>?)`), customer.String, customer.String, id).Scan(&customerShared); err != nil {
			return err
		}
		if customerShared {
			return errors.New("authtest: resolve the shared Stripe customer before deleting the organization")
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "subscription" WHERE `+ref+` AND `+s.scimExact(`"stripeCustomerId"`)+`=?`), id, customer.String); err != nil {
			return err
		}
	}
	// A reference ID alone does not distinguish an organization from an
	// account. Preserve proven account subscriptions and reject unknown rows.
	var ambiguous bool
	q := `SELECT EXISTS(SELECT 1 FROM "subscription" WHERE ` + ref + ` AND NOT EXISTS(SELECT 1 FROM "user" u WHERE ` + s.scimExact(`u."id"`) + `=? AND u."stripeCustomerId" IS NOT NULL AND u."stripeCustomerId"<>'' AND ` + s.scimExact(`u."stripeCustomerId"`) + `=` + s.scimExact(`"subscription"."stripeCustomerId"`) + `))`
	if err = tx.QueryRowContext(ctx, s.bind(q), id, id).Scan(&ambiguous); err != nil {
		return err
	}
	if ambiguous {
		return errors.New("authtest: reconcile unclassified local subscriptions before deleting the organization")
	}
	return nil
}
