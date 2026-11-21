package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	ak "github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
)

// The canonical apikey table uses one referenceId column for either owner
// kind. Keep the namespace kind across restarts so an unrelated account with
// the same ID can never acquire or delete an organization's credentials.
func (s *Store) ConfigureKeyReference(ctx context.Context, config string, org bool) error {
	if err := s.ensureAPIKeyLedger(ctx); err != nil {
		return err
	}
	kind := "apikey-user-config"
	if org {
		kind = "apikey-org-config"
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT m."userId",m."role",o."id" FROM "member" m JOIN "organization" o ON o."id"=m."organizationId" WHERE 1=0`))
		if err != nil {
			return ak.ErrOrgPlugin
		}
		if err = rows.Close(); err != nil {
			return err
		}
	}
	sum := sha256.Sum256([]byte("api-key-namespace\x00" + config))
	id := hex.EncodeToString(sum[:16])
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var marked bool
	err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE "id"=?)`), id).Scan(&marked)
	if err != nil {
		return err
	}
	if !marked {
		opposite := "user"
		test := org
		if !org {
			opposite = "organization"
			test, err = s.hasKeyOwnerTable(ctx, tx, opposite)
			if err != nil {
				return err
			}
		}
		if test {
			param, _ := s.deviceTokenParameters([]string{config})
			var ambiguous bool
			err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "apikey" k JOIN "`+opposite+`" o ON o."id"=k."referenceId" WHERE k."configId"=`+param+`)`), config).Scan(&ambiguous)
			if err != nil {
				return err
			}
			if ambiguous {
				return errors.New("apikey: existing keys in this namespace match the other owner type; reissue with a distinct configuration")
			}
		}
	}
	query := `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`
	if s.dialect == "mysql" {
		query += ` ON DUPLICATE KEY UPDATE "id"="id"`
	} else {
		query += ` ON CONFLICT ("id") DO NOTHING`
	}
	_, err = tx.ExecContext(ctx, s.bind(query), id, kind, config, s.date(time.Unix(1<<31-1, 0).UTC()), s.date(now), s.date(now))
	if err != nil {
		return err
	}
	var actual, value string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "identifier","value" FROM "verification" WHERE "id"=?`), id).Scan(&actual, &value)
	if err != nil {
		return err
	}
	if actual != kind || value != config {
		return errors.New("apikey: configuration is already registered for a different owner type")
	}
	return tx.Commit()
}

func (s *Store) authorizeKeyOrganization(ctx context.Context, tx *sql.Tx, owner ak.Owner) error {
	if owner.OrganizationID == "" {
		return ak.ErrOrganizationRequired
	}
	if err := s.lockOrganization(ctx, tx, owner.OrganizationID); err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, org.ErrNotFound) {
			return ak.ErrMissing
		}
		return err
	}
	// Only digest verification has no acting member. The organization remains the principal.
	if owner.UserID == "" {
		return nil
	}
	var role string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "role" FROM "member" WHERE "organizationId"=? AND "userId"=?`), owner.OrganizationID, owner.UserID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ak.ErrMembership
	}
	if err != nil {
		return err
	}
	if !owner.Organization.Allows(role, owner.Action) {
		return ak.ErrPermission
	}
	return nil
}
