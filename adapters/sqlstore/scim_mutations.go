package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/scim"
)

type scimTombstone struct{ id, owner, profile string }

func (s *Store) scimTomb(ctx context.Context, tx *sql.Tx, d scim.Directory, external string) (t scimTombstone, err error) {
	if external == "" {
		return t, nil
	}
	q := `SELECT "id","userId","profile" FROM "scimIdentityTombstone" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(`"externalIdKey"`) + `=?`
	err = tx.QueryRowContext(ctx, s.bind(q), d.ID, d.ProvisioningDomainID, scimKey("scim-user-external-id", d.ID, external)).Scan(&t.id, &t.owner, &t.profile)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}
func (s *Store) scimUpdateCore(ctx context.Context, tx *sql.Tx, id string, p scim.Profile, now time.Time) error {
	// Compare email before assigning it. MySQL evaluates assignments left to right.
	_, err := s.execUserUpdate(ctx, tx, id, s.bind(`UPDATE "user" SET "emailVerified"=CASE WHEN "email"=? THEN "emailVerified" ELSE ? END,"email"=?,"name"=?,"updatedAt"=? WHERE "id"=?`), p.PrimaryEmail, false, p.PrimaryEmail, p.DisplayName, s.date(now), id)
	return err
}
func (s *Store) scimRevokeIfInactive(ctx context.Context, tx *sql.Tx, id string) error {
	// Caller holds the canonical user lock. Use a current read on MySQL in
	// case another connection changed the same subject before we acquired it.
	query := `SELECT u."id" FROM "scimUser" u WHERE u."userId"=? AND u."active"=? AND NOT EXISTS
		(SELECT 1 FROM "scimConnectionBinding" b WHERE ` + s.scimExact(`b."connectionId"`) + `=u."connectionId" AND b."decommissionStatus"<>'active') LIMIT 1`
	var active string
	err := tx.QueryRowContext(ctx, s.readForUpdate(query), id, true).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.deleteSessionsTx(ctx, tx, `"userId"=?`, id)
	}
	return err
}
func (s *Store) scimOwner(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	if err := s.lockAccount(ctx, tx, id); err != nil {
		return "", err
	}
	var source sql.NullString
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "profileSourceId" FROM "scimSubject" WHERE "userId"=?`), id).Scan(&source)
	return source.String, err
}

var _ scim.IdentityStore = (*Store)(nil)

func (s *Store) SCIMCreate(ctx context.Context, d scim.Directory, p scim.Profile) (scim.Record, error) {
	return s.SCIMCreateResolved(ctx, d, p, scim.IdentityResolution{})
}

// SCIMReuse reports, in a read transaction that closes before any resolver
// runs, whether creating p reclaims an inactive SCIM User or a deleted
// User's account through its externalId.
func (s *Store) SCIMReuse(ctx context.Context, d scim.Directory, p scim.Profile) (reuse bool, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		if p.ExternalID != "" {
			u, e := s.scimFind(ctx, tx, d, `"externalIdKey"`, scimKey("scim-user-external-id", d.ID, p.ExternalID))
			switch {
			case e == nil:
				if u.Active {
					return scim.ErrConflict
				}
				reuse = true
				return nil
			case !errors.Is(e, scim.ErrNotFound):
				return e
			}
			t, e := s.scimTomb(ctx, tx, d, p.ExternalID)
			if e != nil {
				return e
			}
			if t.id != "" {
				reuse = true
				return nil
			}
		}
		_, e := s.scimFind(ctx, tx, d, `"userNameKey"`, scimKey("scim-user-name", d.ID, strings.ToLower(p.UserName)))
		if e == nil {
			return scim.ErrConflict
		}
		if errors.Is(e, scim.ErrNotFound) {
			return nil
		}
		return e
	})
	return
}

// SCIMCreateResolved creates a SCIM User and its account, or attaches it to
// the account a resolver linked.
func (s *Store) SCIMCreateResolved(ctx context.Context, d scim.Directory, p scim.Profile, r scim.IdentityResolution) (out scim.Record, err error) {
	link := r.Action == "link"
	err = s.scimWriteTx(ctx, d, func(tx *sql.Tx) error {
		now := time.Now().UTC().Truncate(time.Millisecond)
		if p.ExternalID != "" {
			u, e := s.scimFind(ctx, tx, d, `"externalIdKey"`, scimKey("scim-user-external-id", d.ID, p.ExternalID))
			switch {
			case e == nil:
				// A link decided before an inactive User was reclaimed no
				// longer applies.
				if u.Active || link {
					return scim.ErrConflict
				}
				out, e = s.scimReplace(ctx, tx, d, u, p, now)
				return e
			case !errors.Is(e, scim.ErrNotFound):
				return e
			}
		}
		t, e := s.scimTomb(ctx, tx, d, p.ExternalID)
		if e != nil {
			return e
		}
		if t.id != "" && link {
			return scim.ErrConflict
		}
		u := directoryUser{Record: scim.Record{ID: rand.Text(), Profile: p, CreatedAt: now, UpdatedAt: now}, owner: t.owner}
		switch {
		case link:
			if e = s.lockAccount(ctx, tx, r.UserID); errors.Is(e, authn.ErrNotFound) {
				return scim.ErrResolvedUserMissing
			} else if e != nil {
				return e
			}
			u.owner = r.UserID
			if e = s.scimAttach(ctx, tx, u.owner, u.ID, r.Profile, p, now); e != nil {
				return e
			}
		case t.id == "":
			u.owner = rand.Text()
			_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), u.owner, p.DisplayName, p.PrimaryEmail, false, s.date(now), s.date(now))
			if e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimSubject" ("id","userId","profileSourceId","revision","createdAt","updatedAt") VALUES (?,?,?,1,?,?)`), rand.Text(), u.owner, u.ID, s.date(now), s.date(now))
			if e != nil {
				return e
			}
		default:
			if e = s.scimAttach(ctx, tx, u.owner, u.ID, t.profile, p, now); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "scimIdentityTombstone" WHERE "id"=?`), t.id); e != nil {
				return e
			}
		}
		if e = s.scimInsert(ctx, tx, d, u); e != nil {
			return e
		}
		if !p.Active {
			if e = s.scimRevokeIfInactive(ctx, tx, u.owner); e != nil {
				return e
			}
		}
		out = u.Record
		return s.projectSCIMUser(ctx, tx, d.ProvisioningDomainID, u.owner, false)
	})
	return
}

// scimAttach joins source to an existing account's subject, creating the
// subject when the account has none, and hands the account's email and name
// to the source for profile "manage".
func (s *Store) scimAttach(ctx context.Context, tx *sql.Tx, owner, source, profile string, p scim.Profile, now time.Time) error {
	current, e := s.scimOwner(ctx, tx, owner)
	if errors.Is(e, sql.ErrNoRows) {
		_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimSubject" ("id","userId","profileSourceId","revision","createdAt","updatedAt") VALUES (?,?,NULL,1,?,?)`), rand.Text(), owner, s.date(now), s.date(now))
		current = ""
	}
	if e != nil {
		return e
	}
	switch profile {
	case "manage":
		if current != "" {
			return scim.ErrConflict
		}
		if e = s.scimUpdateCore(ctx, tx, owner, p, now); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimSubject" SET "profileSourceId"=?,"revision"="revision"+1,"updatedAt"=? WHERE "userId"=?`), source, s.date(now), owner)
	case "preserve":
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimSubject" SET "revision"="revision"+1,"updatedAt"=? WHERE "userId"=?`), s.date(now), owner)
	default:
		return scim.ErrConflict
	}
	return e
}

func (s *Store) SCIMUpdate(ctx context.Context, d scim.Directory, id string, change func(scim.Record) (scim.Profile, error)) (out scim.Record, err error) {
	err = s.scimWriteTx(ctx, d, func(tx *sql.Tx) error {
		u, e := s.scimFind(ctx, tx, d, `"id"`, id)
		if e != nil {
			return e
		}
		p, e := change(u.Record)
		if e != nil {
			return e
		}
		out, e = s.scimReplace(ctx, tx, d, u, p, time.Now().UTC().Truncate(time.Millisecond))
		return e
	})
	return
}

// Imported projection grants require the application's role reconciler. Leave
// both the source and its grants intact when handling these Users locally.
func (s *Store) scimCheckGrants(ctx context.Context, tx *sql.Tx, id string) error {
	var exists bool
	err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" WHERE "scimUserId"=?)`), id).Scan(&exists)
	if err == nil && exists {
		return &scim.Error{Status: 409, Detail: "The User has externally managed authorization grants"}
	}
	return err
}
func (s *Store) scimReplace(ctx context.Context, tx *sql.Tx, d scim.Directory, u directoryUser, p scim.Profile, now time.Time) (scim.Record, error) {
	source, e := s.scimOwner(ctx, tx, u.owner)
	if e != nil {
		return scim.Record{}, e
	}
	if e = s.checkSCIMUserGrantPolicy(ctx, tx, d, u.ID); e != nil {
		return scim.Record{}, e
	}
	if p.ExternalID != u.ExternalID {
		t, e := s.scimTomb(ctx, tx, d, p.ExternalID)
		if e != nil {
			return scim.Record{}, e
		}
		if t.id != "" {
			return scim.Record{}, scim.ErrConflict
		}
	}
	if source == u.ID {
		if e = s.scimUpdateCore(ctx, tx, u.owner, p, now); e != nil {
			return scim.Record{}, e
		}
	}
	args, e := s.scimArgs(d, p, now)
	if e != nil {
		return scim.Record{}, e
	}
	cols := strings.Split(scimMutableColumns, ",")
	_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimUser" SET `+strings.Join(cols, "=?,")+`=? WHERE "id"=?`), append(args, u.ID)...)
	if e != nil {
		return scim.Record{}, e
	}
	_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimSubject" SET "revision"="revision"+1,"updatedAt"=? WHERE "userId"=?`), s.date(now), u.owner)
	if e != nil {
		return scim.Record{}, e
	}
	if !p.Active {
		if e = s.scimRevokeIfInactive(ctx, tx, u.owner); e != nil {
			return scim.Record{}, e
		}
	}
	u.Profile = p
	u.UpdatedAt = now
	return u.Record, s.projectSCIMUser(ctx, tx, d.ProvisioningDomainID, u.owner, false)
}
func (s *Store) SCIMDelete(ctx context.Context, d scim.Directory, id string) error {
	return s.scimWriteTx(ctx, d, func(tx *sql.Tx) error {
		u, e := s.scimFind(ctx, tx, d, `"id"`, id)
		if e != nil {
			return e
		}
		source, e := s.scimOwner(ctx, tx, u.owner)
		if e != nil {
			return e
		}
		if e = s.checkSCIMUserGrantPolicy(ctx, tx, d, u.ID); e != nil {
			return e
		}
		now := s.date(time.Now())
		profile := "preserve"
		if source == u.ID {
			profile = "manage"
		}
		if u.ExternalID != "" {
			_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimIdentityTombstone" ("id","connectionId","provisioningDomainId","externalId","externalIdKey","userId","profile","deletedAt") VALUES (?,?,?,?,?,?,?,?)`), rand.Text(), d.ID, d.ProvisioningDomainID, u.ExternalID, scimKey("scim-user-external-id", d.ID, u.ExternalID), u.owner, profile, now)
			if e != nil {
				return e
			}
		}
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimGroup" SET "revision"="revision"+1,"updatedAt"=? WHERE `+s.scimScope()+` AND "id" IN (SELECT "groupId" FROM "scimGroupMember" WHERE "scimUserId"=?)`), now, d.ID, d.ProvisioningDomainID, id)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "scimGroupMember" WHERE "scimUserId"=? AND `+s.scimExact(`"connectionId"`)+`=?`), id, d.ID)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "scimUser" WHERE "id"=?`), id)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimSubject" SET "revision"="revision"+1,"updatedAt"=?,"profileSourceId"=CASE WHEN "profileSourceId"=? THEN NULL ELSE "profileSourceId" END WHERE "userId"=?`), now, id, u.owner)
		if e != nil {
			return e
		}
		if e = s.scimRevokeIfInactive(ctx, tx, u.owner); e != nil {
			return e
		}
		return s.projectSCIMUser(ctx, tx, d.ProvisioningDomainID, u.owner, false)
	})
}

// Core account deletion must remove directory data on engines that accept the
// canonical inline references without enforcing their cascading deletes.
func (s *Store) cleanupSCIMAccount(ctx context.Context, tx *sql.Tx, userID string) error {
	exists, err := s.hasKeyOwnerTable(ctx, tx, "scimUser")
	if err != nil || !exists {
		return err
	}
	domains, err := s.scimAccountPolicies(ctx, tx, userID)
	if err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM "scimGroupMember" WHERE "scimUserId" IN (SELECT "id" FROM "scimUser" WHERE "userId"=?)`,
		`DELETE FROM "scimProjectionGrant" WHERE "userId"=?`,
		`DELETE FROM "scimUser" WHERE "userId"=?`,
		`DELETE FROM "scimIdentityTombstone" WHERE "userId"=?`,
		`DELETE FROM "scimSubject" WHERE "userId"=?`,
	} {
		if _, err = tx.ExecContext(ctx, s.bind(q), userID); err != nil {
			return err
		}
	}
	for _, domain := range domains {
		if err = s.projectSCIMUser(ctx, tx, domain, userID, false); err != nil {
			return err
		}
	}
	return nil
}
