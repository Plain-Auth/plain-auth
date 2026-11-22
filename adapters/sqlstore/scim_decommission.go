package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"

	"github.com/Plain-Auth/plain-auth/plugins/scim"
)

type directoryRetirement struct {
	scim.Retirement
	id            string
	lease, cursor sql.NullString
}

func (s *Store) readRetirement(ctx context.Context, tx *sql.Tx, d scim.Directory) (r directoryRetirement, err error) {
	query := s.readForUpdate(`SELECT "id","connectionId","provisioningDomainId","decommissionStatus","decommissionedAt","decommissionCompletedAt","decommissionLeaseExpiresAt","decommissionReconciledUserCount","decommissionBatchCount","decommissionLeaseId","decommissionCursorUserId" FROM "scimConnectionBinding" WHERE "connectionKey"=?`)
	err = tx.QueryRowContext(ctx, query, scimKey("scim-connection", d.ID)).Scan(&r.id, &r.ConnectionID, &r.ProvisioningDomainID, &r.Status, &r.DecommissionedAt, &r.CompletedAt, &r.RetryAfter, &r.ReconciledUsers, &r.Batches, &r.lease, &r.cursor)
	if err == nil && (r.ConnectionID != d.ID || r.ProvisioningDomainID != d.ProvisioningDomainID) {
		err = scim.ErrDomain
	}
	return
}

const scimLeaseDuration = 5 * time.Minute

func (s *Store) acquireRetirement(ctx context.Context, d scim.Directory) (directoryRetirement, string, error) {
	tx, finishTx, err := s.beginSCIMTransaction(ctx, d.ProvisioningDomainID, true)
	if err != nil {
		return directoryRetirement{}, "", err
	}
	defer finishTx.rollback()
	if err = s.requireSCIMPolicy(ctx, tx, d.ProvisioningDomainID); err != nil {
		return directoryRetirement{}, "", err
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	// A never-used directory starts in the terminal state. If provisioning won
	// the initial binding race, lock the existing row and retire its Users.
	q := `INSERT INTO "scimConnectionBinding" ("id","connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionedAt","decommissionCompletedAt","decommissionBatchCount","decommissionRevision","decommissionReconciledUserCount") VALUES (?,?,?,?,?,'complete',?,?,0,0,0)`
	if s.dialect == "mysql" {
		q += ` ON DUPLICATE KEY UPDATE "id"="id"`
	} else {
		q += ` ON CONFLICT("connectionKey") DO NOTHING`
	}
	_, err = tx.ExecContext(ctx, s.bind(q), rand.Text(), d.ID, scimKey("scim-connection", d.ID), d.ProvisioningDomainID, s.date(now), s.date(now), s.date(now))
	if err != nil {
		return directoryRetirement{}, "", err
	}
	r, err := s.readRetirement(ctx, tx, d)
	if err != nil {
		return r, "", err
	}
	if r.Status == "complete" || (r.Status == "reconciling" && r.lease.Valid && r.RetryAfter != nil && r.RetryAfter.After(now)) {
		return r, "", finishTx.commit()
	}
	if r.Status != "active" && r.Status != "reconciling" {
		return r, "", scim.ErrConflict
	}
	lease := rand.Text()
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionStatus"='reconciling',"decommissionedAt"=COALESCE("decommissionedAt",?),"decommissionCompletedAt"=NULL,"decommissionLeaseId"=?,"decommissionLeaseExpiresAt"=?,"decommissionRevision"="decommissionRevision"+1 WHERE "id"=?`), s.date(now), lease, s.date(now.Add(scimLeaseDuration)), r.id)
	if err != nil {
		return r, "", err
	}
	return r, lease, finishTx.commit()
}

// Each batch commits its identity changes and cursor together. An interrupted
// worker can be replaced safely after the persisted lease expires.
func (s *Store) SCIMDecommission(ctx context.Context, d scim.Directory) (scim.Retirement, error) {
	r, lease, err := s.acquireRetirement(ctx, d)
	if err != nil || lease == "" {
		return r.Retirement, err
	}
	for {
		next, err := s.retirementBatch(ctx, d, lease)
		if err != nil {
			// If the request has ended, the persisted lease remains recoverable.
			_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionLeaseId"=NULL,"decommissionLeaseExpiresAt"=NULL,"decommissionRevision"="decommissionRevision"+1 WHERE "id"=? AND "decommissionLeaseId"=?`), r.id, lease)
			return scim.Retirement{}, err
		}
		if next.Status == "complete" {
			return next.Retirement, nil
		}
	}
}

func (s *Store) retirementBatch(ctx context.Context, d scim.Directory, lease string) (directoryRetirement, error) {
	tx, finishTx, err := s.beginSCIMTransaction(ctx, d.ProvisioningDomainID, true)
	if err != nil {
		return directoryRetirement{}, err
	}
	defer finishTx.rollback()
	if err = s.requireSCIMPolicy(ctx, tx, d.ProvisioningDomainID); err != nil {
		return directoryRetirement{}, err
	}
	r, err := s.readRetirement(ctx, tx, d)
	if err != nil || r.Status == "complete" {
		return r, err
	}
	if r.Status != "reconciling" || r.lease.String != lease {
		return r, scim.ErrManagedConflict
	}
	// Match the canonical page cursor on the application user ID. Each user is
	// reconciled exactly once even if two directory sources occupy the boundary.
	query := `SELECT DISTINCT "userId" FROM "scimUser" WHERE ` + s.scimExact(`"provisioningDomainId"`) + `=?`
	args := []any{d.ProvisioningDomainID}
	if r.cursor.Valid {
		query += ` AND "userId">?`
		args = append(args, r.cursor.String)
	}
	query += ` ORDER BY "userId" LIMIT 51`
	rows, err := tx.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return r, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return r, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return r, err
	}
	end := len(ids) <= 50
	if !end {
		ids = ids[:50]
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, owner := range ids {
		if err = s.retireSubject(ctx, tx, d.ProvisioningDomainID, owner, now); err != nil {
			return r, err
		}
	}
	var cursor any
	if r.cursor.Valid {
		cursor = r.cursor.String
	}
	if len(ids) > 0 {
		cursor = ids[len(ids)-1]
		r.Batches++
		r.ReconciledUsers += len(ids)
	}
	var expires, completed, leaseValue any
	r.Status = "reconciling"
	if end {
		r.Status = "complete"
		completed = s.date(now)
		r.CompletedAt = &now
		r.RetryAfter = nil
	} else {
		next := now.Add(scimLeaseDuration)
		expires = s.date(next)
		r.RetryAfter = &next
		leaseValue = lease
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "scimConnectionBinding" SET "decommissionStatus"=?,"decommissionCursorUserId"=?,"decommissionCompletedAt"=?,"decommissionLeaseId"=?,"decommissionLeaseExpiresAt"=?,"decommissionRevision"="decommissionRevision"+1,"decommissionBatchCount"=?,"decommissionReconciledUserCount"=? WHERE "id"=?`), r.Status, cursor, completed, leaseValue, expires, r.Batches, r.ReconciledUsers, r.id)
	if err != nil {
		return r, err
	}
	return r, finishTx.commit()
}

func (s *Store) retireSubject(ctx context.Context, tx *sql.Tx, domain, owner string, now time.Time) error {
	profile, err := s.scimOwner(ctx, tx, owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var grants bool
	err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" WHERE "userId"=? AND `+s.scimExact(`"provisioningDomainId"`)+`=?)`), owner, domain).Scan(&grants)
	if err != nil {
		return err
	}
	if _, configured := s.scimPolicies[domain]; grants && !configured {
		return &scim.Error{Status: 409, Detail: "The User has externally managed authorization grants"}
	}
	if profile != "" {
		q := `SELECT u."id" FROM "scimUser" u WHERE u."id"=? AND u."userId"=? AND NOT EXISTS (SELECT 1 FROM "scimConnectionBinding" b WHERE ` + s.scimExact(`b."connectionId"`) + `=u."connectionId" AND b."decommissionStatus"<>'active')`
		var id string
		err = tx.QueryRowContext(ctx, s.readForUpdate(q), profile, owner).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "scimSubject" SET "profileSourceId"=NULL,"revision"="revision"+1,"updatedAt"=? WHERE "userId"=? AND "profileSourceId"=?`), s.date(now), owner, profile)
		}
		if err != nil {
			return err
		}
	}
	if err = s.scimRevokeIfInactive(ctx, tx, owner); err != nil {
		return err
	}
	return s.projectSCIMUser(ctx, tx, domain, owner, false)
}

// Persist the access cutoff before beginning the recoverable resource batches.
// The status and audit transition occur once even when the initiating caller
// disconnects or another application instance finishes the retirement.
func (s *Store) managedRetirementStage(ctx context.Context, d scim.Directory, actor string, finish bool) (scim.ManagedState, error) {
	tx, finishTx, err := s.beginSCIMTransaction(ctx, d.ProvisioningDomainID, true)
	if err != nil {
		return scim.ManagedState{}, err
	}
	defer finishTx.rollback()
	if err = s.requireSCIMPolicy(ctx, tx, d.ProvisioningDomainID); err != nil {
		return scim.ManagedState{}, err
	}
	c, err := s.managedConn(ctx, tx, d, true)
	if err != nil {
		return scim.ManagedState{}, err
	}
	now := s.date(time.Now())
	switch {
	case !finish && c.Status == "active":
		q := `UPDATE "scimManagedConnection" SET "status"='decommissioning',"decommissionStartedAt"=?,"decommissionStartedBy"=?,"revision"="revision"+1 WHERE "id"=?`
		_, err = tx.ExecContext(ctx, s.bind(q), now, actor, c.id)
		if err != nil {
			return scim.ManagedState{}, err
		}
		rows, err := tx.QueryContext(ctx, s.readForUpdate(`SELECT "credentialId" FROM "scimManagedCredential" WHERE "connectionRecordId"=? AND "status"='active'`), c.id)
		if err != nil {
			return scim.ManagedState{}, err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return scim.ManagedState{}, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return scim.ManagedState{}, err
		}
		for _, id := range ids {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedCredential" SET "status"='decommissioned',"activeSlotKey"=?,"decommissionedAt"=? WHERE "connectionRecordId"=? AND "credentialId"=?`), id+":inactive", now, c.id, id)
			if err != nil {
				return scim.ManagedState{}, err
			}
		}
		err = s.managedEvent(ctx, tx, c.id, c.revision+1, "connection.decommissioning", actor, nil, time.Now())
	case finish && c.Status == "decommissioning":
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedConnection" SET "status"='decommissioned',"decommissionedAt"=?,"decommissionedBy"=?,"revision"="revision"+1 WHERE "id"=?`), now, actor, c.id)
		if err == nil {
			err = s.managedEvent(ctx, tx, c.id, c.revision+1, "connection.decommissioned", actor, nil, time.Now())
		}
	case c.Status != "decommissioning" && c.Status != "decommissioned":
		err = scim.ErrManagedConflict
	}
	if err != nil {
		return scim.ManagedState{}, err
	}
	c, err = s.managedConn(ctx, tx, d, false)
	if err != nil {
		return scim.ManagedState{}, err
	}
	state, err := s.managedState(ctx, tx, c)
	if err != nil {
		return scim.ManagedState{}, err
	}
	return state, finishTx.commit()
}

func (s *Store) SCIMDecommissionManaged(ctx context.Context, d scim.Directory, actor string) (scim.ManagedRetirement, error) {
	snapshot, err := s.managedRetirementStage(ctx, d, actor, false)
	if err != nil {
		return scim.ManagedRetirement{}, err
	}
	r, err := s.SCIMDecommission(ctx, d)
	if err != nil {
		return scim.ManagedRetirement{}, err
	}
	if r.Status == "complete" && snapshot.Connection.Status != "decommissioned" {
		snapshot, err = s.managedRetirementStage(ctx, d, actor, true)
	}
	return scim.ManagedRetirement{ManagedState: snapshot, Decommission: r}, err
}
