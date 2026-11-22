package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"strings"
	"unicode/utf8"

	"github.com/Stonewrit/stonewrit-auth/plugins/scim"
)

const scimPolicyTable = "stonewritSCIMProjectionPolicy"

var errProjectionPolicy = &scim.Error{Status: 409, Detail: "The provisioning domain requires its configured application projection policy"}
var errUnknownGrant = &scim.Error{Status: 409, Detail: "The provisioning domain contains a grant with unrecognized provenance"}

// EnableSCIMProjection returns a view of the same connection pool. It installs
// durable domain policy ownership and reconciles existing subjects atomically.
// Later instances can attach the same policy without replaying earlier writes.
func (s *Store) EnableSCIMProjection(ctx context.Context, domain string, policy scim.Projection) (*Store, error) {
	if domain == "" || strings.TrimSpace(domain) != domain || utf8.RuneCountInString(domain) > 255 ||
		strings.TrimSpace(policy.PolicyID) == "" || utf8.RuneCountInString(policy.PolicyID) > 255 ||
		policy.ReconcileUser == nil || (policy.Map == nil) != (policy.Exists == nil) {
		return nil, errors.New("sqlstore: invalid SCIM projection domain or policy")
	}
	// MySQL DDL implicitly commits. Create the empty extension table before
	// entering the transaction that activates it for a particular domain.
	present, err := s.hasKeyOwnerTable(ctx, s.db, scimPolicyTable)
	if err != nil {
		return nil, err
	}
	if !present {
		_, err = s.db.ExecContext(ctx, s.bind(`CREATE TABLE IF NOT EXISTS "stonewritSCIMProjectionPolicy" ("domainKey" VARCHAR(43) PRIMARY KEY, "domain" VARCHAR(255) NOT NULL, "policyId" VARCHAR(255) NOT NULL)`))
		if err != nil {
			// Two first-time instances may race on PostgreSQL's catalog even
			// with IF NOT EXISTS. The winning DDL must be committed and visible.
			present, checkErr := s.hasKeyOwnerTable(ctx, s.db, scimPolicyTable)
			if checkErr != nil || !present {
				return nil, err
			}
		}
	}
	configured := *s
	configured.scimPolicies = maps.Clone(s.scimPolicies)
	if configured.scimPolicies == nil {
		configured.scimPolicies = make(map[string]scim.Projection)
	}
	configured.scimPolicies[domain] = policy
	tx, finish, err := s.beginSCIMTransaction(ctx, domain, true)
	if err != nil {
		return nil, err
	}
	defer finish.rollback()
	id, err := s.scimPolicyID(ctx, tx, domain)
	if err != nil {
		return nil, err
	}
	switch {
	case id == "":
		if err = configured.checkImportedSCIMSources(ctx, tx, domain); err != nil {
			return nil, err
		}

		if policy.Map == nil {
			var existing bool
			err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" WHERE `+s.scimExact(`"provisioningDomainId"`)+`=?)`), domain).Scan(&existing)
			if err != nil {
				return nil, err
			}
			if existing {
				return nil, &scim.Error{Status: 409, Detail: "The provisioning domain has existing role grants and requires a role mapping policy"}
			}
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "stonewritSCIMProjectionPolicy" ("domainKey","domain","policyId") VALUES (?,?,?)`), scimKey("scim-policy", domain), domain, policy.PolicyID)
		if err == nil {
			err = configured.projectSCIMDomain(ctx, tx, domain, false)
		}
	case id != policy.PolicyID:
		err = errProjectionPolicy
	}
	if err != nil {
		return nil, err
	}
	if err = finish.commit(); err != nil {
		return nil, err
	}
	return &configured, nil
}

// ReconcileSCIMProjection rebuilds every subject from current, persisted
// directory facts. Call after changing trusted role mappings or role catalogs.
func (s *Store) ReconcileSCIMProjection(ctx context.Context, domain string) error {
	return s.changeSCIMProjection(ctx, domain, false)
}

// DisableSCIMProjection withdraws all domain grants through the current host
// reconciler before allowing unconfigured Go writers to resume.
func (s *Store) DisableSCIMProjection(ctx context.Context, domain string) error {
	return s.changeSCIMProjection(ctx, domain, true)
}

func (s *Store) changeSCIMProjection(ctx context.Context, domain string, disable bool) error {
	if _, ok := s.scimPolicies[domain]; !ok {
		return errProjectionPolicy
	}
	tx, finish, err := s.beginSCIMTransaction(ctx, domain, true)
	if err != nil {
		return err
	}
	defer finish.rollback()
	if err = s.requireSCIMPolicy(ctx, tx, domain); err != nil {
		return err
	}
	if err = s.projectSCIMDomain(ctx, tx, domain, disable); err != nil {
		return err
	}
	if disable {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "stonewritSCIMProjectionPolicy" WHERE "domainKey"=?`), scimKey("scim-policy", domain)); err != nil {
			return err
		}
	}
	return finish.commit()
}

// The owner of a reserved connection needs the outcome of the physical
// transaction before deciding whether that connection can return to the pool.
type scimTransactionEnd struct {
	tx      *sql.Tx
	done    bool
	release func(error)
}

func (end *scimTransactionEnd) finish(action func() error) error {
	if end.done {
		return sql.ErrTxDone
	}
	end.done = true
	err := action()
	if end.release != nil {
		end.release(err)
	}
	return err
}
func (end *scimTransactionEnd) commit() error { return end.finish(end.tx.Commit) }
func (end *scimTransactionEnd) rollback()     { _ = end.finish(end.tx.Rollback) }

// Upgraded plain and configured writers always acquire the same logical lock,
// including before the first policy row exists. Keep the MySQL connection
// reserved until commit or rollback completes and the advisory lock is released.
func (s *Store) beginSCIMTransaction(ctx context.Context, domain string, write bool) (*sql.Tx, *scimTransactionEnd, error) {
	if !write || s.dialect != "mysql" {
		tx, err := s.beginMembershipChange(ctx)
		if err != nil {
			return nil, nil, err
		}
		if write && s.dialect == "postgres" {
			_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scimKey("scim-projection-domain", domain))
			if err != nil {
				tx.Rollback()
				return nil, nil, err
			}
		}
		// SQLite connections use BEGIN IMMEDIATE.
		return tx, &scimTransactionEnd{tx: tx}, nil
	}
	const name = "SHA2(CONCAT(DATABASE(), '/stonewrit/scim-projection/', ?), 256)"
	busy := &scim.Error{Status: 503, Detail: "The provisioning domain is busy. Retry the request."}
	lock, err := s.acquireMySQLNamedLock(ctx, name, 15, busy, domain)
	if err != nil {
		return nil, nil, err
	}
	tx, err := lock.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		lock.discard()
		return nil, nil, err
	}
	return tx, &scimTransactionEnd{tx: tx, release: lock.release}, nil
}
func (s *Store) scimPolicyID(ctx context.Context, tx *sql.Tx, domain string) (string, error) {
	exists, err := s.hasKeyOwnerTable(ctx, tx, scimPolicyTable)
	if err != nil || !exists {
		return "", err
	}
	var stored, id string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "domain","policyId" FROM "stonewritSCIMProjectionPolicy" WHERE "domainKey"=?`), scimKey("scim-policy", domain)).Scan(&stored, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if stored != domain || id == "" {
		return "", errProjectionPolicy
	}
	return id, nil
}
func (s *Store) requireSCIMPolicy(ctx context.Context, tx *sql.Tx, domain string) error {
	id, err := s.scimPolicyID(ctx, tx, domain)
	if err != nil {
		return err
	}
	if id != s.scimPolicies[domain].PolicyID {
		return errProjectionPolicy
	}
	return nil
}

// Before taking ownership, require each imported row to identify directory
// records from the stated connection and the same canonical application user.
func (s *Store) checkImportedSCIMSources(ctx context.Context, tx *sql.Tx, domain string) error {
	q := `SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" p
	 LEFT JOIN "scimUser" u ON ` + s.scimExact(`u."id"`) + `=p."scimUserId"
	 LEFT JOIN "scimGroup" g ON ` + s.scimExact(`g."id"`) + `=p."sourceId"
	 WHERE ` + s.scimExact(`p."provisioningDomainId"`) + `=? AND (u."id" IS NULL OR g."id" IS NULL
	 OR ` + s.scimExact(`u."connectionId"`) + `<>p."connectionId" OR ` + s.scimExact(`g."connectionId"`) + `<>p."connectionId"
	 OR ` + s.scimExact(`u."provisioningDomainId"`) + `<>p."provisioningDomainId" OR ` + s.scimExact(`g."provisioningDomainId"`) + `<>p."provisioningDomainId"
	 OR ` + s.scimExact(`u."userId"`) + `<>p."userId"))`
	var mismatch bool
	if err := tx.QueryRowContext(ctx, s.bind(q), domain).Scan(&mismatch); err != nil {
		return err
	}
	if mismatch {
		return errUnknownGrant
	}
	return nil
}
