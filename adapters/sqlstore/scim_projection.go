package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Plain-Auth/plain-auth/internal/jsjson"
	"github.com/Plain-Auth/plain-auth/plugins/scim"
)

// Expose transaction operations without exposing commit, rollback or the pool.
type scimProjectionTx struct {
	tx          *sql.Tx
	bind, exact func(string) string
}

func (t scimProjectionTx) Exact(column string) string { return t.exact(column) }
func (t scimProjectionTx) Bind(q string) string       { return t.bind(q) }
func (t scimProjectionTx) ExecContext(c context.Context, q string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(c, q, args...)
}
func (t scimProjectionTx) QueryContext(c context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(c, q, args...)
}
func (t scimProjectionTx) QueryRowContext(c context.Context, q string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(c, q, args...)
}

func (s *Store) projectSCIMDomain(ctx context.Context, tx *sql.Tx, domain string, withdraw bool) error {
	// Include imported ledger entries for sources that were removed outside
	// this process. Unsupported provenance must fail the entire transition.
	q := `SELECT "userId" FROM "scimUser" WHERE ` + s.scimExact(`"provisioningDomainId"`) + `=? UNION SELECT "userId" FROM "scimProjectionGrant" WHERE ` + s.scimExact(`"provisioningDomainId"`) + `=? ORDER BY "userId"`
	rows, err := tx.QueryContext(ctx, s.bind(q), domain, domain)
	if err != nil {
		return err
	}
	ids, err := scanStrings(rows)
	if err != nil {
		return err
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err = s.lockAccount(ctx, tx, id); err != nil {
			return err
		}
		if err = s.projectSCIMUser(ctx, tx, domain, id, withdraw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) projectSCIMMembers(ctx context.Context, tx *sql.Tx, d scim.Directory, ids []string) error {
	if _, ok := s.scimPolicies[d.ProvisioningDomainID]; !ok {
		return nil
	}
	owners := map[string]bool{}
	for batch := range slices.Chunk(ids, 400) {
		args := []any{d.ID, d.ProvisioningDomainID}
		for _, id := range batch {
			args = append(args, id)
		}
		q := `SELECT DISTINCT "userId" FROM "scimUser" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(`"id"`) + ` IN (` + scimMarks(len(batch)) + `)`
		rows, err := tx.QueryContext(ctx, s.bind(q), args...)
		if err != nil {
			return err
		}
		found, err := scanStrings(rows)
		if err != nil {
			return err
		}
		for _, id := range found {
			owners[id] = true
		}
	}
	// scimGroupUsers holds the account locks for all added, retained and removed members.
	for _, owner := range slices.Sorted(maps.Keys(owners)) {
		if err := s.projectSCIMUser(ctx, tx, d.ProvisioningDomainID, owner, false); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) scimProjectedSources(ctx context.Context, tx *sql.Tx, domain, owner string) ([]scim.IdentitySource, error) {
	q := `SELECT u."id",u."connectionId",u."active" FROM "scimUser" u WHERE ` + s.scimExact(`u."userId"`) + `=? AND ` + s.scimExact(`u."provisioningDomainId"`) + `=?
	 AND NOT EXISTS (SELECT 1 FROM "scimConnectionBinding" b WHERE ` + s.scimExact(`b."connectionId"`) + `=u."connectionId" AND b."decommissionStatus"<>'active') ORDER BY u."id"`
	rows, err := tx.QueryContext(ctx, s.bind(q), owner, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sources := make([]scim.IdentitySource, 0)
	for rows.Next() {
		src := scim.IdentitySource{Directory: scim.Directory{ProvisioningDomainID: domain}}
		if err = rows.Scan(&src.SCIMUserID, &src.ID, &src.Active); err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	slices.SortFunc(sources, func(a, b scim.IdentitySource) int { return strings.Compare(a.SCIMUserID, b.SCIMUserID) })
	return sources, rows.Err()
}
func (s *Store) scimRoleInputs(ctx context.Context, tx *sql.Tx, d scim.IdentitySource, owner string) ([]scim.RoleMapping, error) {
	q := `SELECT g."id",g."externalId",g."displayName" FROM "scimGroupMember" m JOIN "scimGroup" g ON ` + s.scimExact(`g."id"`) + `=m."groupId" WHERE ` + s.scimExact(`m."scimUserId"`) + `=? AND ` + s.scimExact(`m."connectionId"`) + `=? AND ` + s.scimExact(`g."connectionId"`) + `=? AND ` + s.scimExact(`g."provisioningDomainId"`) + `=? ORDER BY g."id"`
	rows, err := tx.QueryContext(ctx, s.bind(q), d.SCIMUserID, d.ID, d.ID, d.ProvisioningDomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []scim.RoleMapping
	for rows.Next() {
		m := scim.RoleMapping{Directory: d.Directory, SCIMUserID: d.SCIMUserID, UserID: owner}
		var ext sql.NullString
		if err = rows.Scan(&m.Group.ID, &ext, &m.Group.DisplayName); err != nil {
			return nil, err
		}
		m.Group.ExternalID = ext.String
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func scimCallbackFailure(detail string) error { return &scim.Error{Status: 500, Detail: detail} }
func (s *Store) projectSCIMUser(ctx context.Context, tx *sql.Tx, domain, owner string, withdraw bool) error {
	policy, ok := s.scimPolicies[domain]
	if !ok {
		return nil
	}
	view := scimProjectionTx{tx, s.bind, s.scimExact}
	state := scim.ProjectedUser{ProvisioningDomainID: domain, UserID: owner, Grants: []scim.ProjectedGrant{}}
	var err error
	state.Sources, err = s.scimProjectedSources(ctx, tx, domain, owner)
	if err != nil {
		return err
	}
	desired := map[string]scim.ProjectedGrant{}
	catalog := map[scim.RoleLookup]bool{}
	for _, src := range state.Sources {
		if !src.Active {
			continue
		}
		state.Active = true
		if withdraw || policy.Map == nil {
			continue
		}
		mappings, err := s.scimRoleInputs(ctx, tx, src, owner)
		if err != nil {
			return err
		}
		for _, m := range mappings {
			roles, err := policy.Map(ctx, view, m)
			if err != nil {
				return scimCallbackFailure("SCIM role mapping failed")
			}
			for _, raw := range roles {
				role := jsjson.TrimSpace(raw)
				if role == "" {
					continue
				}
				if !utf8.ValidString(role) {
					return scimCallbackFailure("SCIM role mapping returned an invalid role")
				}
				lookup := scim.RoleLookup{Directory: src.Directory, Role: role}
				found, cached := catalog[lookup]
				if !cached {
					found, err = policy.Exists(ctx, view, lookup)
					if err != nil {
						return scimCallbackFailure("SCIM role validation failed")
					}
					catalog[lookup] = found
				}
				if !found {
					continue
				}
				key := scimKey("scim-projection-grant", src.ID, src.SCIMUserID, "group", m.Group.ID, role)
				desired[key] = scim.ProjectedGrant{RoleMapping: m, Role: role, GrantKey: key}
			}
		}
	}
	if err = s.syncSCIMGrantRows(ctx, tx, domain, owner, desired); err != nil {
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(desired)) {
		state.Grants = append(state.Grants, desired[k])
	}
	if err = policy.ReconcileUser(ctx, view, state); err != nil {
		return scimCallbackFailure("SCIM projection reconciliation failed")
	}
	return nil
}
func (s *Store) syncSCIMGrantRows(ctx context.Context, tx *sql.Tx, domain, owner string, desired map[string]scim.ProjectedGrant) error {
	q := `SELECT "id","grantKey","connectionId","scimUserId","sourceKind","sourceId","role" FROM "scimProjectionGrant" WHERE ` + s.scimExact(`"userId"`) + `=? AND ` + s.scimExact(`"provisioningDomainId"`) + `=?`
	rows, err := tx.QueryContext(ctx, s.bind(q), owner, domain)
	if err != nil {
		return err
	}
	existing := map[string]bool{}
	var remove []string
	for rows.Next() {
		var id, key, dir, src, kind, group, role string
		if err = rows.Scan(&id, &key, &dir, &src, &kind, &group, &role); err != nil {
			rows.Close()
			return err
		}
		if kind != "group" || key != scimKey("scim-projection-grant", dir, src, kind, group, role) {
			rows.Close()
			return errUnknownGrant
		}
		existing[key] = true
		if _, ok := desired[key]; !ok {
			remove = append(remove, id)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, id := range remove {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "scimProjectionGrant" WHERE "id"=?`), id); err != nil {
			return err
		}
	}
	now := s.date(time.Now())
	for _, key := range slices.Sorted(maps.Keys(desired)) {
		g := desired[key]
		if existing[key] {
			continue
		}
		value := g.Group.ExternalID
		if value == "" {
			value = g.Group.DisplayName
		}
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimProjectionGrant" ("id","grantKey","connectionId","scimUserId","sourceKind","sourceId","role","provisioningDomainId","userId","sourceValue","createdAt","updatedAt") VALUES (?,?,?,?,'group',?,?,?,?,?,?,?)`), rand.Text(), key, g.ID, g.SCIMUserID, g.Group.ID, g.Role, domain, owner, value, now, now); err != nil {
			return err
		}
	}
	return nil
}

// Called after locking the account but before removing its sources. Account
// deletion and policy transitions serialize on the same canonical account row.
func (s *Store) scimAccountPolicies(ctx context.Context, tx *sql.Tx, user string) ([]string, error) {
	domainKey := s.scimExact(`"provisioningDomainId"`)
	q := `SELECT ` + domainKey + ` FROM "scimUser" WHERE "userId"=? UNION SELECT ` + domainKey + ` FROM "scimProjectionGrant" WHERE "userId"=?`
	rows, err := tx.QueryContext(ctx, s.bind(q), user, user)
	if err != nil {
		return nil, err
	}
	domains, err := scanStrings(rows)
	if err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if err = s.requireSCIMPolicy(ctx, tx, domain); err != nil {
			return nil, err
		}
		if _, ok := s.scimPolicies[domain]; !ok {
			var grants bool
			if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" WHERE "userId"=? AND `+s.scimExact(`"provisioningDomainId"`)+`=?)`), user, domain).Scan(&grants); err != nil {
				return nil, err
			}
			if grants {
				return nil, errUnknownGrant
			}
		} else if err = s.syncSCIMGrantRows(ctx, tx, domain, user, nil); err != nil {
			return nil, err
		}
	}
	return domains, nil
}

func scimAffectedMembers(old scim.Group, change scim.GroupChange) []string {
	all := !change.PreserveUnchanged || old.DisplayName != change.DisplayName || old.ExternalID != change.ExternalID
	ids := map[string]bool{}
	for _, m := range old.Members {
		ids[m.ID] = true
	}
	for _, id := range change.MemberIDs {
		if ids[id] && !all {
			delete(ids, id)
		} else {
			ids[id] = true
		}
	}
	return slices.Sorted(maps.Keys(ids))
}
func (s *Store) checkSCIMUserGrantPolicy(ctx context.Context, tx *sql.Tx, d scim.Directory, id string) error {
	if _, ok := s.scimPolicies[d.ProvisioningDomainID]; !ok {
		return s.scimCheckGrants(ctx, tx, id)
	}
	return s.validateSCIMGrants(ctx, tx, d, `"scimUserId"`, id)
}
func (s *Store) checkSCIMGroupGrantPolicy(ctx context.Context, tx *sql.Tx, d scim.Directory, id string) error {
	if _, ok := s.scimPolicies[d.ProvisioningDomainID]; !ok {
		return s.scimGroupGrant(ctx, tx, d, id)
	}
	return s.validateSCIMGrants(ctx, tx, d, `"sourceId"`, id)
}
func (s *Store) validateSCIMGrants(ctx context.Context, tx *sql.Tx, d scim.Directory, column, id string) error {
	q := `SELECT "grantKey","scimUserId","sourceKind","sourceId","role" FROM "scimProjectionGrant" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(column) + `=?`
	rows, err := tx.QueryContext(ctx, s.bind(q), d.ID, d.ProvisioningDomainID, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, src, kind, group, role string
		if err = rows.Scan(&key, &src, &kind, &group, &role); err != nil {
			return err
		}
		if kind != "group" || key != scimKey("scim-projection-grant", d.ID, src, kind, group, role) {
			return errUnknownGrant
		}
	}
	return rows.Err()
}
