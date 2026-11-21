package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Stonewrit/stonewrit-auth/plugins/scim"
)

var _ scim.GroupStore = (*Store)(nil)

const scimGroupColumns = `"id","displayName","externalId","createdAt","updatedAt"`

func scanSCIMGroup(row rowScanner) (g scim.Group, e error) {
	var external sql.NullString
	e = row.Scan(&g.ID, &g.DisplayName, &external, &g.CreatedAt, &g.UpdatedAt)
	g.ExternalID = external.String
	return
}

func (s *Store) scimGroupRow(ctx context.Context, tx *sql.Tx, d scim.Directory, id string, lock bool) (scim.Group, error) {
	q := `SELECT ` + scimGroupColumns + ` FROM "scimGroup" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(`"id"`) + `=?`
	sqlQuery := s.bind(q)
	if lock {
		sqlQuery = s.readForUpdate(q)
	}
	g, e := scanSCIMGroup(tx.QueryRowContext(ctx, sqlQuery, d.ID, d.ProvisioningDomainID, id))
	if errors.Is(e, sql.ErrNoRows) {
		e = scim.ErrGroupNotFound
	}
	return g, e
}
func scimMarks(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

// Fetch one page of memberships in a single query. Scope both the edge and
// referenced User, even when an imported database contains inconsistent rows.
func (s *Store) scimGroupMembers(ctx context.Context, tx *sql.Tx, d scim.Directory, groups []scim.Group) error {
	if len(groups) == 0 {
		return nil
	}
	index := make(map[string]int, len(groups))
	args := []any{d.ID, d.ProvisioningDomainID, d.ID}
	for i, g := range groups {
		index[g.ID] = i
		args = append(args, g.ID)
	}
	q := `SELECT m."groupId",u."id",u."displayName" FROM "scimGroupMember" m JOIN "scimUser" u ON ` + s.scimExact(`u."id"`) + `=m."scimUserId"
	WHERE ` + s.scimExact(`u."connectionId"`) + `=? AND ` + s.scimExact(`u."provisioningDomainId"`) + `=? AND ` + s.scimExact(`m."connectionId"`) + `=? AND ` + s.scimExact(`m."groupId"`) + ` IN (` + scimMarks(len(groups)) + `) ORDER BY m."groupId",m."createdAt",m."id" LIMIT ?`
	rows, e := tx.QueryContext(ctx, s.bind(q), append(args, len(groups)*scim.MaxGroupMembers+1)...)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		var groupID string
		var v scim.GroupMember
		if e = rows.Scan(&groupID, &v.ID, &v.DisplayName); e != nil {
			return e
		}
		i, ok := index[groupID]
		if !ok {
			return errors.New("sqlstore: unexpected SCIM group")
		}
		if len(groups[i].Members) >= scim.MaxGroupMembers {
			return errors.New("sqlstore: group membership exceeds configured SCIM maximum")
		}
		groups[i].Members = append(groups[i].Members, v)
	}
	return rows.Err()
}
func (s *Store) scimReadGroup(ctx context.Context, tx *sql.Tx, d scim.Directory, id string, withMembers, lock bool) (scim.Group, error) {
	g, e := s.scimGroupRow(ctx, tx, d, id, lock)
	if e != nil || !withMembers {
		return g, e
	}
	one := []scim.Group{g}
	e = s.scimGroupMembers(ctx, tx, d, one)
	return one[0], e
}
func (s *Store) SCIMGetGroup(ctx context.Context, d scim.Directory, id string, withMembers bool) (out scim.Group, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		var e error
		out, e = s.scimReadGroup(ctx, tx, d, id, withMembers, false)
		return e
	})
	return
}
func (s *Store) SCIMListGroups(ctx context.Context, d scim.Directory, q scim.Query, withMembers bool) (groups []scim.Group, total int, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		from := ` FROM "scimGroup" WHERE ` + s.scimScope()
		args := []any{d.ID, d.ProvisioningDomainID}
		for _, f := range q.Filters {
			var col string
			val := f.Value
			switch f.Attribute {
			case "id":
				col = `"id"`
			case "displayname":
				col = `"displayNameKey"`
				val = scimKey("scim-group-display-name", d.ID, strings.ToLower(val))
			case "externalid":
				col = `"externalIdKey"`
				val = scimKey("scim-group-external-id", d.ID, val)
			default:
				return errors.New("sqlstore: unsupported SCIM Group filter")
			}
			from += " AND " + s.scimExact(col) + "=?"
			args = append(args, val)
		}
		if e := tx.QueryRowContext(ctx, s.bind("SELECT count(*)"+from), args...).Scan(&total); e != nil {
			return e
		}
		if q.Count <= 0 {
			return nil
		}
		rows, e := tx.QueryContext(ctx, s.bind("SELECT "+scimGroupColumns+from+` ORDER BY "orderKey" LIMIT ? OFFSET ?`), append(args, min(100, q.Count), max(0, q.Offset))...)
		if e != nil {
			return e
		}
		for rows.Next() {
			g, e := scanSCIMGroup(rows)
			if e != nil {
				rows.Close()
				return e
			}
			groups = append(groups, g)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if withMembers {
			return s.scimGroupMembers(ctx, tx, d, groups)
		}
		return nil
	})
	return
}
func groupExternal(d scim.Directory, v string) (any, any) {
	if v == "" {
		return nil, nil
	}
	return v, scimKey("scim-group-external-id", d.ID, v)
}

// Resolve only connection-owned User ids. Lock the canonical accounts before
// changing edges so an account deletion cannot race a late membership insert.
// Recheck scoped Users under lock after waiting on a canonical account lock.
func (s *Store) scimGroupUsers(ctx context.Context, tx *sql.Tx, d scim.Directory, ids []string) error {
	for batch := range slices.Chunk(ids, 400) {
		marks := scimMarks(len(batch))
		args := []any{d.ID, d.ProvisioningDomainID}
		for _, id := range batch {
			args = append(args, id)
		}
		q := `SELECT "id","userId" FROM "scimUser" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(`"id"`) + ` IN (` + marks + `) ORDER BY "id"`
		resolve := func(query string) (map[string]bool, error) {
			rows, e := tx.QueryContext(ctx, query, args...)
			if e != nil {
				return nil, e
			}
			defer rows.Close()
			owners := map[string]bool{}
			seen := map[string]bool{}
			for rows.Next() {
				var id, user string
				if e = rows.Scan(&id, &user); e != nil {
					return nil, e
				}
				owners[user] = true
				seen[id] = true
			}
			if e = rows.Err(); e != nil {
				return nil, e
			}
			for _, id := range batch {
				if !seen[id] {
					return nil, scim.ErrInvalidMember
				}
			}
			return owners, nil
		}
		owners, e := resolve(s.bind(q))
		if e != nil {
			return e
		}
		ownerArgs := make([]any, 0, len(owners))
		for _, id := range slices.Sorted(maps.Keys(owners)) {
			ownerArgs = append(ownerArgs, id)
		}
		rows, e := tx.QueryContext(ctx, s.readForUpdate(`SELECT "id" FROM "user" WHERE "id" IN (`+scimMarks(len(owners))+`) ORDER BY "id"`), ownerArgs...)
		if e != nil {
			return e
		}
		n := 0
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			n++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if n != len(owners) {
			return scim.ErrInvalidMember
		}
		if _, e = resolve(s.readForUpdate(q)); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) scimGroupGrant(ctx context.Context, tx *sql.Tx, d scim.Directory, id string) error {
	var exists bool
	e := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "scimProjectionGrant" WHERE `+s.scimScope()+` AND "sourceKind"='group' AND `+s.scimExact(`"sourceId"`)+`=?)`), d.ID, d.ProvisioningDomainID, id).Scan(&exists)
	if e == nil && exists {
		return &scim.Error{Status: 409, Detail: "The Group has externally managed authorization grants"}
	}
	return e
}
func (s *Store) scimGroupEdges(ctx context.Context, tx *sql.Tx, d scim.Directory, g scim.Group, members, validate []string, now time.Time) error {
	if len(members) > scim.MaxGroupMembers {
		return &scim.Error{Status: 400, Type: "invalidValue", Detail: "Too many direct Group members"}
	}
	old := map[string]bool{}
	for _, m := range g.Members {
		old[m.ID] = true
	}
	desired := map[string]bool{}
	check := map[string]bool{}
	for _, id := range validate {
		check[id] = true
	}
	for _, id := range members {
		desired[id] = true
		if !old[id] {
			check[id] = true
		}
	}
	if e := s.scimGroupUsers(ctx, tx, d, slices.Sorted(maps.Keys(check))); e != nil {
		return e
	}
	var removed, added []string
	for id := range old {
		if !desired[id] {
			removed = append(removed, id)
		}
	}
	for id := range desired {
		if !old[id] {
			added = append(added, id)
		}
	}
	for batch := range slices.Chunk(removed, 400) {
		args := []any{d.ID, g.ID}
		for _, id := range batch {
			args = append(args, id)
		}
		_, e := tx.ExecContext(ctx, s.bind(`DELETE FROM "scimGroupMember" WHERE `+s.scimExact(`"connectionId"`)+`=? AND "groupId"=? AND "scimUserId" IN (`+scimMarks(len(batch))+")"), args...)
		if e != nil {
			return e
		}
	}
	slices.Sort(added)
	for batch := range slices.Chunk(added, 100) {
		args := make([]any, 0, len(batch)*6)
		for _, id := range batch {
			args = append(args, rand.Text(), d.ID, g.ID, id, scimKey("scim-group-member", d.ID, g.ID, id), s.date(now))
		}
		_, e := tx.ExecContext(ctx, s.bind(`INSERT INTO "scimGroupMember" ("id","connectionId","groupId","scimUserId","membershipKey","createdAt") VALUES `+strings.TrimSuffix(strings.Repeat("(?,?,?,?,?,?),", len(batch)), ",")), args...)
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) SCIMCreateGroup(ctx context.Context, d scim.Directory, p scim.GroupProfile) (out scim.Group, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		now := time.Now().UTC().Truncate(time.Millisecond)
		id := rand.Text()
		ext, extKey := groupExternal(d, p.ExternalID)
		_, e := tx.ExecContext(ctx, s.bind(`INSERT INTO "scimGroup" ("id","connectionId","provisioningDomainId","displayName","displayNameKey","externalId","externalIdKey","revision","orderKey","createdAt","updatedAt") VALUES (?,?,?,?,?,?,?,0,?,?,?)`), id, d.ID, d.ProvisioningDomainID, p.DisplayName, scimKey("scim-group-display-name", d.ID, strings.ToLower(p.DisplayName)), ext, extKey, fmt.Sprintf("%015d:%s", now.UnixMilli(), rand.Text()[:16]), s.date(now), s.date(now))
		if e != nil {
			return e
		}
		if e = s.scimGroupEdges(ctx, tx, d, scim.Group{ID: id}, p.MemberIDs, nil, now); e != nil {
			return e
		}
		out, e = s.scimReadGroup(ctx, tx, d, id, true, false)
		return e
	})
	return
}
func (s *Store) SCIMUpdateGroup(ctx context.Context, d scim.Directory, id string, change func(scim.Group) (scim.GroupChange, error)) (out scim.Group, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		current, e := s.scimReadGroup(ctx, tx, d, id, true, true)
		if e != nil {
			return e
		}
		p, e := change(current)
		if e != nil {
			return e
		}
		if p.PreserveUnchanged && current.DisplayName == p.DisplayName && current.ExternalID == p.ExternalID && len(current.Members) == len(p.MemberIDs) {
			ids := make([]string, 0, len(current.Members))
			for _, m := range current.Members {
				ids = append(ids, m.ID)
			}
			slices.Sort(ids)
			if slices.Equal(ids, p.MemberIDs) {
				out = current
				return s.scimGroupUsers(ctx, tx, d, p.ValidateIDs)
			}
		}
		if e = s.scimGroupGrant(ctx, tx, d, id); e != nil {
			return e
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		ext, extKey := groupExternal(d, p.ExternalID)
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimGroup" SET "revision"="revision"+1,"displayName"=?,"displayNameKey"=?,"externalId"=?,"externalIdKey"=?,"updatedAt"=? WHERE "id"=?`), p.DisplayName, scimKey("scim-group-display-name", d.ID, strings.ToLower(p.DisplayName)), ext, extKey, s.date(now), id)
		if e != nil {
			return e
		}
		if e = s.scimGroupEdges(ctx, tx, d, current, p.MemberIDs, p.ValidateIDs, now); e != nil {
			return e
		}
		out, e = s.scimReadGroup(ctx, tx, d, id, true, false)
		return e
	})
	return
}
func (s *Store) SCIMDeleteGroup(ctx context.Context, d scim.Directory, id string) error {
	return s.scimTx(ctx, d, func(tx *sql.Tx) error {
		if _, e := s.scimGroupRow(ctx, tx, d, id, true); e != nil {
			return e
		}
		if e := s.scimGroupGrant(ctx, tx, d, id); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, s.bind(`DELETE FROM "scimGroupMember" WHERE `+s.scimExact(`"connectionId"`)+`=? AND "groupId"=?`), d.ID, id)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, s.bind(`DELETE FROM "scimGroup" WHERE "id"=?`), id)
		return e
	})
}
