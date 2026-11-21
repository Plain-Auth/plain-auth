package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
)

func (s *Store) WithOrganizationTeams(opts org.TeamOptions) (org.TeamStore, error) {
	if opts.MaximumTeams < 0 || (opts.MaximumMembersPerTeam != nil && *opts.MaximumMembersPerTeam < 0) {
		return nil, errors.New("sqlstore: team limits must be nonnegative")
	}
	if opts.MaximumMembersPerTeam != nil {
		limit := *opts.MaximumMembersPerTeam
		opts.MaximumMembersPerTeam = &limit
	}
	copy := *s
	copy.teamOptions = &opts
	// This zero-row query validates all required extension columns at startup.
	rows, err := s.db.Query(s.bind(`SELECT t."memberCount",tm."membershipKey",ss."activeTeamId",i."teamId" FROM "team" t,"teamMember" tm,"session" ss,"invitation" i WHERE 1=0`))
	if err != nil {
		return nil, errors.New("sqlstore: organization teams require the organization-teams schema")
	}
	return &copy, rows.Close()
}

type teamTransaction struct {
	*Store
	ctx                   context.Context
	tx                    *sql.Tx
	actor                 org.TeamActor
	activeOrg, activeTeam string
}

func (s *Store) withTeamActor(ctx context.Context, a org.TeamActor, otherUser string, fn func(teamTransaction) error) error {
	if s.teamOptions == nil {
		return errors.New("sqlstore: organization teams are disabled")
	}
	var err error
	for range 3 {
		err = s.runTeamTransaction(ctx, a, otherUser, fn)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}
func (s *Store) runTeamTransaction(ctx context.Context, a org.TeamActor, otherUser string, fn func(teamTransaction) error) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Lock both accounts in stable order before the organization. Account deletion takes the same account locks.
	if otherUser != "" && otherUser != a.UserID {
		users := []string{a.UserID, otherUser}
		slices.Sort(users)
		for _, id := range users {
			if err = s.lockAccount(ctx, tx, id); err != nil {
				if errors.Is(err, authn.ErrNotFound) {
					if id == a.UserID {
						return org.ErrUnauthenticated
					}
					return org.ErrTeamOrgMember
				}
				return err
			}
		}
	}
	if _, err = s.organizationActor(ctx, tx, a.UserID, a.SessionID, time.Now()); err != nil {
		return err
	}
	t := teamTransaction{Store: s, ctx: ctx, tx: tx, actor: a}
	err = tx.QueryRowContext(ctx, s.bind(`SELECT COALESCE("activeOrganizationId",''),COALESCE("activeTeamId",'') FROM "session" WHERE "id"=? AND "userId"=?`), a.SessionID, a.UserID).Scan(&t.activeOrg, &t.activeTeam)
	if err != nil {
		return err
	}
	if err = fn(t); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ActiveTeam(ctx context.Context, a org.TeamActor) (*string, error) {
	var id *string
	query := `SELECT t."id" FROM "session" ss JOIN "team" t ON t."id"=ss."activeTeamId" AND t."organizationId"=ss."activeOrganizationId"
		JOIN "teamMember" tm ON tm."teamId"=t."id" AND tm."userId"=ss."userId"
		JOIN "member" m ON m."organizationId"=t."organizationId" AND m."userId"=ss."userId"
		WHERE ss."id"=? AND ss."userId"=?`
	err := s.db.QueryRowContext(ctx, s.bind(query), a.SessionID, a.UserID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return id, err
}

func (t teamTransaction) memberRole(orgID, userID string) (string, error) {
	var role string
	err := t.tx.QueryRowContext(t.ctx, t.bind(`SELECT "role" FROM "member" WHERE "organizationId"=? AND "userId"=?`), orgID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}
func (t teamTransaction) authorizeOrg(explicit string, missing, denied *authn.APIError) (string, error) {
	id := explicit
	if id == "" {
		id = t.activeOrg
	}
	if id == "" {
		return "", org.ErrNoActiveOrg
	}
	if err := t.lockOrganization(t.ctx, t.tx, id); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			return "", missing
		}
		return "", err
	}
	role, err := t.memberRole(id, t.actor.UserID)
	if err != nil {
		return "", err
	}
	if role == "" {
		return "", missing
	}
	roles := strings.Split(role, ",")
	if denied != nil && !slices.Contains(roles, "owner") && !slices.Contains(roles, "admin") {
		return "", denied
	}
	return id, nil
}

const teamFields = `t."id",t."name",t."organizationId",t."createdAt",t."updatedAt"`

func scanTeam(r rowScanner) (*org.Team, error) {
	var t org.Team
	err := r.Scan(&t.ID, &t.Name, &t.OrganizationID, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrTeamNotFound
	}
	return &t, err
}
func (s *Store) findTeam(ctx context.Context, tx *sql.Tx, orgID, id string) (*org.Team, error) {
	return scanTeam(tx.QueryRowContext(ctx, s.bind(`SELECT `+teamFields+` FROM "team" t WHERE t."organizationId"=? AND t."id"=?`), orgID, id))
}
func (s *Store) insertTeam(ctx context.Context, tx *sql.Tx, orgID, name string, updated bool) (*org.Team, error) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	t := org.Team{ID: rand.Text(), Name: name, OrganizationID: orgID, CreatedAt: now}
	var date any
	if updated {
		t.UpdatedAt = &now
		date = s.date(now)
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "team" ("id","name","organizationId","memberCount","createdAt","updatedAt") VALUES(?,?,?,0,?,?)`), t.ID, name, orgID, s.date(now), date)
	return &t, err
}
func (s *Store) CreateTeam(ctx context.Context, a org.TeamActor, explicit, name string) (result *org.Team, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		id, err := t.authorizeOrg(explicit, org.ErrInviteDenied, org.ErrTeamCreate)
		if err != nil {
			return err
		}
		if max := s.teamOptions.MaximumTeams; max > 0 {
			var count int
			if err = t.tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`), id).Scan(&count); err != nil {
				return err
			}
			if count >= max {
				return org.ErrTeamLimit
			}
		}
		result, err = s.insertTeam(ctx, t.tx, id, name, true)
		return err
	})
	return
}
func (s *Store) UpdateTeam(ctx context.Context, a org.TeamActor, explicit, id string, name *string) (result *org.Team, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		group, err := t.authorizeOrg(explicit, org.ErrTeamUpdate, org.ErrTeamUpdate)
		if err != nil {
			return err
		}
		result, err = s.findTeam(ctx, t.tx, group, id)
		if err != nil {
			return err
		}
		if name != nil {
			result.Name = *name
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		result.UpdatedAt = &now
		_, err = t.tx.ExecContext(ctx, s.bind(`UPDATE "team" SET "name"=?,"updatedAt"=? WHERE "id"=? AND "organizationId"=?`), result.Name, s.date(now), id, group)
		return err
	})
	return
}
func (s *Store) RemoveTeam(ctx context.Context, a org.TeamActor, explicit, id string) error {
	return s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		group, err := t.authorizeOrg(explicit, org.ErrTeamDeleteActive, org.ErrTeamDelete)
		if err != nil {
			return err
		}
		if t.activeTeam == id {
			return org.ErrTeamDeleteActive
		}
		if _, err = s.findTeam(ctx, t.tx, group, id); err != nil {
			return err
		}
		if !s.teamOptions.AllowRemovingAllTeams {
			var count int
			if err = t.tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "team" WHERE "organizationId"=?`), group).Scan(&count); err != nil {
				return err
			}
			if count <= 1 {
				return org.ErrTeamLast
			}
		}
		if _, err = t.tx.ExecContext(ctx, s.bind(`DELETE FROM "teamMember" WHERE "teamId"=?`), id); err != nil {
			return err
		}
		if _, err = t.tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeTeamId"=NULL WHERE "activeTeamId"=?`), id); err != nil {
			return err
		}
		if _, err = t.tx.ExecContext(ctx, s.bind(`DELETE FROM "team" WHERE "id"=? AND "organizationId"=?`), id, group); err != nil {
			return err
		}
		return s.pruneTeamInvitations(ctx, t.tx, group, id)
	})
}
func (s *Store) pruneTeamInvitations(ctx context.Context, tx *sql.Tx, group, id string) error {
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "id","teamId" FROM "invitation" WHERE "organizationId"=? AND "status"='pending' AND "teamId" IS NOT NULL`), group)
	if err != nil {
		return err
	}
	updates := map[string]*string{}
	for rows.Next() {
		var invite, ids string
		if err = rows.Scan(&invite, &ids); err != nil {
			rows.Close()
			return err
		}
		parts := strings.Split(ids, ",")
		if !slices.Contains(parts, id) {
			continue
		}
		remaining := strings.Join(slices.DeleteFunc(parts, func(v string) bool { return v == id }), ",")
		if remaining == "" {
			updates[invite] = nil
		} else {
			updates[invite] = &remaining
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for invite, remaining := range updates {
		if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "invitation" SET "teamId"=? WHERE "id"=?`), remaining, invite); err != nil {
			return err
		}
	}
	return nil
}
func listTeamsQuery(t teamTransaction, query string, args ...any) ([]org.Team, error) {
	rows, err := t.tx.QueryContext(t.ctx, t.bind(`SELECT `+teamFields+` FROM "team" t `+query+` ORDER BY t."createdAt",t."id"`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []org.Team{}
	for rows.Next() {
		v, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}
func (s *Store) ListTeams(ctx context.Context, a org.TeamActor, explicit string) (out []org.Team, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		id, err := t.authorizeOrg(explicit, org.ErrTeamList, nil)
		if err != nil {
			return err
		}
		out, err = listTeamsQuery(t, ` WHERE t."organizationId"=?`, id)
		return err
	})
	return
}
func (s *Store) ListUserTeams(ctx context.Context, a org.TeamActor, explicit, userID string) (out []org.Team, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		target := userID
		if target == "" {
			target = a.UserID
		}
		query := ` WHERE EXISTS(SELECT 1 FROM "member" m WHERE m."organizationId"=t."organizationId" AND m."userId"=?)
			AND EXISTS(SELECT 1 FROM "teamMember" tm WHERE tm."teamId"=t."id" AND tm."userId"=?)`
		args := []any{target, target}
		if target != a.UserID || explicit != "" {
			var denied *authn.APIError
			if target != a.UserID {
				denied = org.ErrTeamListUser
			}
			id, err := t.authorizeOrg(explicit, org.ErrTeamListOrg, denied)
			if err != nil {
				return err
			}
			role, err := t.memberRole(id, target)
			if err != nil {
				return err
			}
			if role == "" {
				return org.ErrTeamOrgMember
			}
			query += ` AND t."organizationId"=?`
			args = append(args, id)
		}
		var listErr error
		out, listErr = listTeamsQuery(t, query, args...)
		return listErr
	})
	return
}
func (s *Store) SetActiveTeam(ctx context.Context, a org.TeamActor, id *string) (out *org.Team, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		if id != nil {
			group, err := t.authorizeOrg("", org.ErrTeamSelect, nil)
			if err != nil {
				return err
			}
			out, err = s.findTeam(ctx, t.tx, group, *id)
			if err != nil {
				return err
			}
			_, err = s.readTeamMember(ctx, t.tx, *id, a.UserID)
			if errors.Is(err, sql.ErrNoRows) {
				return org.ErrTeamSelect
			}
			if err != nil {
				return err
			}
		}
		_, err := t.tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeTeamId"=? WHERE "id"=? AND "userId"=?`), id, a.SessionID, a.UserID)
		return err
	})
	return
}

const teamMemberFields = `tm."id",tm."teamId",tm."userId",tm."createdAt"`

func scanTeamMember(r rowScanner) (*org.TeamMember, error) {
	var v org.TeamMember
	err := r.Scan(&v.ID, &v.TeamID, &v.UserID, &v.CreatedAt)
	return &v, err
}
func (s *Store) readTeamMember(ctx context.Context, tx *sql.Tx, id, user string) (*org.TeamMember, error) {
	return scanTeamMember(tx.QueryRowContext(ctx, s.bind(`SELECT `+teamMemberFields+` FROM "teamMember" tm WHERE tm."teamId"=? AND tm."userId"=?`), id, user))
}
func (s *Store) ListTeamMembers(ctx context.Context, a org.TeamActor, teamID string) (out []org.TeamMember, err error) {
	err = s.withTeamActor(ctx, a, "", func(t teamTransaction) error {
		id := teamID
		if id == "" {
			id = t.activeTeam
		}
		if id == "" {
			return org.ErrNoActiveTeam
		}
		var group string
		err := t.tx.QueryRowContext(ctx, s.bind(`SELECT "organizationId" FROM "team" WHERE "id"=?`), id).Scan(&group)
		if errors.Is(err, sql.ErrNoRows) {
			return org.ErrTeamNotFound
		}
		if err != nil {
			return err
		}
		if _, err = t.authorizeOrg(group, org.ErrTeamMember, nil); err != nil {
			return err
		}
		if _, err = s.readTeamMember(ctx, t.tx, id, a.UserID); errors.Is(err, sql.ErrNoRows) {
			return org.ErrTeamMember
		} else if err != nil {
			return err
		}
		rows, err := t.tx.QueryContext(ctx, s.bind(`SELECT `+teamMemberFields+` FROM "teamMember" tm WHERE tm."teamId"=? AND EXISTS (SELECT 1 FROM "member" m WHERE m."organizationId"=? AND m."userId"=tm."userId") ORDER BY tm."createdAt",tm."id"`), id, group)
		if err != nil {
			return err
		}
		defer rows.Close()
		out = []org.TeamMember{}
		for rows.Next() {
			m, err := scanTeamMember(rows)
			if err != nil {
				return err
			}
			out = append(out, *m)
		}
		return rows.Err()
	})
	return
}

// Match the membership key for the JSON array [teamId,userId]. It stays internal.
func teamMembershipKey(id, user string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode([2]string{id, user})
	sum := sha256.Sum256(bytes.TrimSuffix(b.Bytes(), []byte{'\n'}))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func (s *Store) teamCapacity(ctx context.Context, tx *sql.Tx, id string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`), id).Scan(&n)
	if err == nil && s.teamOptions.MaximumMembersPerTeam != nil && n >= *s.teamOptions.MaximumMembersPerTeam {
		return n, org.ErrTeamMemberLimit
	}
	return n, err
}
func (s *Store) insertTeamMember(ctx context.Context, tx *sql.Tx, id, user string, limit bool) (*org.TeamMember, error) {
	last, err := s.readTeamMember(ctx, tx, id, user)
	if err == nil {
		return last, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if limit {
		if _, err = s.teamCapacity(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	m := org.TeamMember{ID: rand.Text(), TeamID: id, UserID: user, CreatedAt: &now}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "teamMember" ("id","teamId","userId","createdAt","membershipKey") VALUES(?,?,?,?,?)`), m.ID, id, user, s.date(now), teamMembershipKey(id, user))
	if err != nil {
		return nil, err
	}
	return &m, s.updateTeamCount(ctx, tx, id)
}
func (s *Store) updateTeamCount(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "team" SET "memberCount"=(SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?) WHERE "id"=?`), id, id)
	return err
}

func (t teamTransaction) authorizeMemberChange(explicit, id, user string, denied *authn.APIError) error {
	group, err := t.authorizeOrg(explicit, org.ErrTeamOrgMember, denied)
	if err != nil {
		return err
	}
	role, err := t.memberRole(group, user)
	if err != nil {
		return err
	}
	if role == "" {
		return org.ErrTeamOrgMember
	}
	_, err = t.findTeam(t.ctx, t.tx, group, id)
	return err
}
func (s *Store) AddTeamMember(ctx context.Context, a org.TeamActor, explicit, id, user string) (out *org.TeamMember, err error) {
	err = s.withTeamActor(ctx, a, user, func(t teamTransaction) error {
		if err := t.authorizeMemberChange(explicit, id, user, org.ErrTeamAdd); err != nil {
			return err
		}
		var err error
		out, err = s.insertTeamMember(ctx, t.tx, id, user, true)
		return err
	})
	return
}
func (s *Store) RemoveTeamMember(ctx context.Context, a org.TeamActor, explicit, id, user string) error {
	return s.withTeamActor(ctx, a, user, func(t teamTransaction) error {
		if err := t.authorizeMemberChange(explicit, id, user, org.ErrTeamRemove); err != nil {
			return err
		}
		res, err := t.tx.ExecContext(ctx, s.bind(`DELETE FROM "teamMember" WHERE "teamId"=? AND "userId"=?`), id, user)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return org.ErrTeamMember
		}
		if _, err = t.tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeTeamId"=NULL WHERE "activeTeamId"=? AND "userId"=?`), id, user); err != nil {
			return err
		}
		return s.updateTeamCount(ctx, t.tx, id)
	})
}

func (s *Store) selectOrganizationAndTeam(ctx context.Context, tx *sql.Tx, session, user string, group, team *string) error {
	if s.teamOptions != nil {
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeOrganizationId"=?,"activeTeamId"=? WHERE "id"=? AND "userId"=?`), group, team, session, user)
		return err
	}
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeOrganizationId"=? WHERE "id"=? AND "userId"=?`), group, session, user)
	return err
}
