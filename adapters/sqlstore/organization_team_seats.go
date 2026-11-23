package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var errResolveTeamSeat = errors.New("resolve team member limit outside transaction")

// teamSeats carries resolved per-team caps across transaction attempts. A pass
// that reaches a team without a decision records the callback input and rolls
// back. The host decides outside the transaction, and the next pass rechecks
// the same input while it holds the organization lock.
type teamSeats struct {
	// The signed-in caller. Both are empty for a trusted server call.
	sessionID, userID string
	limits            map[string]teamSeatLimit
	pending           *org.TeamMemberLimitInput
	pendingSnapshot   []byte
}

type teamSeatLimit struct {
	snapshot []byte
	maximum  int
}

// checkTeamSeat rejects a new member when the team is full. The caller holds
// the organization lock, so concurrent joins count each other.
func (s *Store) checkTeamSeat(ctx context.Context, tx *sql.Tx, organizationID, teamID string, seats *teamSeats) error {
	var count int
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "teamMember" WHERE "teamId"=?`), teamID).Scan(&count); err != nil {
		return err
	}
	resolve := s.teamOptions.ResolveMaximumMembersPerTeam
	if resolve == nil {
		if limit := s.teamOptions.MaximumMembersPerTeam; limit != nil && count >= *limit {
			return org.ErrTeamMemberLimit
		}
		return nil
	}
	if seats == nil || seats.sessionID == "" {
		return org.ErrUnauthenticated
	}
	session, err := s.sessionResult(ctx, tx, seats.sessionID, seats.userID)
	if errors.Is(err, sql.ErrNoRows) {
		return org.ErrUnauthenticated
	}
	if err != nil {
		return err
	}
	input := org.TeamMemberLimitInput{TeamID: teamID, OrganizationID: organizationID, Session: session}
	snapshot, err := json.Marshal(input)
	if err != nil {
		return err
	}
	limit, decided := seats.limits[teamID]
	if !decided {
		seats.pending, seats.pendingSnapshot = &input, snapshot
		return errResolveTeamSeat
	}
	if !bytes.Equal(limit.snapshot, snapshot) {
		return org.ErrTeamLimitChanged
	}
	if count >= limit.maximum {
		return org.ErrTeamMemberLimit
	}
	return nil
}

// resolveTeamSeat asks the host for the cap recorded by the last pass.
func (s *Store) resolveTeamSeat(ctx context.Context, seats *teamSeats) error {
	maximum, err := s.teamOptions.ResolveMaximumMembersPerTeam(ctx, *seats.pending)
	if err != nil {
		return err
	}
	if maximum < 0 {
		return errors.New("organization: resolved team member limit must be nonnegative")
	}
	if seats.limits == nil {
		seats.limits = map[string]teamSeatLimit{}
	}
	seats.limits[seats.pending.TeamID] = teamSeatLimit{snapshot: seats.pendingSnapshot, maximum: maximum}
	seats.pending, seats.pendingSnapshot = nil, nil
	return nil
}

// withTeamSeats reruns attempt until every team it joins has a decided cap.
// Each rerun decides one more team, so a multi-team invitation takes one pass
// per team plus the committing pass.
func (s *Store) withTeamSeats(ctx context.Context, seats *teamSeats, attempt func() error) error {
	for {
		err := attempt()
		if err != errResolveTeamSeat {
			return err
		}
		if err := s.resolveTeamSeat(ctx, seats); err != nil {
			return err
		}
	}
}

// sessionResult reads the caller's live session and account inside tx.
func (s *Store) sessionResult(ctx context.Context, tx *sql.Tx, sessionID, userID string) (*auth.SessionResult, error) {
	var ss auth.StoredSession
	var user auth.User
	arg := s.exactSQLValue("?")
	q := `SELECT ` + sessionColumns + `,` + userColumns + `,s."activeOrganizationId",s."activeTeamId" FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."id"=` + arg + ` AND u."id"=` + arg
	dest := append(sessionFields(&ss), userFields(&user)...)
	dest = append(dest, &ss.ActiveOrganizationID, &ss.ActiveTeamID)
	if err := tx.QueryRowContext(ctx, s.bind(q), sessionID, userID).Scan(dest...); err != nil {
		return nil, err
	}
	return &auth.SessionResult{Session: ss.Session, User: user}, nil
}
