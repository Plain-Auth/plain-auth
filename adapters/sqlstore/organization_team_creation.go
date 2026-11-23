package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// CreateTeam uses the session and account recorded by the existing TeamStore API.
func (s *Store) CreateTeam(ctx context.Context, actor org.TeamActor, organizationID, name string) (*org.Team, error) {
	return s.CreateOrganizationTeam(ctx, &actor, org.CreateTeamRequest{OrganizationID: organizationID, Name: name}, nil)
}

// teamLimitInput runs inside an authorized transaction and reads the callback's core account and session fields.
func (t teamTransaction) teamLimitInput(id string) (org.TeamLimitInput, error) {
	input := org.TeamLimitInput{OrganizationID: id}
	if t.actor.SessionID == "" {
		return input, nil
	}
	session, err := t.sessionResult(t.ctx, t.tx, t.actor.SessionID, t.actor.UserID)
	input.Session = session
	return input, err
}

var errResolveTeamLimit = errors.New("resolve team limit outside transaction")

// CreateOrganizationTeam authorizes the actor, counts all teams under the
// organization lock, and commits one team. A trusted call has no HTTP identity.
func (s *Store) CreateOrganizationTeam(ctx context.Context, actor *org.TeamActor, input org.CreateTeamRequest, request *http.Request) (*org.Team, error) {
	if s.teamOptions == nil {
		return nil, errors.New("sqlstore: organization teams are disabled")
	}
	if actor == nil && (request != nil || input.OrganizationID == "") {
		if request != nil {
			return nil, org.ErrUnauthenticated
		}
		return nil, org.ErrNoActiveOrg
	}
	var snapshot org.TeamLimitInput
	var expected []byte
	maximum := s.teamOptions.MaximumTeams
	resolve := s.teamOptions.ResolveMaximumTeams
	var saved *org.Team
	for {
		err := s.withTeamTransaction(ctx, actor, "", func(t teamTransaction) error {
			id := input.OrganizationID
			var err error
			if actor == nil {
				err = t.lockOrganization(ctx, t.tx, id)
			} else {
				id, err = t.authorizeOrg(id, "team", "create", org.ErrInviteDenied, org.ErrTeamCreate)
			}
			if err != nil {
				return err
			}
			if resolve != nil {
				current, err := t.teamLimitInput(id)
				if err != nil {
					return err
				}
				encoded, err := json.Marshal(current)
				if err != nil {
					return err
				}
				if expected == nil {
					snapshot, expected = current, encoded
					return errResolveTeamLimit
				}
				if !bytes.Equal(expected, encoded) {
					return org.ErrTeamLimitChanged
				}
			}
			if maximum > 0 {
				var count int
				q := `SELECT COUNT(*) FROM "team" WHERE "organizationId"=` + s.exactSQLValue("?")
				if err := t.tx.QueryRowContext(ctx, s.bind(q), id).Scan(&count); err != nil {
					return err
				}
				if count >= maximum {
					return org.ErrTeamLimit
				}
			}
			saved, err = s.insertTeam(ctx, t.tx, id, input.Name, true)
			return err
		})
		if err == nil {
			return saved, nil
		}
		if !errors.Is(err, errResolveTeamLimit) {
			return nil, err
		}
		snapshot.Request = request
		maximum, err = resolve(ctx, snapshot)
		if err != nil {
			return nil, err
		}
		if maximum < 0 {
			return nil, errors.New("organization: resolved team limit must be nonnegative")
		}
	}
}
