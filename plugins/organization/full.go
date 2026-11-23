package organization

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// FullOrganization is the visible portion of one organization's directory.
// With teams enabled an empty Teams slice is encoded as an empty array.
type FullOrganization struct {
	Organization
	Members     []MemberWithUser `json:"members"`
	Invitations []Invitation     `json:"invitations"`
	Teams       []Team           `json:"teams,omitzero"`
}

type FullOrganizationQuery struct {
	OrganizationID, OrganizationSlug string
	MembersLimit                     int
}

// FullOrganizationStore reads the session, membership, and visible records
// from a consistent snapshot. An empty selection returns a nil organization.
type FullOrganizationStore interface {
	FullOrganization(ctx context.Context, sessionID, userID string, q FullOrganizationQuery, includeTeams bool) (*FullOrganization, error)
}

var memberLimitPrefix = regexp.MustCompile(`^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)`)

func (o Options) fullOrganizationEndpoint(store FullOrganizationStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/get-full-organization", Handler: func(c auth.EndpointContext) (any, error) {
		v := c.Request.URL.Query()
		for _, key := range []string{"organizationId", "organizationSlug", "membersLimit"} {
			if len(v[key]) > 1 {
				return nil, problem(400, "VALIDATION_ERROR", "[query."+key+"] Invalid input")
			}
		}
		q := FullOrganizationQuery{OrganizationID: v.Get("organizationId"), OrganizationSlug: v.Get("organizationSlug")}
		if prefix := memberLimitPrefix.FindString(strings.TrimSpace(v.Get("membersLimit"))); prefix != "" {
			base := 10
			if strings.HasPrefix(strings.ToLower(strings.TrimLeft(prefix, "+-")), "0x") {
				base = 0
			}
			n, err := strconv.ParseInt(prefix, base, strconv.IntSize)
			if err != nil || n < 0 {
				return nil, problem(400, "VALIDATION_ERROR", "[query.membersLimit] Expected a nonnegative integer")
			}
			q.MembersLimit = int(n)
		}
		session, err := endpointSession(c, http.MethodGet, "get-full-organization")
		if err != nil {
			return nil, err
		}
		return store.FullOrganization(c.Request.Context(), session.Session.ID, session.User.ID, q, o.Teams != nil)
	}}
}
