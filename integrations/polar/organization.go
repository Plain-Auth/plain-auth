package polar

import (
	"context"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	auth "github.com/Plain-Org/plain-auth"
	polargo "github.com/polarsource/polar-go"
)

// OrganizationOptions accepts an organization's referenceId on checkout and
// on the subscription list, as another runtime's reference system does. The
// caller must be a member, and AuthorizeReference must approve the request.
type OrganizationOptions struct {
	// AuthorizeReference is required. It runs outside any database
	// transaction, before the provider call and again before the result is
	// returned. Keep it local and side-effect free.
	AuthorizeReference func(ReferenceAuthorization) bool
	// ServerURL is the Polar API server the Client uses, for the
	// organization subscription list: empty for production, or
	// polargo.ServerList[polargo.ServerSandbox] for the sandbox. The list
	// sends its metadata filter itself, since the Go SDK cannot encode it.
	ServerURL string
}

// serverURL is the configured API server, production by default.
func (o *OrganizationOptions) serverURL() string {
	if o.ServerURL == "" {
		return polargo.ServerList[polargo.ServerProduction]
	}
	return o.ServerURL
}

// validServerURL accepts an HTTPS origin without a path, query or
// credentials.
func validServerURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// ReferenceAuthorization describes one organization-scoped request. Role is
// the member's role, which may list several roles separated by commas.
// Action is "checkout" or "list-subscription".
type ReferenceAuthorization struct {
	UserID, OrganizationID, SessionID, Role, Action string
}

// referenceMetadata is the checkout metadata key holding the organization
// reference, as another runtime names it.
const referenceMetadata = "referenceId"

const maxReferenceBytes = 255

// validReference accepts 1 to 255 bytes of UTF-8 without control characters.
func validReference(ref string) bool {
	return ref != "" && len(ref) <= maxReferenceBytes && utf8.ValidString(ref) && !strings.ContainsFunc(ref, unicode.IsControl)
}

func referenceForbidden() error {
	return failure(403, "POLAR_REFERENCE_FORBIDDEN", "You cannot bill for this organization")
}

// memberRole reads the user's role in the organization from the member
// table, without a transaction. Rows that are not byte-for-byte equal to
// the request are discarded, since MySQL compares case-insensitively.
func (l *Ledger) memberRole(ctx context.Context, organizationID, userID string) (string, bool, error) {
	q := `SELECT m."organizationId",m."userId",m."role" FROM "member" m WHERE m."organizationId"=? AND m."userId"=?`
	if l.dialect == "mysql" {
		q = strings.ReplaceAll(q, `"`, "`")
	}
	rows, err := l.db.QueryContext(ctx, l.bind(q), organizationID, userID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var role string
	matches := 0
	for rows.Next() {
		var org, user, r string
		if err := rows.Scan(&org, &user, &r); err != nil {
			return "", false, err
		}
		if org == organizationID && user == userID {
			role = r
			matches++
		}
	}
	return role, matches == 1, rows.Err()
}

// checkMemberTable confirms the member table the reference check reads.
func (l *Ledger) checkMemberTable(ctx context.Context) error {
	q := `SELECT m."organizationId",m."userId",m."role" FROM "member" m WHERE 1=0`
	if l.dialect == "mysql" {
		q = strings.ReplaceAll(q, `"`, "`")
	}
	rows, err := l.db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	return rows.Close()
}

// authorizeReference requires exactly one membership for the caller in the
// organization and the host's approval.
func (s *Service) authorizeReference(c auth.EndpointContext, session *auth.SessionResult, ref, action string) error {
	role, member, err := s.opts.Ledger.memberRole(c.Request.Context(), ref, session.User.ID)
	if err != nil {
		return err
	}
	if !member || !s.opts.Organization.AuthorizeReference(ReferenceAuthorization{UserID: session.User.ID, OrganizationID: ref, SessionID: session.Session.ID, Role: role, Action: action}) {
		return referenceForbidden()
	}
	return nil
}
