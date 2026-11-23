package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// OrganizationSelection selects a tenant by ID or slug. A nonempty ID takes
// precedence. An empty selection uses this session's current organization.
type OrganizationSelection struct {
	OrganizationID   string `json:"organizationId,omitempty"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

// OrganizationSelectionStore authorizes and applies a selector in one transaction.
// Nil clears the calling session. A denied destination clears its selection.
type OrganizationSelectionStore interface {
	SelectOrganization(ctx context.Context, sessionID, userID string, selection *OrganizationSelection) (*Organization, error)
}

func (o Options) selectActive(c auth.EndpointContext) (any, error) {
	rawID, hasID := c.Body["organizationId"]
	id, idIsString := rawID.(string)
	rawSlug, hasSlug := c.Body["organizationSlug"]
	slug, slugIsString := rawSlug.(string)
	var issues []string
	if rawID != nil && !idIsString {
		issues = append(issues, bodyTypeIssue("organizationId", "string", rawID, true))
	}
	if hasSlug && !slugIsString {
		issues = append(issues, bodyTypeIssue("organizationSlug", "string", rawSlug, true))
	}
	if len(issues) != 0 {
		return nil, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}

	signed, err := endpointSession(c, http.MethodPost, "set-active")
	if err != nil {
		return nil, err
	}
	var selection *OrganizationSelection
	if !hasID || rawID != nil {
		selection = &OrganizationSelection{OrganizationID: id, OrganizationSlug: slug}
	}
	ctx := c.Request.Context()
	var selected *Organization
	if store, ok := o.Store.(OrganizationSelectionStore); ok {
		selected, err = store.SelectOrganization(ctx, signed.Session.ID, signed.User.ID, selection)
	} else {
		selected, err = o.selectWithStore(ctx, signed, selection)
	}
	if err != nil {
		return nil, err
	}
	if (selected != nil || signed.Session.ActiveOrganizationID != nil) && c.DirectBrowserSession(signed.Session.Token) {
		err = c.TryReissueSessionCookie(signed.Session)
	}
	return selected, err
}

// Preserve custom stores that implement the original read and write operations.
func (o Options) selectWithStore(ctx context.Context, signed *auth.SessionResult, selection *OrganizationSelection) (*Organization, error) {
	set := func(id *string) error {
		return o.Store.SetActiveOrganization(ctx, signed.Session.ID, signed.User.ID, id)
	}
	if selection == nil {
		return nil, set(nil)
	}
	id, slug := selection.OrganizationID, selection.OrganizationSlug
	if id != "" {
		slug = ""
	} else if slug == "" {
		id = activeID(signed)
		if id == "" {
			return nil, nil
		}
	}
	group, err := o.Store.OrganizationForMember(ctx, signed.User.ID, id, slug)
	if err == nil {
		id = group.ID
		err = set(&id)
	}
	if errors.Is(err, ErrNotMember) || (id != "" && errors.Is(err, ErrNotFound)) {
		if err := set(nil); err != nil {
			return nil, err
		}
		return nil, ErrNotMember
	}
	if err != nil {
		return nil, err
	}
	return group, nil
}
