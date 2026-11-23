package organization

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// MemberListQuery pages through memberships in a shared organization. A slug
// takes precedence over an ID. Leave both empty to use the session selection.
type MemberListQuery struct {
	OrganizationID, OrganizationSlug string
	Limit, Offset                    int
	SortBy, SortDirection            string
	FilterField, FilterOperator      string
	FilterValues                     []string
}

// MemberPage contains the selected rows and the total after filtering, before pagination.
type MemberPage struct {
	Members []MemberWithUser `json:"members"`
	Total   int              `json:"total"`
}

// MemberDirectoryStore checks the live session and its membership before
// returning either rows or counts. All reads must see one consistent snapshot.
type MemberDirectoryStore interface {
	ListOrganizationMembers(ctx context.Context, sessionID, actorID string, q MemberListQuery) (MemberPage, error)
}

var memberOperators = []string{"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains", "starts_with", "ends_with"}

func listPosition(value string) (int, bool) {
	value = strings.TrimSpace(value)
	var number float64
	var err error
	if strings.HasPrefix(strings.ToLower(value), "0x") || strings.HasPrefix(strings.ToLower(value), "0o") || strings.HasPrefix(strings.ToLower(value), "0b") {
		var n uint64
		n, err = strconv.ParseUint(value, 0, 64)
		number = float64(n)
	} else {
		number, err = strconv.ParseFloat(value, 64)
	}
	if err != nil && !math.IsInf(number, 0) || math.IsNaN(number) {
		// A value that converts to NaN uses the default page position.
		return 0, true
	}
	if number < 0 || number >= math.Exp2(strconv.IntSize-1) || math.Trunc(number) != number {
		return 0, false
	}
	return int(number), true
}

func parseMemberListQuery(v url.Values) (MemberListQuery, error) {
	q := MemberListQuery{
		OrganizationID: v.Get("organizationId"), OrganizationSlug: v.Get("organizationSlug"),
		SortBy: v.Get("sortBy"), SortDirection: v.Get("sortDirection"),
		FilterField: v.Get("filterField"), FilterOperator: v.Get("filterOperator"), FilterValues: v["filterValue"],
	}
	var issues []string
	for _, field := range []string{"limit", "offset", "sortBy", "sortDirection", "filterField", "filterOperator", "organizationId", "organizationSlug"} {
		values := v[field]
		if len(values) == 0 {
			continue
		}
		switch field {
		case "limit", "offset":
			if len(values) != 1 {
				issues = append(issues, "[query."+field+"] Invalid input")
				continue
			}
			n, ok := listPosition(values[0])
			if !ok {
				issues = append(issues, "[query."+field+"] Expected a nonnegative integer")
			}
			if field == "limit" {
				q.Limit = n
			} else {
				q.Offset = n
			}
		case "sortDirection", "filterOperator":
			choices := memberOperators
			if field == "sortDirection" {
				choices = []string{"asc", "desc"}
			}
			if len(values) != 1 || !slices.Contains(choices, values[0]) {
				issues = append(issues, "[query."+field+"] Invalid option: expected one of \""+strings.Join(choices, "\"|\"")+"\"")
			}
		default:
			if len(values) != 1 {
				issues = append(issues, "[query."+field+"] Invalid input: expected string, received array")
			}
		}
	}
	if len(issues) > 0 {
		return q, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: strings.Join(issues, "; ")}
	}
	return q, nil
}

func (o Options) memberDirectoryEndpoint(store MemberDirectoryStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodGet, Path: "/organization/list-members", Handler: func(c auth.EndpointContext) (any, error) {
		q, err := parseMemberListQuery(c.Request.URL.Query())
		if err != nil {
			return nil, err
		}
		session, err := endpointSession(c, http.MethodGet, "list-members")
		if err != nil {
			return nil, err
		}
		return store.ListOrganizationMembers(c.Request.Context(), session.Session.ID, session.User.ID, q)
	}}
}
