package sqlstore

import (
	"context"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var memberListColumns = map[string]string{
	"id": `m."id"`, "userId": `m."userId"`, "organizationId": `m."organizationId"`,
	"role": `m."role"`, "createdAt": `m."createdAt"`,
}

func memberQueryError(field string) error {
	return &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Invalid " + field + " in organization member query"}
}

func (s *Store) memberFilter(q org.MemberListQuery) (string, []any, error) {
	if q.FilterField == "" {
		return "", nil, nil
	}
	col, ok := memberListColumns[q.FilterField]
	if !ok {
		return "", nil, memberQueryError("filterField")
	}
	if len(q.FilterValues) == 0 {
		return "", nil, memberQueryError("filterValue")
	}
	if q.FilterOperator != "in" && q.FilterOperator != "not_in" && len(q.FilterValues) != 1 {
		return "", nil, memberQueryError("filterValue")
	}
	switch q.FilterOperator {
	case "starts_with", "ends_with", "contains":
		if q.FilterField == "createdAt" {
			// Pattern matching uses the millisecond UTC representation returned over HTTP.
			switch s.dialect {
			case "postgres":
				col = `to_char(m."createdAt" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`
			case "mysql":
				col = `concat(left(date_format(m."createdAt", '%Y-%m-%dT%H:%i:%s.%f'), 23), 'Z')`
			}
		}
		pattern := q.FilterValues[0]
		if q.FilterOperator != "starts_with" {
			pattern = "%" + pattern
		}
		if q.FilterOperator != "ends_with" {
			pattern += "%"
		}
		return " AND " + col + " LIKE ?", []any{pattern}, nil
	}
	args := make([]any, len(q.FilterValues))
	for i, raw := range q.FilterValues {
		args[i] = raw
		if q.FilterField == "createdAt" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				t, err = time.Parse(time.DateOnly, raw)
			}
			if err != nil {
				return "", nil, memberQueryError("filterValue")
			}
			args[i] = s.date(t)
		}
	}
	if q.FilterField != "createdAt" {
		col = s.exactSQLValue(col)
	}
	if q.FilterOperator == "in" || q.FilterOperator == "not_in" {
		op := " IN "
		if q.FilterOperator == "not_in" {
			op = " NOT IN "
		}
		return " AND " + col + op + "(?" + strings.Repeat(",?", len(args)-1) + ")", args, nil
	}
	op, ok := map[string]string{"": "=", "eq": "=", "ne": "<>", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[q.FilterOperator]
	if !ok {
		return "", nil, memberQueryError("filterOperator")
	}
	return " AND " + col + op + "?", args, nil
}

// ListOrganizationMembers reads the live session, caller's membership, filtered
// count and public member profiles from the same database snapshot.
func (s *Store) ListOrganizationMembers(ctx context.Context, sessionID, actorID string, q org.MemberListQuery) (org.MemberPage, error) {
	var page org.MemberPage
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	group, _, err := s.organizationRole(ctx, tx, sessionID, actorID, org.MemberRoleQuery{OrganizationID: q.OrganizationID, OrganizationSlug: q.OrganizationSlug})
	if err != nil {
		return page, err
	}
	filter, args, err := s.memberFilter(q)
	if err != nil {
		return page, err
	}
	if q.SortDirection != "" && q.SortDirection != "asc" && q.SortDirection != "desc" {
		return page, memberQueryError("sortDirection")
	}
	order := `m."id"`
	if q.SortBy != "" {
		col, ok := memberListColumns[q.SortBy]
		if !ok {
			return page, memberQueryError("sortBy")
		}
		order = col + " " + q.SortDirection
		if q.SortBy != "id" {
			order += `, m."id"`
		}
	}
	if q.Limit < 0 || q.Offset < 0 {
		return page, memberQueryError("pagination")
	}
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	where := ` WHERE m."organizationId"=` + s.exactSQLValue("?") + filter
	args = append([]any{group}, args...)
	if err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "member" m`+where), args...).Scan(&page.Total); err != nil {
		return org.MemberPage{}, err
	}
	page.Members = []org.MemberWithUser{}
	if page.Total > q.Offset {
		query := `SELECT m."id", m."organizationId", m."userId", m."role", m."createdAt", u."id", u."name", u."email", u."image"
			FROM "member" m LEFT JOIN "user" u ON u."id"=` + s.exactSQLValue(`m."userId"`) + where +
			" ORDER BY " + order + " LIMIT ? OFFSET ?"
		rows, err := tx.QueryContext(ctx, s.bind(query), append(args, limit, q.Offset)...)
		if err != nil {
			return org.MemberPage{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var member org.MemberWithUser
			err := rows.Scan(&member.ID, &member.OrganizationID, &member.UserID, &member.Role, &member.CreatedAt, &member.User.ID, &member.User.Name, &member.User.Email, &member.User.Image)
			if err != nil {
				return org.MemberPage{}, err
			}
			page.Members = append(page.Members, member)
		}
		if err := rows.Err(); err != nil {
			return org.MemberPage{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return org.MemberPage{}, err
	}
	return page, nil
}
