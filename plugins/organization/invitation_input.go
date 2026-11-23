package organization

import (
	"regexp"
	"strings"

	"github.com/Plain-Auth/plain-auth/internal/jsjson"
)

var invitationEmailPattern = regexp.MustCompile(`(?i)^([a-z0-9_'+-]+\.)*[a-z0-9_'+-]*[a-z0-9_+-]@([a-z0-9][a-z0-9-]*\.)+[a-z]{2,}$`)

type invitationInput struct {
	email          string
	roles          []string
	organizationID string
	resend         bool
	teamIDs        []string
}

func invitationStrings(value any) ([]string, bool) {
	switch v := value.(type) {
	case string:
		return []string{v}, true
	case []string:
		return v, true
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, s)
		}
		return result, true
	default:
		return nil, false
	}
}

func readInvitationInput(body map[string]any) (invitationInput, error) {
	var input invitationInput
	var issues []string
	typeIssue := func(field, want string) string {
		kind := "undefined"
		if v, ok := body[field]; ok {
			kind = jsjson.TypeName(v)
		}
		return "[body." + field + "] Invalid input: expected " + want + ", received " + kind
	}
	var ok bool
	if input.email, ok = body["email"].(string); !ok {
		issues = append(issues, typeIssue("email", "string"))
	}
	if input.roles, ok = invitationStrings(body["role"]); !ok {
		issues = append(issues, "[body.role] Invalid input")
	}
	if v, exists := body["organizationId"]; exists {
		if input.organizationID, ok = v.(string); !ok {
			issues = append(issues, typeIssue("organizationId", "string"))
		}
	}
	if v, exists := body["resend"]; exists {
		if input.resend, ok = v.(bool); !ok {
			issues = append(issues, typeIssue("resend", "boolean"))
		}
	}
	if v, exists := body["teamId"]; exists {
		if input.teamIDs, ok = invitationStrings(v); !ok {
			issues = append(issues, "[body.teamId] Invalid input")
		}
	}
	if len(issues) > 0 {
		return invitationInput{}, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	return input, nil
}

func builtinRole(role string) bool {
	return role == "admin" || role == "owner" || role == "member"
}

// ParseInvitationRoles validates the built-in invitation roles and preserves their order.
func ParseInvitationRoles(input ...string) (string, error) {
	roles := NormalizeRoles(input...)
	if len(roles) == 0 {
		return "", problem(400, "ROLE_NOT_FOUND", "Role not found")
	}
	var unknown []string
	for _, role := range roles {
		if !builtinRole(role) {
			unknown = append(unknown, role)
		}
	}
	if len(unknown) > 0 {
		return "", problem(400, "", "ROLE_NOT_FOUND: "+strings.Join(unknown, ", "))
	}
	return strings.Join(roles, ","), nil
}
