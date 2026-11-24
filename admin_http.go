package plainauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func parseAdminRoles(v any) ([]string, error) {
	switch x := v.(type) {
	case string:
		return []string{x}, nil
	case []string:
		return x, nil
	case []any:
		roles := make([]string, 0, len(x))
		for _, r := range x {
			role, ok := r.(string)
			if !ok {
				return nil, adminError(400, "INVALID_ROLE_TYPE", "Invalid role type")
			}
			roles = append(roles, role)
		}
		return roles, nil
	default:
		return nil, adminError(400, "INVALID_ROLE_TYPE", "Invalid role type")
	}
}

func (a *Auth) adminUpdateFields(ctx context.Context, actor *User, u *User, req AdminRequest, creating bool) error {
	if req.Operation == "update-user" && len(req.Data) == 0 {
		return adminError(400, "NO_DATA_TO_UPDATE", "No data to update")
	}
	if err := a.adminPhoneFields(ctx, actor, u, req.Data, creating); err != nil {
		return err
	}
	if a.username != nil {
		patch, err := usernamePatch(req.Data)
		name, display := patch.Username, patch.DisplayUsername
		if err != nil {
			return err
		}
		if patch.hasUsernameChange() || creating {
			f, err := a.username.fields(ctx, name, display, creating && name != nil)
			if err != nil {
				return err
			}
			if u.UsernameFields == nil {
				u.UsernameFields = f
			} else {
				if patch.ClearUsername || f.Username != nil {
					u.Username = f.Username
				}
				if f.DisplayUsernameFields != nil && (patch.ClearDisplayUsername || f.DisplayUsername != nil) {
					u.DisplayUsernameFields = f.DisplayUsernameFields
				}
			}
		}
	}
	role := req.Role
	if v, ok := req.Data["role"]; ok && role == nil {
		var err error
		role, err = parseAdminRoles(v)
		if err != nil {
			return err
		}
	}
	if req.Operation == "set-role" && len(role) == 0 {
		return validationError("Role is required")
	}
	if role != nil {
		if err := a.requireAdminFieldGrant(actor, "set-role"); err != nil {
			return err
		}
		if len(role) == 0 {
			return validationError("Role is required")
		}
		for _, r := range role {
			if _, ok := a.admin.Roles[r]; !ok {
				return adminError(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE", "You are not allowed to set a non-existent role value")
			}
		}
		u.Role = strings.Join(role, ",")
	}
	for key, v := range req.Data {
		switch key {
		case "username", "displayUsername":
			if a.username == nil {
				return validationError("Unknown user field")
			}
		case "role", "phoneNumber", "phoneNumberVerified":
			continue
		case "id":
			return adminError(400, "USER_ID_CANNOT_BE_UPDATED", "User id cannot be updated")
		case "password":
			return adminError(400, "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER", "Password cannot be updated through update-user. Use the set-user-password endpoint instead")
		case "name":
			if creating {
				continue
			}
			value, ok := v.(string)
			if !ok || value == "" {
				return validationError("Invalid name")
			}
			u.Name = value
		case "image":
			if v == nil {
				u.Image = nil
				continue
			}
			value, ok := v.(string)
			if !ok {
				return validationError("Invalid image")
			}
			u.Image = &value
		case "email", "emailVerified":
			if key == "email" && creating {
				continue
			}
			if err := a.requireAdminFieldGrant(actor, "set-email"); err != nil {
				return err
			}
			if key == "emailVerified" {
				value, ok := v.(bool)
				if !ok {
					return validationError("Invalid emailVerified")
				}
				u.EmailVerified = value
				continue
			}
			value, ok := v.(string)
			if !ok || !emailPattern.MatchString(value) || len(value) > 254 || strings.Contains(value, "..") {
				return adminError(400, "INVALID_EMAIL", "Invalid email")
			}
			u.Email = strings.ToLower(value)
		case "banned", "banReason", "banExpires":
			if err := a.requireAdminFieldGrant(actor, "ban-user"); err != nil {
				return err
			}
			switch key {
			case "banned":
				value, ok := v.(bool)
				if !ok {
					return validationError("Invalid banned flag")
				}
				if value && actor != nil && actor.ID == u.ID {
					return adminError(400, "YOU_CANNOT_BAN_YOURSELF", "You cannot ban yourself")
				}
				u.Banned = value
			case "banReason":
				if v == nil {
					u.BanReason = nil
					continue
				}
				value, ok := v.(string)
				if !ok {
					return validationError("Invalid ban reason")
				}
				u.BanReason = &value
			case "banExpires":
				if v == nil {
					u.BanExpires = nil
					continue
				}
				value, ok := v.(string)
				until, err := time.Parse(time.RFC3339Nano, value)
				if !ok || err != nil {
					return validationError("Invalid ban expiration")
				}
				u.BanExpires = &until
			}
		default:
			if _, declared := a.opts.UserAdditionalFields[key]; !creating || !declared {
				return validationError("Unknown user field")
			}
		}
	}
	return nil
}
func (a *Auth) adminReturnCredential(h http.Header, temporary string) (string, string) {
	r := http.Request{Header: h}
	c, err := r.Cookie(a.prefixedCookieName("admin_session"))
	if err != nil {
		return "", ""
	}
	v := strings.Split(a.VerifySignedSessionToken(c.Value), "|")
	if len(v) != 4 || v[0] != "admin-return" || v[1] != temporary || (v[2] != "persistent" && v[2] != "browser") {
		return "", ""
	}
	return v[3], v[2]
}

func (a *Auth) adminHTTP(c EndpointContext, name string) (any, error) {
	r, b := c.Request, c.Body
	req := AdminRequest{Operation: name}
	var err error
	if v, ok := b["userId"]; ok {
		req.UserID, ok = v.(string)
		if !ok {
			return nil, validationError("Invalid user ID")
		}
	}
	params := r.URL.Query()
	switch name {
	case "get-user":
		req.UserID = params.Get("id")
	case "list-users":
		q := AdminQuery{SearchField: params.Get("searchField"), SearchValue: params.Get("searchValue"), SearchOperator: params.Get("searchOperator"), FilterField: params.Get("filterField"), FilterOperator: params.Get("filterOperator"), FilterValues: params["filterValue"], SortBy: params.Get("sortBy"), SortDirection: params.Get("sortDirection")}
		if params.Has("limit") {
			q.Limit, err = strconv.Atoi(params.Get("limit"))
			if err != nil || q.Limit < 0 {
				return nil, validationError("Invalid limit")
			}
		}
		if params.Has("offset") {
			q.Offset, err = strconv.Atoi(params.Get("offset"))
			if err != nil || q.Offset < 0 {
				return nil, validationError("Invalid offset")
			}
		}
		req.Query = q
	case "set-role", "create-user", "update-user":
		if v, ok := b["role"]; ok {
			req.Role, err = parseAdminRoles(v)
			if err != nil {
				return nil, err
			}
		}
		if v, ok := b["data"]; ok {
			var valid bool
			req.Data, valid = v.(map[string]any)
			if !valid {
				return nil, validationError("Invalid user data")
			}
		}
		if name == "create-user" {
			req.Email, err = requiredString(b, "email")
			if err != nil {
				return nil, err
			}
			req.Name, err = requiredString(b, "name")
			if err != nil {
				return nil, err
			}
			if _, ok := b["password"]; ok {
				req.Password, err = requiredString(b, "password")
				if err != nil {
					return nil, err
				}
			}
		}
	case "set-user-password":
		req.Password, err = requiredString(b, "newPassword")
		if err != nil {
			return nil, err
		}
	case "revoke-user-session":
		req.SessionToken, err = requiredString(b, "sessionToken")
		if err != nil {
			return nil, err
		}
	case "ban-user":
		if _, ok := b["banReason"]; ok {
			req.BanReason, err = requiredString(b, "banReason")
			if err != nil {
				return nil, err
			}
		}
		if v, ok := b["banExpiresIn"]; ok {
			num, ok := v.(json.Number)
			n, numberErr := strconv.ParseFloat(string(num), 64)
			if !ok || numberErr != nil || n < 0 || n > float64((1<<63-1)/time.Second) {
				return nil, validationError("Invalid ban duration")
			}
			req.BanDuration = time.Duration(n * float64(time.Second))
		}
	case "has-permission":
		raw, ok := b["permissions"].(map[string]any)
		if !ok {
			return nil, validationError("Permissions are required")
		}
		req.Permissions = make(AdminPermissions, len(raw))
		for k, v := range raw {
			actions, ok := v.([]any)
			if !ok {
				return nil, validationError("Invalid permissions")
			}
			req.Permissions[k] = make([]string, 0, len(actions))
			for _, value := range actions {
				action, ok := value.(string)
				if !ok {
					return nil, validationError("Invalid action")
				}
				req.Permissions[k] = append(req.Permissions[k], action)
			}
		}
	}
	out, err := a.executeAdmin(r.Context(), r.Header, req, RequestMeta{IPAddress: a.clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		return nil, err
	}
	switch name {
	case "get-user", "update-user":
		return out.User, nil
	case "list-users":
		return out.Page, nil
	case "list-user-sessions":
		return map[string]any{"sessions": out.Sessions}, nil
	case "has-permission":
		return map[string]any{"success": out.Allowed, "error": nil}, nil
	case "set-user-password":
		return map[string]bool{"status": true}, nil
	case "impersonate-user":
		mode := "persistent"
		if a.dontRemember(r) {
			mode = "browser"
		}
		marker := a.adminSessionCookie("admin-return|"+out.Session.Session.Token+"|"+mode+"|"+out.original, 0)
		c.ResponseHeader.Add("Set-Cookie", marker.String())
		if err := a.writeSessionCookieHeaders(c.ResponseHeader, r, out.Session.Session.Token, false); err != nil {
			return nil, err
		}
		a.writeRememberPreference(c.ResponseHeader, r, false)
		return out.Session, nil
	case "stop-impersonating":
		c.ResponseHeader.Add("Set-Cookie", a.adminSessionCookie("", -1).String())
		persistent := out.persistence == "persistent"
		if err := a.writeSessionCookieHeaders(c.ResponseHeader, r, out.Session.Session.Token, persistent); err != nil {
			return nil, err
		}
		a.writeRememberPreference(c.ResponseHeader, r, persistent)
		return out.Session, nil
	}
	if out.User != nil {
		return map[string]any{"user": out.User}, nil
	}
	return map[string]bool{"success": true}, nil
}
