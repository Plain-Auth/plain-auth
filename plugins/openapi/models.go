package openapi

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/apikey"
	"github.com/Stonewrit/stonewrit-auth/plugins/organization"
	"github.com/Stonewrit/stonewrit-auth/plugins/passkey"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
)

type object = map[string]any

func modelRef(name string) object { return object{"$ref": "#/components/schemas/" + name} }
func array(item object) object    { return object{"type": "array", "items": item} }
func responseObject(fields object, required ...string) object {
	s := object{"type": "object", "properties": fields}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// modelSchema follows encoding/json field tags on the public response types.
// Database-only types and provider credential records never enter the model set.
func modelSchema(t reflect.Type) object {
	if t == reflect.TypeFor[time.Time]() {
		return object{"type": "string", "format": "date-time"}
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		return object{}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return object{"anyOf": []object{modelSchema(t.Elem()), {"type": "null"}}}
	case reflect.Struct:
		properties := object{}
		var required []string
		for _, f := range reflect.VisibleFields(t) {
			if !f.IsExported() || f.Anonymous {
				continue
			}
			tag, flags, _ := strings.Cut(f.Tag.Get("json"), ",")
			if tag == "-" || tag == "" {
				continue
			}
			s := modelSchema(f.Type)
			if tag == "email" {
				s["format"] = "email"
			}
			properties[tag] = s
			// A pointer-embedded extension can be absent as a whole.
			if !strings.Contains(flags, "omitempty") && len(f.Index) == 1 {
				required = append(required, tag)
			}
		}
		return responseObject(properties, required...)
	case reflect.String:
		return object{"type": "string"}
	case reflect.Bool:
		return object{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return object{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return object{"type": "number"}
	case reflect.Slice, reflect.Array:
		return array(modelSchema(t.Elem()))
	case reflect.Map:
		return object{"type": "object", "additionalProperties": modelSchema(t.Elem())}
	default:
		return object{}
	}
}

func models(a *stonewrit.Auth, info stonewrit.HTTPDescription) object {
	user := modelSchema(reflect.TypeFor[stonewrit.User]())
	session := modelSchema(reflect.TypeFor[stonewrit.Session]())
	userFields := user["properties"].(object)
	sessionFields := session["properties"].(object)
	for name, plugin := range map[string]string{"username": "username", "displayUsername": "username", "twoFactorEnabled": "two-factor", "role": "admin", "banned": "admin", "banExpires": "admin", "banReason": "admin", "isAnonymous": "anonymous", "lastLoginMethod": "last-login-method"} {
		if !a.HasPlugin(plugin) || name == "displayUsername" && !info.DisplayUsername {
			delete(userFields, name)
		}
	}
	for name, plugin := range map[string]string{"impersonatedBy": "admin", "activeOrganizationId": "organization", "activeTeamId": "organization", "credentialType": "api-key"} {
		if !a.HasPlugin(plugin) {
			delete(sessionFields, name)
		}
	}
	hasTeams := slices.ContainsFunc(info.Routes, func(r stonewrit.HTTPRoute) bool {
		return r.Plugin == "organization" && r.Path == "/organization/create-team"
	})
	if !hasTeams {
		delete(sessionFields, "activeTeamId")
	}
	m := object{"User": user, "Session": session, "Account": modelSchema(reflect.TypeFor[stonewrit.LinkedAccount]()), "Error": modelSchema(reflect.TypeFor[stonewrit.APIError]()),
		"SessionResult": responseObject(object{"user": modelRef("User"), "session": modelRef("Session")}, "user", "session")}
	if a.HasPlugin("organization") {
		m["Organization"] = modelSchema(reflect.TypeFor[organization.Organization]())
		m["Member"] = modelSchema(reflect.TypeFor[organization.Member]())
		m["Invitation"] = modelSchema(reflect.TypeFor[organization.Invitation]())
		if hasTeams {
			m["Team"] = modelSchema(reflect.TypeFor[organization.Team]())
			m["TeamMember"] = modelSchema(reflect.TypeFor[organization.TeamMember]())
		}
	}
	if a.HasPlugin("api-key") {
		m["APIKey"] = modelSchema(reflect.TypeFor[apikey.Key]())
	}
	if a.HasPlugin("passkey") {
		m["Passkey"] = modelSchema(reflect.TypeFor[passkey.Record]())
	}
	if a.HasPlugin("stripe") && slices.ContainsFunc(info.Routes, func(r stonewrit.HTTPRoute) bool { return r.Plugin == "stripe" && r.Path == "/subscription/list" }) {
		m["Subscription"] = modelSchema(reflect.TypeFor[billing.Subscription]())
	}
	return m
}
