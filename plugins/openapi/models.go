package openapi

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/apikey"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/plugins/passkey"
	billing "github.com/Plain-Auth/plain-auth/plugins/stripe"
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

func models(a *plainauth.Auth, info plainauth.HTTPDescription) object {
	user := modelSchema(reflect.TypeFor[plainauth.User]())
	session := modelSchema(reflect.TypeFor[plainauth.Session]())
	userFields := user["properties"].(object)
	sessionFields := session["properties"].(object)
	addOutputFields(session, info.SessionFields)
	addOutputFields(user, info.UserFields)
	for name, plugin := range map[string]string{"phoneNumber": "phone-number", "phoneNumberVerified": "phone-number", "username": "username", "displayUsername": "username", "twoFactorEnabled": "two-factor", "role": "admin", "banned": "admin", "banExpires": "admin", "banReason": "admin", "isAnonymous": "anonymous", "lastLoginMethod": "last-login-method"} {
		if !a.HasPlugin(plugin) || name == "displayUsername" && !info.DisplayUsername {
			delete(userFields, name)
		}
	}
	for name, plugin := range map[string]string{"impersonatedBy": "admin", "activeOrganizationId": "organization", "activeTeamId": "organization", "credentialType": "api-key"} {
		if !a.HasPlugin(plugin) {
			delete(sessionFields, name)
		}
	}
	hasTeams := slices.ContainsFunc(info.Routes, func(r plainauth.HTTPRoute) bool {
		return r.Plugin == "organization" && r.Path == "/organization/create-team"
	})
	if !hasTeams {
		delete(sessionFields, "activeTeamId")
	}
	m := object{"User": user, "Session": session, "Account": modelSchema(reflect.TypeFor[plainauth.LinkedAccount]()), "Error": modelSchema(reflect.TypeFor[plainauth.APIError]()),
		"SessionResult": responseObject(object{"user": modelRef("User"), "session": modelRef("Session")}, "user", "session")}
	if a.HasPlugin("organization") {
		if slices.ContainsFunc(info.Routes, func(r plainauth.HTTPRoute) bool {
			return r.Plugin == "organization" && (r.Path == "/organization/get-role" || r.Path == "/organization/list-roles" || r.Path == "/organization/create-role" || r.Path == "/organization/update-role")
		}) {
			m["OrganizationRole"] = modelSchema(reflect.TypeFor[organization.RoleDefinition]())
		}
		m["Organization"] = modelSchema(reflect.TypeFor[organization.Organization]())
		m["Member"] = modelSchema(reflect.TypeFor[organization.Member]())
		invitation := modelSchema(reflect.TypeFor[organization.Invitation]())
		if !hasTeams {
			delete(invitation["properties"].(object), "teamId")
		}
		m["Invitation"] = invitation
		lists := object{"members": array(organizationMemberProfile()), "invitations": array(modelRef("Invitation"))}
		required := []string{"members", "invitations"}
		if hasTeams {
			lists["teams"] = array(modelRef("Team"))
			required = append(required, "teams")
			m["Team"] = modelSchema(reflect.TypeFor[organization.Team]())
			m["TeamMember"] = modelSchema(reflect.TypeFor[organization.TeamMember]())
		}
		m["FullOrganization"] = object{"allOf": []object{modelRef("Organization"), responseObject(lists, required...)}}
	}
	if a.HasPlugin("api-key") {
		m["APIKey"] = modelSchema(reflect.TypeFor[apikey.Key]())
	}
	if a.HasPlugin("passkey") {
		m["Passkey"] = modelSchema(reflect.TypeFor[passkey.Record]())
	}
	if a.HasPlugin("stripe") && slices.ContainsFunc(info.Routes, func(r plainauth.HTTPRoute) bool { return r.Plugin == "stripe" && r.Path == "/subscription/list" }) {
		m["Subscription"] = modelSchema(reflect.TypeFor[billing.Subscription]())
	}
	return m
}

func addOutputFields(schema object, fields map[string]plainauth.HTTPField) {
	properties := schema["properties"].(object)
	var required []string
	for name, field := range fields {
		if !field.Returned {
			continue
		}
		property := scalarFieldSchema(field)
		if !field.Writable {
			property["readOnly"] = true
		}
		properties[name] = property
		if field.Required {
			required = append(required, name)
		}
	}
	if len(required) != 0 {
		slices.Sort(required)
		schema["required"] = append(schema["required"].([]string), required...)
	}
}

func scalarFieldSchema(field plainauth.HTTPField) object {
	t := string(field.Type)
	schema := object{}
	switch field.Type {
	case plainauth.FieldNumber:
		t = "integer"
		schema["minimum"], schema["maximum"] = math.MinInt32, math.MaxInt32
	case plainauth.FieldDate:
		t = "string"
		schema["format"] = "date-time"
	}
	if field.Required {
		schema["type"] = t
	} else {
		schema["type"] = []string{t, "null"}
	}
	return schema
}
