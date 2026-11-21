package stripe

import (
	"encoding/json"
	"net/http"
	"strings"

	auth "github.com/Stonewrit/stonewrit-auth"
)

type billingField struct {
	name, kind string
	required   bool
}

// Field order determines the order of errors for requests with several invalid values.
var (
	referenceField    = billingField{"referenceId", "string", false}
	customerTypeField = billingField{"customerType", "customerType", false}
	subscriptionField = billingField{"subscriptionId", "string", false}
	redirectField     = billingField{"disableRedirect", "boolean", false}
	listFields        = []billingField{referenceField, customerTypeField}
	portalFields      = []billingField{
		{"locale", "locale", false}, referenceField, customerTypeField, {"returnUrl", "string", false}, redirectField,
	}
	cancelFields = []billingField{
		referenceField, subscriptionField, customerTypeField, {"returnUrl", "string", true}, redirectField,
	}
	restoreFields  = []billingField{referenceField, subscriptionField, customerTypeField}
	checkoutFields = []billingField{
		{"plan", "string", true}, {"annual", "boolean", false}, referenceField, subscriptionField,
		customerTypeField, {"successUrl", "string", false}, {"cancelUrl", "string", false},
		{"returnUrl", "string", false}, redirectField, {"scheduleAtPeriodEnd", "boolean", false},
	}
)

func billingValueKind(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	case json.Number:
		return "number"
	case []any, []string:
		return "array"
	default:
		return "object"
	}
}

func billingOwner(c auth.EndpointContext, schema []billingField) (*auth.SessionResult, error) {
	values, source := c.Body, "body"
	if c.Request.Method == http.MethodGet {
		values, source = make(map[string]any), "query"
		for name, entries := range c.Request.URL.Query() {
			if len(entries) == 1 {
				values[name] = entries[0]
			} else {
				values[name] = entries
			}
		}
	}
	var issues []string
	for _, field := range schema {
		value, present := values[field.name]
		if !present && !field.required {
			continue
		}
		prefix := "[" + source + "." + field.name + "] "
		actual := "undefined"
		if present {
			actual = billingValueKind(value)
		}
		switch field.kind {
		case "customerType":
			if value != "user" && value != "organization" {
				issues = append(issues, prefix+`Invalid option: expected one of "user"|"organization"`)
			}
		case "locale":
			if actual != "string" {
				issues = append(issues, prefix+"Invalid input")
			}
		default:
			if actual != field.kind {
				issues = append(issues, prefix+"Invalid input: expected "+field.kind+", received "+actual)
			}
		}
	}
	if len(issues) != 0 {
		return nil, billingError(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
	}
	session, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrCheckoutSession
	}
	if err := session.Session.RequireOwner(); err != nil {
		return nil, err
	}
	if values["customerType"] == "organization" {
		return nil, billingError(400, "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED", "Organization subscription is not enabled")
	}
	if id, _ := values["referenceId"].(string); id != "" && id != session.User.ID {
		return nil, billingError(400, "REFERENCE_ID_NOT_ALLOWED", "Reference id is not allowed")
	}
	return session, nil
}
