package sso

import (
	"encoding/json"
	"errors"
	"fmt"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/jsjson"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

// ProviderField declares an additional column on the SSO provider table.
// Declare the same map in schema.AdditionalFields.SSOProvider.
type ProviderField = auth.SessionField

// ProviderFieldStore binds declared provider fields to a store view that
// writes and reads their columns.
type ProviderFieldStore interface {
	WithSSOProviderFields(map[string]ProviderField) (auth.Store, error)
}

// configureProviderFields gives the instance a store view for the declared
// provider fields.
func (o Options) configureProviderFields(s auth.Store) (auth.Store, error) {
	store, ok := s.(ProviderFieldStore)
	if !ok {
		return nil, errors.New("sso: ProviderAdditionalFields require a ProviderFieldStore")
	}
	return store.WithSSOProviderFields(o.ProviderAdditionalFields)
}

// providerFieldInput reads the declared fields from the top level of a
// registration or update body, as another runtime does. A registration
// fills defaults for the rest; an update changes only the fields it names.
func (o Options) providerFieldInput(body map[string]any, create bool) (map[string]any, error) {
	var out map[string]any
	for _, name := range sessionfields.Names(o.ProviderAdditionalFields) {
		field := o.ProviderAdditionalFields[name]
		raw, ok := body[name]
		if ok && field.ServerOnly {
			return nil, &auth.APIError{Status: 400, Code: "FIELD_NOT_ALLOWED", Message: name + " is not allowed to be set"}
		}
		var value any
		var err error
		switch {
		case ok:
			if value, err = field.Value(raw); err != nil {
				return nil, fieldInputError(name, field, jsjson.TypeName(raw))
			}
		case !create:
			continue
		// A settable required field is checked with the body, as another
		// runtime's schema checks it; a server-only one when it is filled.
		case field.Required && !field.ServerOnly:
			return nil, fieldInputError(name, field, "undefined")
		case field.Required && field.Default == nil:
			return nil, &auth.APIError{Status: 400, Code: "MISSING_FIELD", Message: name + " is required"}
		default:
			if value, err = field.CreationDefault(); err != nil {
				return nil, fmt.Errorf("sso: default for provider field %q: %w", name, err)
			}
		}
		if out == nil {
			out = make(map[string]any)
		}
		out[name] = value
	}
	return out, nil
}

// fieldInputError refuses a missing or mistyped field in another runtime's
// body validation form.
func fieldInputError(name string, field ProviderField, received string) error {
	return &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "[body." + name + "] Invalid input: expected " + string(field.Type) + ", received " + received}
}

// publicFields returns the declared fields responses show: every field but
// a Hidden one.
func (o Options) publicFields(values map[string]any) map[string]any {
	var out map[string]any
	for _, name := range sessionfields.Names(o.ProviderAdditionalFields) {
		field := o.ProviderAdditionalFields[name]
		if field.Hidden {
			continue
		}
		value, err := field.PublicValue(values[name])
		if err != nil {
			continue
		}
		if out == nil {
			out = make(map[string]any)
		}
		out[name] = value
	}
	return out
}

// inlineFields writes the declared fields beside the built-in keys.
func inlineFields(base any, fields map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil || len(fields) == 0 {
		return raw, err
	}
	var merged map[string]json.RawMessage
	if err = json.Unmarshal(raw, &merged); err != nil {
		return nil, err
	}
	for name, value := range fields {
		if _, taken := merged[name]; taken {
			continue
		}
		if merged[name], err = json.Marshal(value); err != nil {
			return nil, err
		}
	}
	return json.Marshal(merged)
}

// MarshalJSON writes the provider's declared fields beside its keys.
func (p PublicProvider) MarshalJSON() ([]byte, error) {
	type plain PublicProvider
	return inlineFields(plain(p), p.AdditionalFields)
}

// MarshalJSON writes the registered provider's declared fields beside its keys.
func (r Registered) MarshalJSON() ([]byte, error) {
	type plain Registered
	return inlineFields(plain(r), r.AdditionalFields)
}

// providerFieldsOpenAPI describes the declared fields for the OpenAPI
// document under x-plainauth-provider-fields: each field's JSON schema,
// whether a request may set it and whether it must, and whether responses
// return it.
func (o Options) providerFieldsOpenAPI() (json.RawMessage, error) {
	type described struct {
		Schema   map[string]any `json:"schema"`
		Input    bool           `json:"input"`
		Required bool           `json:"required"`
		Returned bool           `json:"returned"`
	}
	fields := make(map[string]described, len(o.ProviderAdditionalFields))
	for name, field := range o.ProviderAdditionalFields {
		schema := map[string]any{"type": string(field.Type)}
		if field.Type == auth.FieldDate {
			schema = map[string]any{"type": "string", "format": "date-time"}
		}
		fields[name] = described{Schema: schema, Input: !field.ServerOnly, Required: field.Required && field.Default == nil, Returned: !field.Hidden}
	}
	return json.Marshal(map[string]any{"x-plainauth-provider-fields": fields})
}
