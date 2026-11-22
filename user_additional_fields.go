package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

// UserField configures a scalar profile attribute. Column names its storage column.
// ServerOnly reserves writes for the host. Hidden excludes the field from responses.
type UserField = sessionfields.Field

// UserFieldValues carries validated physical values into the account creation transaction.
type UserFieldValues struct{ columns map[string]any }

// RegistrationUserFields holds the configured defaults for a new profile.
// Adapters inspect it only after determining that the verified identity is new.
type RegistrationUserFields struct {
	values UserFieldValues
	err    error
}

// Columns returns validated physical columns, or an error when a required
// field has no default that the registration flow can supply.
func (f RegistrationUserFields) Columns() (map[string]any, error) {
	return f.values.Columns(), f.err
}

func (a *Auth) registrationUserFields() RegistrationUserFields {
	values, err := a.prepareUserFields(nil, true, true)
	if err != nil {
		// A mailbox caller cannot supply these attributes. Keep their names private.
		return RegistrationUserFields{err: errors.New("missing registration profile default")}
	}
	return RegistrationUserFields{values: values}
}

// Columns returns a copy keyed by physical column name.
func (v UserFieldValues) Columns() map[string]any { return maps.Clone(v.columns) }

// Present reports whether any configured columns participate in this write.
func (v UserFieldValues) Present() bool { return len(v.columns) > 0 }

// PhysicalUserFields provides only the columns previously validated by Auth.
func (p ProfileUpdate) PhysicalUserFields() map[string]any { return p.validatedFields.Columns() }

// UserFieldStore commits configured fields with their user/credential/session or
// profile writes. ReadUserFields returns public columns only, keyed by physical name.
// UpdateUserFields must lock the exact user and revalidate any supplied direct session.
type UserFieldStore interface {
	ValidateUserFields(map[string]UserField) error
	CreateUserWithFields(context.Context, User, string, *StoredSession, UserFieldValues) error
	ReadUserFields(context.Context, string, map[string]UserField) (map[string]any, error)
	UpdateUserFields(context.Context, string, *Session, ProfileUpdate, time.Time) error
}

func (a *Auth) userFieldInput(body map[string]any) map[string]any {
	var out map[string]any
	for name := range a.opts.UserAdditionalFields {
		if raw, ok := body[name]; ok {
			if out == nil {
				out = map[string]any{}
			}
			out[name] = raw
		}
	}
	return out
}

func (a *Auth) prepareUserFields(input map[string]any, create, trusted bool) (UserFieldValues, error) {
	var out UserFieldValues
	for name := range input {
		if _, ok := a.opts.UserAdditionalFields[name]; !ok {
			return out, &APIError{400, "VALIDATION_ERROR", "Unknown user field " + name}
		}
	}
	for _, name := range sessionfields.Names(a.opts.UserAdditionalFields) {
		field := a.opts.UserAdditionalFields[name]
		raw, ok := input[name]
		if ok && field.ServerOnly && !trusted {
			switch {
			case create && field.Default != nil:
				raw = field.Default
			case emptyUserInput(raw):
				// A false, zero, empty or null browser value for an input:false
				// field is ignored by the profile parser.
				ok = false
			default:
				return out, &APIError{400, "FIELD_NOT_ALLOWED", name + " is not allowed to be set"}
			}
		}
		if !ok {
			if !create {
				continue
			}
			raw = field.Default
			if field.Required && raw == nil {
				return out, &APIError{400, "MISSING_FIELD", name + " is required"}
			}
		}
		value, err := field.Value(raw)
		if err != nil {
			return out, &APIError{400, "VALIDATION_ERROR", "Invalid field " + name}
		}
		if out.columns == nil {
			out.columns = make(map[string]any)
		}
		out.columns[field.Column] = value
	}
	return out, nil
}

// Only the scalar values JavaScript considers false take the no-write path.
func emptyUserInput(v any) bool {
	if v == nil {
		return true
	}
	if n, ok := v.(json.Number); ok {
		f, err := n.Float64()
		return err == nil && f == 0
	}
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.String:
		return value.IsZero()
	}
	return false
}

// UpdateTrustedUserFields patches explicitly configured fields, including hidden
// and server-owned attributes. Call it only after the host authorizes userID.
func (a *Auth) UpdateTrustedUserFields(ctx context.Context, userID string, changes map[string]any) error {
	values, err := a.prepareUserFields(changes, false, true)
	if err != nil {
		return err
	}
	if !values.Present() {
		return &APIError{400, "BAD_REQUEST", "No fields to update"}
	}
	return a.opts.Store.(UserFieldStore).UpdateUserFields(ctx, userID, nil, ProfileUpdate{validatedFields: values}, a.now().UTC())
}

func (a *Auth) readUserExtras(ctx context.Context, user *User) error {
	user.extraJSON = ""
	if user.ID == "" || len(a.opts.UserAdditionalFields) == 0 {
		return nil
	}
	columns, err := a.opts.Store.(UserFieldStore).ReadUserFields(ctx, user.ID, a.opts.UserAdditionalFields)
	if err != nil {
		return err
	}
	return a.projectPublicUser(user, columns)
}

func (a *Auth) projectPublicUser(user *User, columns map[string]any) error {
	user.extraJSON = ""
	var public map[string]any
	for name, f := range a.opts.UserAdditionalFields {
		if f.Hidden {
			continue
		}
		value, err := f.Value(columns[f.Column])
		if err != nil {
			return fmt.Errorf("invalid stored user field %q: %w", name, err)
		}
		if public == nil {
			public = make(map[string]any)
		}
		public[name] = value
	}
	if len(public) > 0 {
		raw, err := json.Marshal(public)
		if err != nil {
			return err
		}
		user.extraJSON = string(raw)
	}
	return nil
}

// AdditionalField returns a public profile value, with int64 for numbers and
// a separate presence flag for nullable fields.
func (u User) AdditionalField(name string) (any, bool) { return additionalField(u.extraJSON, name) }

type wireUser User

func (u User) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(wireUser(u))
	if err != nil || u.extraJSON == "" {
		return raw, err
	}
	raw[len(raw)-1] = ','
	return append(raw, u.extraJSON[1:]...), nil
}

func (u *User) UnmarshalJSON(data []byte) error {
	var wire wireUser
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	for key := range input {
		if !sessionfields.UserNameOK(key) {
			delete(input, key)
		}
	}
	*u = User(wire)
	if len(input) > 0 {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		u.extraJSON = string(raw)
	}
	return nil
}
