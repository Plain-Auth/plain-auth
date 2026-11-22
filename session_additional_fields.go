package plainauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

// SessionField declares a scalar session attribute. Column defaults to the
// public name. ServerOnly disables browser writes; Hidden omits the output.
type SessionField = sessionfields.Field
type SessionFieldType = sessionfields.Type

const (
	FieldString  = sessionfields.String
	FieldNumber  = sessionfields.Number
	FieldBoolean = sessionfields.Boolean
)

// SessionFieldStore persists configured physical columns. Reads must return only
// rows with the requested token, session ID and owner. Update must reauthorize
// that exact direct session and apply its patch atomically.
type SessionFieldStore interface {
	ValidateSessionFields(map[string]SessionField) error
	ReadSessionFields(context.Context, []Session, map[string]SessionField) (map[string]map[string]any, error)
	UpdateSessionFields(context.Context, Session, map[string]SessionField, map[string]any, time.Time) error
}

// PhysicalSessionFields supplies an adapter with validated column names and
// their scalar values for the same transaction that inserts a session.
func (s StoredSession) PhysicalSessionFields() (map[string]any, error) {
	if s.storageFields == nil {
		return nil, nil
	}
	if s.storageFields.invalid != "" {
		return nil, errors.New(s.storageFields.invalid)
	}
	out := make(map[string]any, len(s.storageFields.columns))
	for k, v := range s.storageFields.columns {
		out[k] = v
	}
	return out, nil
}

type storedSessionFields struct {
	columns map[string]any
	invalid string
}

// WithTrustedSessionFields prepares an unpersisted row using configured defaults
// and trusted overrides, including ServerOnly fields. It never writes to storage.
func (a *Auth) WithTrustedSessionFields(row StoredSession, overrides map[string]any) (StoredSession, error) {
	row.Session.extraJSON = ""
	row.storageFields = nil
	fields := a.opts.SessionAdditionalFields
	for name := range overrides {
		if _, ok := fields[name]; !ok {
			return StoredSession{}, fmt.Errorf("unknown additional session field %q", name)
		}
	}
	if len(fields) == 0 {
		return row, nil
	}
	columns := make(map[string]any, len(fields))
	for _, name := range sessionfields.Names(fields) {
		f := fields[name]
		raw, ok := overrides[name]
		if !ok {
			raw = f.Default
		}
		v, err := f.Value(raw)
		if err != nil {
			return StoredSession{}, fmt.Errorf("session field %q: %w", name, err)
		}
		columns[f.Column] = v
	}
	row.storageFields = &storedSessionFields{columns: columns}
	return row, nil
}

// AdditionalField reads a public field returned by the configured instance.
// Numbers use int64. A present null is distinct from an absent field.
func (s Session) AdditionalField(name string) (any, bool) {
	return additionalField(s.extraJSON, name)
}

func additionalField(data, name string) (any, bool) {
	if data == "" {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(data), &fields) != nil {
		return nil, false
	}
	raw, ok := fields[name]
	if !ok {
		return nil, false
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return nil, false
	}
	if n, ok := v.(json.Number); ok {
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	return v, true
}

type wireSession Session

func (s Session) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(wireSession(s))
	if err != nil || s.extraJSON == "" {
		return base, err
	}
	base[len(base)-1] = ','
	return append(base, s.extraJSON[1:]...), nil
}
func (s *Session) UnmarshalJSON(data []byte) error {
	var bare wireSession
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	for key := range input {
		if !sessionfields.NameOK(key) {
			delete(input, key)
		}
	}
	*s = Session(bare)
	if len(input) > 0 {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		s.extraJSON = string(raw)
	}
	return nil
}

func (a *Auth) projectSessionFields(ctx context.Context, rows []Session) error {
	for i := range rows {
		rows[i].extraJSON = ""
	}
	fields := a.opts.SessionAdditionalFields
	if len(fields) == 0 || len(rows) == 0 {
		return nil
	}
	data, err := a.opts.Store.(SessionFieldStore).ReadSessionFields(ctx, rows, fields)
	if err != nil {
		return err
	}
	for i := range rows {
		raw, ok := data[rows[i].Token]
		if !ok {
			rows[i] = Session{}
			continue
		}
		values := make(map[string]any)
		for name, f := range fields {
			if !f.Hidden {
				value, err := f.Value(raw[name])
				if err != nil {
					return fmt.Errorf("invalid stored session field %q: %w", name, err)
				}
				values[name] = value
			}
		}
		if len(values) > 0 {
			encoded, err := json.Marshal(values)
			if err != nil {
				return err
			}
			rows[i].extraJSON = string(encoded)
		}
	}
	return nil
}

// UpdateSession changes configured, browser-writable fields of the direct
// session. Built-in authority fields never participate in this operation.
func (a *Auth) UpdateSession(ctx context.Context, h http.Header, patch map[string]any) (Session, error) {
	current, err := a.requireOwnerSession(ctx, h)
	if err != nil {
		return Session{}, err
	}
	fields := a.opts.SessionAdditionalFields
	changes := make(map[string]any)
	for _, name := range sessionfields.Names(fields) {
		raw, ok := patch[name]
		if !ok {
			continue
		}
		f := fields[name]
		if f.ServerOnly {
			return Session{}, &APIError{400, "FIELD_NOT_ALLOWED", name + " is not allowed to be set"}
		}
		value, err := f.Value(raw)
		if err != nil {
			return Session{}, &APIError{400, "VALIDATION_ERROR", "Invalid field " + name}
		}
		changes[name] = value
	}
	if len(changes) == 0 {
		return Session{}, &APIError{Status: 400, Message: "No fields to update"}
	}
	now := a.now().UTC().Truncate(time.Millisecond)
	if err := a.opts.Store.(SessionFieldStore).UpdateSessionFields(ctx, current.Session, fields, changes, now); err != nil {
		if errors.Is(err, ErrNotFound) {
			return Session{}, &APIError{401, "FAILED_TO_GET_SESSION", "Failed to get session"}
		}
		return Session{}, err
	}
	updated, err := a.GetSession(ctx, h)
	if err != nil {
		return Session{}, err
	}
	if updated == nil || updated.Session.ID != current.Session.ID {
		return Session{}, &APIError{401, "FAILED_TO_GET_SESSION", "Failed to get session"}
	}
	return updated.Session, nil
}

func (a *Auth) sessionFieldsHTTP(w http.ResponseWriter, r *http.Request, body wireBody) (any, error) {
	s, err := a.UpdateSession(r.Context(), r.Header, body)
	if err != nil {
		return nil, err
	}
	if err := a.addSessionCookieHeaders(w.Header(), r, s.Token, !a.dontRemember(r)); err != nil {
		return nil, err
	}
	return map[string]Session{"session": s}, nil
}

// WithStoredSessionPatch is for memory-backed adapters applying a validated
// patch while holding their session lock. It preserves fields from other nodes.
func (s StoredSession) WithStoredSessionPatch(fields map[string]SessionField, patch map[string]any) (StoredSession, error) {
	if len(patch) == 0 {
		return StoredSession{}, errors.New("empty session field patch")
	}
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return StoredSession{}, err
	}
	columns, err := s.PhysicalSessionFields()
	if err != nil {
		return StoredSession{}, err
	}
	if columns == nil {
		columns = make(map[string]any)
	}
	for name, value := range patch {
		f, ok := fields[name]
		if !ok || f.ServerOnly {
			return StoredSession{}, errors.New("cannot update session field")
		}
		v, err := f.Value(value)
		if err != nil {
			return StoredSession{}, err
		}
		columns[f.Column] = v
	}
	s.storageFields = &storedSessionFields{columns: columns}
	return s, nil
}
