package sqlstore

import (
	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	"github.com/Plain-Org/plain-auth/plugins/sso"
)

var _ sso.ProviderFieldStore = (*Store)(nil)

// WithSSOProviderFields validates the declared provider columns without
// changing the shared pool, and returns a view that writes and reads them.
func (s *Store) WithSSOProviderFields(defs map[string]sso.ProviderField) (auth.Store, error) {
	fields, err := sessionfields.NormalizeSSOProvider(defs)
	if err != nil {
		return nil, err
	}
	if err := s.validateModelFields("ssoProvider", fields); err != nil {
		return nil, err
	}
	view := *s
	view.ssoFields = fields
	return &view, nil
}

// providerCols lists the provider columns, then the declared ones in name
// order.
func (s *Store) providerCols() string {
	cols := browserProviderCols
	for _, name := range sessionfields.Names(s.ssoFields) {
		cols += `,p."` + s.ssoFields[name].Column + `"`
	}
	return cols
}

// providerFieldDest appends a scan destination for each declared column.
func (s *Store) providerFieldDest(dest []any) []any {
	for _, name := range sessionfields.Names(s.ssoFields) {
		dest = append(dest, scalarDestination(s.ssoFields[name].Type))
	}
	return dest
}

// providerFields reads the declared values scanned into dest from offset on.
func (s *Store) providerFields(dest []any, offset int) (map[string]any, error) {
	names := sessionfields.Names(s.ssoFields)
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(names))
	for i, name := range names {
		value, err := s.ssoFields[name].PublicValue(scannedScalar(dest[offset+i]))
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, nil
}

// providerFieldWrite returns the declared columns and values to write. An
// update writes only the fields it carries.
func (s *Store) providerFieldWrite(values map[string]any, all bool) (columns []string, args []any) {
	for _, name := range sessionfields.Names(s.ssoFields) {
		value, present := values[name]
		if !present && !all {
			continue
		}
		// A value read back for the response is in its public form, such as
		// a date string, so it is parsed again before it is written.
		if value != nil {
			parsed, err := s.ssoFields[name].Value(value)
			if err == nil {
				value = parsed
			}
		}
		columns = append(columns, `"`+s.ssoFields[name].Column+`"`)
		args = append(args, s.fieldParameter(value))
	}
	return columns, args
}
