package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var idTokenCoreFields = map[string]auth.SessionFieldType{
	"id": auth.FieldString, "name": auth.FieldString, "email": auth.FieldString, "image": auth.FieldString,
	"emailVerified": auth.FieldBoolean, "createdAt": auth.FieldDate, "updatedAt": auth.FieldDate,
}

func (s *Store) idTokenClaimsSnapshot(ctx context.Context, tx *sql.Tx, userID string, client op.AuthorizationCodeClient, record op.DelegatedAccessRecord) (string, error) {
	// Only declared and schema-owned fields enter the hook input. For a
	// declared field the host may have chosen a different physical name.
	fields, err := sessionfields.Normalize(record.IDTokenUserFields)
	if err != nil {
		return "", err
	}
	projection := make(map[string]auth.UserField, len(fields)+len(idTokenCoreFields))
	for name, kind := range idTokenCoreFields {
		projection[name] = auth.UserField{Type: kind, Column: name}
	}
	maps.Copy(projection, fields)
	names := slices.Sorted(maps.Keys(projection))
	columns := make([]string, 0, len(names))
	dest := make([]any, 0, len(names))
	for _, name := range names {
		f := projection[name]
		columns = append(columns, `u."`+f.Column+`"`)
		dest = append(dest, scalarDestination(f.Type))
	}
	query := `SELECT ` + strings.Join(columns, ",") + ` FROM "user" u WHERE u."id"=` + s.exactSQLValue("?")
	if err := tx.QueryRowContext(ctx, s.readForUpdate(query), userID).Scan(dest...); err != nil {
		return "", err
	}
	user := make(map[string]any, len(names))
	attributes := make(map[string]any, len(fields))
	for i, name := range names {
		f := projection[name]
		value, err := f.PublicValue(scannedScalar(dest[i]))
		if err != nil {
			return "", err
		}
		if _, custom := fields[name]; custom {
			attributes[name] = value
		}
		if !f.Hidden {
			user[name] = value
		}
	}
	// Keep an immutable representation across the unlocked callback. On the
	// final pass the exact claims inputs must still match before committing.
	data, err := json.Marshal(struct {
		User, UserFields map[string]any
		Scopes           []string
		Metadata         map[string]json.RawMessage
	}{user, attributes, record.Scopes, client.Metadata})
	return string(data), err
}
