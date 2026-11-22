package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/Plain-Auth/plain-auth/internal/jsjson"
	"github.com/Plain-Auth/plain-auth/plugins/scim"
)

var _ scim.Store = (*Store)(nil)

func scimKey(parts ...string) string {
	data, _ := jsjson.Marshal(parts) // Encoding an array of strings cannot fail.
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func (s *Store) scimExact(col string) string {
	if s.dialect == "mysql" {
		return "BINARY " + col
	}
	return col
}
func (s *Store) scimScope() string {
	return s.scimExact(`"connectionId"`) + `=? AND ` + s.scimExact(`"provisioningDomainId"`) + `=?`
}

// Persist the first connection/domain binding independently of resource mutations.
// A failed lookup or rejected mutation still fixes the original domain.
func (s *Store) scimTx(ctx context.Context, d scim.Directory, fn func(*sql.Tx) error) error {
	return s.scimTxMode(ctx, d, false, fn)
}
func (s *Store) scimWriteTx(ctx context.Context, d scim.Directory, fn func(*sql.Tx) error) error {
	return s.scimTxMode(ctx, d, true, fn)
}
func (s *Store) scimTxMode(ctx context.Context, d scim.Directory, write bool, fn func(*sql.Tx) error) error {
	key := scimKey("scim-connection", d.ID)
	query := `SELECT "connectionId","provisioningDomainId","decommissionStatus" FROM "scimConnectionBinding" WHERE "connectionKey"=?`
	var exists string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "scimConnectionBinding" WHERE "connectionKey"=?`), key).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		q := `INSERT INTO "scimConnectionBinding" ("id","connectionId","connectionKey","provisioningDomainId","createdAt","decommissionStatus","decommissionBatchCount","decommissionRevision","decommissionReconciledUserCount") VALUES (?,?,?,?,?,'active',0,0,0)`
		if s.dialect == "mysql" {
			q += ` ON DUPLICATE KEY UPDATE "id"="id"`
		} else {
			q += ` ON CONFLICT("connectionKey") DO NOTHING`
		}
		_, err = s.db.ExecContext(ctx, s.bind(q), rand.Text(), d.ID, key, d.ProvisioningDomainID, s.date(time.Now()))
	}
	if err != nil {
		return err
	}
	tx, finish, err := s.beginSCIMTransaction(ctx, d.ProvisioningDomainID, write)
	if err != nil {
		return err
	}
	defer finish.rollback()
	if write {
		if err = s.requireSCIMPolicy(ctx, tx, d.ProvisioningDomainID); err != nil {
			return err
		}
	}
	if p, ok := scim.PrincipalFromContext(ctx); ok && p.Kind == "managed-bearer" {
		if err = s.lockManagedPrincipal(ctx, tx, d, p); err != nil {
			return err
		}
	}
	var connection, domain, status string
	if err = tx.QueryRowContext(ctx, s.readForUpdate(query), key).Scan(&connection, &domain, &status); err != nil {
		return err
	}
	if connection != d.ID || domain != d.ProvisioningDomainID {
		return scim.ErrDomain
	}
	if status != "active" {
		return scim.ErrDecommissioned
	}
	if err = fn(tx); err != nil {
		if duplicateConstraint(err) {
			return scim.ErrConflict
		}
		return err
	}
	return finish.commit()
}

const scimUserColumns = `"id","userId","userName","displayName","externalId","primaryEmail","active","serializedAttributes","serializedEmails","formattedName","givenName","familyName","createdAt","updatedAt"`

type directoryUser struct {
	scim.Record
	owner string
}

func scanSCIMUser(row rowScanner) (u directoryUser, err error) {
	var external, attrs, given, family sql.NullString
	var emails, formatted string
	err = row.Scan(&u.ID, &u.owner, &u.UserName, &u.DisplayName, &external, &u.PrimaryEmail, &u.Active, &attrs, &emails, &formatted, &given, &family, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return u, err
	}
	u.ExternalID = external.String
	if attrs.Valid {
		err = json.Unmarshal([]byte(attrs.String), &u.Attributes)
		if err == nil && u.Attributes == nil {
			err = errors.New("sqlstore: empty SCIM attributes")
		}
		return u, err
	}
	var entries []any
	if err = json.Unmarshal([]byte(emails), &entries); err != nil {
		return u, err
	}
	name := map[string]any{"formatted": formatted}
	if given.Valid {
		name["givenName"] = given.String
	}
	if family.Valid {
		name["familyName"] = family.String
	}
	u.Attributes = map[string]any{"name": name, "schemas": []any{scim.UserSchema}, "emails": entries}
	return u, nil
}
func (s *Store) scimFind(ctx context.Context, tx *sql.Tx, d scim.Directory, keyCol, key string) (directoryUser, error) {
	q := `SELECT ` + scimUserColumns + ` FROM "scimUser" WHERE ` + s.scimScope() + ` AND ` + s.scimExact(keyCol) + `=?`
	u, err := scanSCIMUser(tx.QueryRowContext(ctx, s.bind(q), d.ID, d.ProvisioningDomainID, key))
	if errors.Is(err, sql.ErrNoRows) {
		err = scim.ErrNotFound
	}
	return u, err
}
func (s *Store) SCIMGet(ctx context.Context, d scim.Directory, id string) (r scim.Record, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error { u, e := s.scimFind(ctx, tx, d, `"id"`, id); r = u.Record; return e })
	return
}
func (s *Store) SCIMList(ctx context.Context, d scim.Directory, q scim.Query) (records []scim.Record, total int, err error) {
	err = s.scimTx(ctx, d, func(tx *sql.Tx) error {
		where := s.scimScope()
		args := []any{d.ID, d.ProvisioningDomainID}
		for _, f := range q.Filters {
			var col string
			val := f.Value
			switch f.Attribute {
			case "id":
				col = `"id"`
			case "username":
				col = `"userNameKey"`
				val = scimKey("scim-user-name", d.ID, strings.ToLower(val))
			case "externalid":
				col = `"externalIdKey"`
				val = scimKey("scim-user-external-id", d.ID, val)
			case "emails.value", "emails.work.value":
				col = `"emailValueIndex"`
				if f.Attribute == "emails.work.value" {
					col = `"workEmailValueIndex"`
				}
				token := "|" + scimKey("scim-email-value", strings.ToLower(val)) + "|"
				if s.dialect == "postgres" {
					where += ` AND strpos(` + col + `,?)>0`
				} else {
					where += ` AND instr(` + s.scimExact(col) + `,?)>0`
				}
				args = append(args, token)
				continue
			default:
				return errors.New("sqlstore: unsupported SCIM filter")
			}
			where += " AND " + s.scimExact(col) + "=?"
			args = append(args, val)
		}
		from := ` FROM "scimUser" WHERE ` + where
		if e := tx.QueryRowContext(ctx, s.bind("SELECT count(*)"+from), args...).Scan(&total); e != nil {
			return e
		}
		if q.Count <= 0 {
			return nil
		}
		rows, e := tx.QueryContext(ctx, s.bind("SELECT "+scimUserColumns+from+` ORDER BY "orderKey" LIMIT ? OFFSET ?`), append(args, min(100, q.Count), max(0, q.Offset))...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			u, e := scanSCIMUser(rows)
			if e != nil {
				return e
			}
			records = append(records, u.Record)
		}
		return rows.Err()
	})
	return
}

const scimMutableColumns = `"userName","userNameKey","primaryEmail","workEmailValueIndex","emailValueIndex","displayName","formattedName","givenName","familyName","serializedEmails","serializedAttributes","externalId","externalIdKey","active","updatedAt"`

func (s *Store) scimArgs(d scim.Directory, p scim.Profile, now time.Time) ([]any, error) {
	var external, key any
	if p.ExternalID != "" {
		external = p.ExternalID
		key = scimKey("scim-user-external-id", d.ID, p.ExternalID)
	}
	name, ok := p.Attributes["name"].(map[string]any)
	if !ok {
		return nil, errors.New("sqlstore: missing SCIM name")
	}
	emails, ok := p.Attributes["emails"].([]any)
	if !ok {
		return nil, errors.New("sqlstore: missing SCIM emails")
	}
	work, all := map[string]bool{}, map[string]bool{}
	for _, entry := range emails {
		m, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New("sqlstore: invalid SCIM email")
		}
		v, ok := m["value"].(string)
		if !ok {
			return nil, errors.New("sqlstore: invalid SCIM address")
		}
		token := scimKey("scim-email-value", strings.ToLower(v))
		all[token] = true
		if m["type"] == "work" {
			work[token] = true
		}
	}
	index := func(keys map[string]bool) string {
		return "|" + strings.Join(slices.Sorted(maps.Keys(keys)), "|") + "|"
	}
	e, err := json.Marshal(emails)
	if err != nil {
		return nil, err
	}
	a, err := jsjson.Marshal(p.Attributes)
	if err != nil {
		return nil, err
	}
	if _, hasRoles := p.Attributes["roles"]; hasRoles && s.dialect == "mysql" && len(a) > 65_535 {
		// The canonical MySQL TEXT column also limits encoded bytes, whereas
		// the protocol bounds the length of the serialized JSON string.
		return nil, &scim.Error{Status: 400, Type: "invalidValue", Detail: "SCIM User attributes exceed the database text limit"}
	}
	return []any{p.UserName, scimKey("scim-user-name", d.ID, strings.ToLower(p.UserName)), p.PrimaryEmail, index(work), index(all), p.DisplayName, name["formatted"], name["givenName"], name["familyName"], string(e), string(a), external, key, p.Active, s.date(now)}, nil
}

func (s *Store) scimInsert(ctx context.Context, tx *sql.Tx, d scim.Directory, u directoryUser) error {
	args, err := s.scimArgs(d, u.Profile, u.UpdatedAt)
	if err != nil {
		return err
	}
	cols := scimMutableColumns + `,"id","userId","connectionId","provisioningDomainId","connectionUserKey","orderKey","createdAt"`
	order := fmt.Sprintf("%015d:%s", u.CreatedAt.UnixMilli(), rand.Text()[:16])
	args = append(args, u.ID, u.owner, d.ID, d.ProvisioningDomainID, scimKey("scim-user", d.ID, u.owner), order, s.date(u.CreatedAt))
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimUser" (`+cols+`) VALUES (`+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")"), args...)
	return err
}
