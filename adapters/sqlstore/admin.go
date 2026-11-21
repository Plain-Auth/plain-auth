package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	authn "github.com/Stonewrit/stonewrit-auth"
)

var _ authn.AdminStore = (*Store)(nil)

const adminUserColumns = `u."role",u."banned",u."banReason",u."banExpires"`
const adminDeniedMessage = "You have been banned from this application. Please contact support if you believe this is an error."

func (s *Store) detectAdminSchema(ctx context.Context) (bool, error) {
	var q string
	switch s.dialect {
	case "sqlite":
		q = `SELECT count(*) FROM pragma_table_info('user') WHERE name='banned'`
	case "mysql":
		q = `SELECT count(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='user' AND column_name='banned'`
	default:
		q = `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='user' AND column_name='banned'`
	}
	var count int
	err := s.db.QueryRowContext(ctx, q).Scan(&count)
	return count > 0, err
}
func (s *Store) WithAdminConfig(role, message string) (authn.AdminStore, error) {
	if !s.adminSchema {
		return nil, errors.New("sqlstore: apply the admin schema before enabling administration")
	}
	rows, err := s.db.Query(s.bind(`SELECT ` + adminUserColumns + `,s."impersonatedBy" FROM "user" u,"session" s WHERE 1=0`))
	if err != nil {
		return nil, errors.New("sqlstore: incomplete administrative schema")
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	copy := *s
	copy.adminRole = role
	copy.adminDenial = message
	return &copy, nil
}
func (s *Store) defaultAdminRole() string {
	if s.adminRole != "" {
		return s.adminRole
	}
	return "user"
}
func (s *Store) banError() error {
	message := s.adminDenial
	if message == "" {
		message = adminDeniedMessage
	}
	return &authn.APIError{Status: 403, Code: "BANNED_USER", Message: message}
}
func (s *Store) adminSessionGate(ctx context.Context, tx *sql.Tx, user string, now time.Time) error {
	var banned sql.NullBool
	var expires *time.Time
	var role sql.NullString
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "banned","banExpires","role" FROM "user" WHERE "id"=?`), user).Scan(&banned, &expires, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNotFound
	}
	if err != nil {
		return err
	}
	if banned.Bool {
		if expires == nil || expires.After(now) {
			return s.banError()
		}
		if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "banned"=?,"banReason"=NULL,"banExpires"=NULL WHERE "id"=?`), false, user); err != nil {
			return err
		}
	}
	if !role.Valid {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "role"=? WHERE "id"=?`), s.defaultAdminRole(), user)
	}
	return err
}
func (s *Store) adminUserScanner(u *authn.User) ([]any, func()) {
	var role sql.NullString
	var banned sql.NullBool
	u.AdminUserFields = &authn.AdminUserFields{}
	fields := append(userFields(u), &role, &banned, &u.BanReason, &u.BanExpires)
	return fields, func() {
		u.Role = role.String
		if u.Role == "" {
			u.Role = s.defaultAdminRole()
		}
		u.Banned = banned.Bool
	}
}
func adminDelegationKey(sessionID string) string {
	sum := sha256.Sum256([]byte("admin-delegation:" + sessionID))
	return hex.EncodeToString(sum[:16])
}
func (s *Store) adminSession(ctx context.Context, db rowQuerier, token string) (authn.StoredSession, authn.User, error) {
	var ss authn.StoredSession
	var user authn.User
	fields, finish := s.adminUserScanner(&user)
	p, _ := s.deviceTokenParameters([]string{token})
	query := `SELECT ` + sessionColumns + `,s."impersonatedBy",` + userColumns + `,` + adminUserColumns + ` FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token"=` + p
	err := db.QueryRowContext(ctx, s.bind(query), token).Scan(append(append(sessionFields(&ss), &ss.ImpersonatedBy), fields...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return ss, user, authn.ErrNotFound
	}
	if err != nil {
		return ss, user, err
	}
	finish()
	if user.Banned && (user.BanExpires == nil || user.BanExpires.After(time.Now())) {
		return authn.StoredSession{}, authn.User{}, authn.ErrNotFound
	}
	if ss.ImpersonatedBy != nil {
		// Sessions issued here bind to one original login. Read the binding if
		// present, and deny the delegated login if its source expired or vanished.
		var live bool
		err = db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "session" a JOIN "user" opUser ON opUser."id"=a."userId" WHERE a."id"=v."value" AND a."userId"=? AND a."expiresAt">? AND (COALESCE(opUser."banned",FALSE)=FALSE OR opUser."banExpires"<=?)) FROM "verification" v WHERE v."id"=? AND v."identifier"='admin-delegation'`), *ss.ImpersonatedBy, s.date(time.Now()), s.date(time.Now()), adminDelegationKey(ss.ID)).Scan(&live)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ss, user, err
		}
		if err == nil && !live {
			return authn.StoredSession{}, authn.User{}, authn.ErrNotFound
		}
	}
	return ss, user, nil
}

type adminTX struct {
	names, displayNames bool
	s                   *Store
	ctx                 context.Context
	tx                  *sql.Tx
	now                 time.Time
}

func (s *Store) AdminTransaction(ctx context.Context, token, target string, now time.Time, fn func(authn.AdminTransaction, authn.SessionResult) error) error {
	if !s.adminSchema {
		return errors.New("sqlstore: administrative schema required")
	}
	var err error
	for range 3 {
		err = s.runAdminTransaction(ctx, token, target, now, fn)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}
func (s *Store) runAdminTransaction(ctx context.Context, token, target string, now time.Time, fn func(authn.AdminTransaction, authn.SessionResult) error) error {
	opts := &sql.TxOptions{}
	if s.dialect != "sqlite" {
		opts.Isolation = sql.LevelReadCommitted
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	denied := &authn.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Unauthorized"}
	p, _ := s.deviceTokenParameters([]string{token})
	var actor string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "userId" FROM "session" WHERE "token"=`+p+` AND "expiresAt">?`), token, s.date(now)).Scan(&actor)
	if errors.Is(err, sql.ErrNoRows) {
		return denied
	}
	if err != nil {
		return err
	}
	ids := []string{actor}
	if target != "" && target != actor {
		ids = append(ids, target)
		slices.Sort(ids)
	}
	for _, id := range ids {
		err = s.lockAccount(ctx, tx, id)
		if errors.Is(err, authn.ErrNotFound) {
			if id == actor {
				return denied
			}
			continue
		}
		if err != nil {
			return err
		}
	}
	// Lock and revalidate the session after locking its owner. Revocation, demotion and ban cannot race the protected operation.
	var current string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "session" WHERE "token"=`+p+` AND "userId"=? AND "expiresAt">?`), token, actor, s.date(now)).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return denied
	}
	if err != nil {
		return err
	}
	ss, u, err := s.adminSession(ctx, tx, token)
	if errors.Is(err, authn.ErrNotFound) {
		return denied
	}
	if err != nil {
		return err
	}
	if err = fn(&adminTX{s: s, ctx: ctx, tx: tx, now: now}, authn.SessionResult{Session: ss.Session, User: u}); err != nil {
		return err
	}
	return tx.Commit()
}
func (t *adminTX) User(id string) (authn.User, error) {
	var u authn.User
	fields, finish := t.publicFields(&u)
	err := t.tx.QueryRowContext(t.ctx, t.s.bind(`SELECT `+t.publicColumns()+` FROM "user" u WHERE u."id"=?`), id).Scan(fields...)
	if errors.Is(err, sql.ErrNoRows) {
		return u, authn.ErrNotFound
	}
	finish()
	return u, err
}
func (t *adminTX) CreateUser(u authn.User, hash string) error {
	s := t.s
	var expires any
	if u.BanExpires != nil {
		expires = s.date(*u.BanExpires)
	}
	_, err := t.tx.ExecContext(t.ctx, s.bind(`INSERT INTO "user" ("id","email","name","image","emailVerified","createdAt","updatedAt","role","banned","banReason","banExpires") VALUES (?,?,?,?,?,?,?,?,?,?,?)`), u.ID, u.Email, u.Name, u.Image, u.EmailVerified, s.date(u.CreatedAt), s.date(u.UpdatedAt), u.Role, u.Banned, u.BanReason, expires)
	if duplicateConstraint(err) {
		return authn.ErrEmailTaken
	}
	if err != nil {
		return err
	}
	if err := s.persistUsernames(t.ctx, t.tx, u); err != nil {
		return err
	}
	if hash != "" {
		return t.SetPassword(u.ID, hash)
	}
	return nil
}
func (t *adminTX) UpdateUser(u authn.User) error {
	s := t.s
	var expires any
	if u.BanExpires != nil {
		expires = s.date(*u.BanExpires)
	}
	_, err := t.tx.ExecContext(t.ctx, s.bind(`UPDATE "user" SET "email"=?,"name"=?,"image"=?,"emailVerified"=?,"updatedAt"=?,"role"=?,"banned"=?,"banReason"=?,"banExpires"=? WHERE "id"=?`), u.Email, u.Name, u.Image, u.EmailVerified, s.date(u.UpdatedAt), u.Role, u.Banned, u.BanReason, expires, u.ID)
	if duplicateConstraint(err) {
		return authn.ErrEmailTaken
	}
	if err != nil {
		return err
	}
	return s.persistUsernames(t.ctx, t.tx, u)
}
func (t *adminTX) SetPassword(user, hash string) error {
	s := t.s
	var id string
	err := t.tx.QueryRowContext(t.ctx, s.bind(`SELECT "id" FROM "account" WHERE "providerId"='credential' AND "userId"=? AND "accountId"=?`), user, user).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = t.tx.ExecContext(t.ctx, s.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","password","createdAt","updatedAt") VALUES (?,'credential',?,?,?,?,?)`), rand.Text(), user, user, hash, s.date(t.now), s.date(t.now))
	} else if err == nil {
		_, err = t.tx.ExecContext(t.ctx, s.bind(`UPDATE "account" SET "password"=?,"updatedAt"=? WHERE "id"=?`), hash, s.date(t.now), id)
	}
	if err != nil {
		return err
	}
	return s.invalidateFactorChallenges(t.ctx, t.tx, user)
}
func (t *adminTX) UserSessions(user string) ([]authn.Session, error) {
	s := t.s
	rows, err := t.tx.QueryContext(t.ctx, s.bind(`SELECT "id","userId",COALESCE("ipAddress",''),COALESCE("userAgent",''),"createdAt","updatedAt","expiresAt","impersonatedBy" FROM "session" WHERE "userId"=? AND "expiresAt">? ORDER BY "createdAt" DESC,"id"`), user, s.date(t.now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authn.Session{}
	for rows.Next() {
		var ss authn.Session
		if err = rows.Scan(&ss.ID, &ss.UserID, &ss.IPAddress, &ss.UserAgent, &ss.CreatedAt, &ss.UpdatedAt, &ss.ExpiresAt, &ss.ImpersonatedBy); err != nil {
			return nil, err
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}
func (t *adminTX) RevokeSession(token string) error {
	p, _ := t.s.deviceTokenParameters([]string{token})
	_, err := t.tx.ExecContext(t.ctx, t.s.bind(`DELETE FROM "session" WHERE "token"=`+p), token)
	return err
}
func (t *adminTX) RevokeListedSession(userID, sessionID string) error {
	_, err := t.tx.ExecContext(t.ctx, t.s.bind(`DELETE FROM "session" WHERE "userId"=? AND "id"=?`), userID, sessionID)
	return err
}
func (t *adminTX) RevokeUserSessions(id string) error {
	_, err := t.tx.ExecContext(t.ctx, t.s.bind(`DELETE FROM "session" WHERE "userId"=? OR "impersonatedBy"=?`), id, id)
	if err != nil {
		return err
	}
	return t.s.invalidateFactorChallenges(t.ctx, t.tx, id)
}
func (t *adminTX) DeleteUser(id string) error {
	if err := t.RevokeUserSessions(id); err != nil {
		return err
	}
	return t.s.deleteAccountRows(t.ctx, t.tx, id)
}
func (t *adminTX) Impersonate(ss authn.StoredSession, source authn.Session) error {
	ss.ImpersonatedBy = &source.UserID
	if err := t.s.insertSession(t.ctx, t.tx, ss); err != nil {
		return err
	}
	_, err := t.tx.ExecContext(t.ctx, t.s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,'admin-delegation',?,?,?,?)`), adminDelegationKey(ss.ID), source.ID, t.s.date(ss.ExpiresAt), t.s.date(t.now), t.s.date(t.now))
	return err
}
func (t *adminTX) RestoreSession(current authn.Session, originalToken string, now time.Time) (authn.SessionResult, error) {
	var result authn.SessionResult
	deny := &authn.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Invalid return session"}
	if current.ImpersonatedBy == nil || originalToken == current.Token {
		return result, deny
	}
	if err := t.s.lockAccount(t.ctx, t.tx, *current.ImpersonatedBy); err != nil {
		if errors.Is(err, authn.ErrNotFound) {
			return result, deny
		}
		return result, err
	}
	s, u, err := t.s.adminSession(t.ctx, t.tx, originalToken)
	if errors.Is(err, authn.ErrNotFound) {
		return result, deny
	}
	if err != nil {
		return result, err
	}
	if s.UserID != *current.ImpersonatedBy || s.ImpersonatedBy != nil || !s.ExpiresAt.After(now) {
		return result, deny
	}
	if err = t.RevokeSession(current.Token); err != nil {
		return result, err
	}
	if _, err = t.tx.ExecContext(t.ctx, t.s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"='admin-delegation'`), adminDelegationKey(current.ID)); err != nil {
		return result, err
	}
	return authn.SessionResult{User: u, Session: s.Session}, nil
}

var adminListFields = map[string]string{"id": `u."id"`, "email": `u."email"`, "name": `u."name"`, "role": `u."role"`, "banned": `u."banned"`, "emailVerified": `u."emailVerified"`, "createdAt": `u."createdAt"`, "updatedAt": `u."updatedAt"`, "banReason": `u."banReason"`, "banExpires": `u."banExpires"`}

func adminFilter(field, op string, values []string) (string, []any, error) {
	if field == "" {
		field = "email"
	}
	column, ok := adminListFields[field]
	bad := &authn.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Invalid administrative query"}
	if !ok {
		return "", nil, bad
	}
	args := make([]any, len(values))
	for i, v := range values {
		args[i] = v
		if field == "banned" || field == "emailVerified" {
			switch v {
			case "true", "1":
				args[i] = true
			case "false", "0":
				args[i] = false
			default:
				return "", nil, bad
			}
		}
	}
	if op == "in" || op == "not_in" {
		if len(args) == 0 {
			return "", nil, bad
		}
		word := " IN "
		if op == "not_in" {
			word = " NOT IN "
		}
		return column + word + "(" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")", args, nil
	}
	if len(args) != 1 {
		return "", nil, bad
	}
	switch op {
	case "", "eq":
		return column + "=?", args, nil
	case "ne":
		return column + "<>?", args, nil
	case "gt", "gte", "lt", "lte":
		return column + map[string]string{"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op] + "?", args, nil
	case "contains", "starts_with", "ends_with":
		if field != "name" && field != "email" && field != "role" && field != "banReason" && field != "id" {
			return "", nil, bad
		}
		v := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(values[0])
		if op != "starts_with" {
			v = "%" + v
		}
		if op != "ends_with" {
			v += "%"
		}
		return column + " LIKE ? ESCAPE '!'", []any{v}, nil
	}
	return "", nil, bad
}
func (t *adminTX) Users(q authn.AdminQuery) (authn.AdminPage, error) {
	out := authn.AdminPage{Users: []authn.User{}, Limit: q.Limit, Offset: q.Offset}
	var terms []string
	var args []any
	if q.SearchValue != "" {
		op := q.SearchOperator
		if op == "" {
			op = "contains"
		}
		term, v, err := adminFilter(q.SearchField, op, []string{q.SearchValue})
		if err != nil {
			return out, err
		}
		terms = append(terms, term)
		args = append(args, v...)
	}
	if q.FilterValues != nil {
		term, v, err := adminFilter(q.FilterField, q.FilterOperator, q.FilterValues)
		if err != nil {
			return out, err
		}
		terms = append(terms, term)
		args = append(args, v...)
	}
	where := ""
	if len(terms) > 0 {
		where = " WHERE " + strings.Join(terms, " AND ")
	}
	column := "id"
	if q.SortBy != "" {
		column = q.SortBy
	}
	sort, ok := adminListFields[column]
	if !ok || q.Limit < 0 || q.Offset < 0 || (q.SortDirection != "" && q.SortDirection != "asc" && q.SortDirection != "desc") {
		return out, &authn.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Invalid administrative query"}
	}
	err := t.tx.QueryRowContext(t.ctx, t.s.bind(`SELECT COUNT(*) FROM "user" u`+where), args...).Scan(&out.Total)
	if err != nil {
		return out, err
	}
	query := `SELECT ` + t.publicColumns() + ` FROM "user" u` + where + " ORDER BY " + sort + " " + q.SortDirection + `,u."id"`
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	query += " LIMIT ? OFFSET ?"
	rows, err := t.tx.QueryContext(t.ctx, t.s.bind(query), append(args, limit, q.Offset)...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var u authn.User
		fields, finish := t.publicFields(&u)
		if err = rows.Scan(fields...); err != nil {
			return out, err
		}
		finish()
		out.Users = append(out.Users, u)
	}
	return out, rows.Err()
}
