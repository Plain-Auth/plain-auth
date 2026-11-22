package sqlstore

import (
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"maps"
	"slices"

	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/go-sql-driver/mysql"
)

var _ authn.Store = (*Store)(nil)

// Close releases the database connection.
func (s *Store) Close() error { return s.db.Close() }

// CreateUser commits the user, credential account, and optional session together.
func (s *Store) CreateUser(ctx context.Context, user authn.User, passwordHash string, initial *authn.StoredSession) error {
	return s.createUser(ctx, user, &passwordHash, initial, nil)
}

// SaveFixtureUser persists a test user without creating a credential or session.
func (s *Store) SaveFixtureUser(ctx context.Context, user authn.User) error {
	return s.createUser(ctx, user, nil, nil, nil)
}

func (s *Store) createUser(ctx context.Context, user authn.User, passwordHash *string, initial *authn.StoredSession, columns map[string]any) error {
	if initial != nil && initial.UserID != user.ID {
		return errors.New("sqlstore: initial session belongs to a different user")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	userInsert, args := s.userInsert(user, columns)
	if s.dialect != "mysql" {
		userInsert += ` ON CONFLICT("email") DO NOTHING`
	}
	result, err := tx.ExecContext(ctx, s.bind(userInsert), args...)
	if err != nil {
		var mysqlError *mysql.MySQLError
		if errors.As(err, &mysqlError) && mysqlError.Number == 1062 {
			// Distinguish an existing email from an unrelated primary key
			// collision without parsing a localized server error message.
			var emailExists bool
			row := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS (SELECT 1 FROM "user" WHERE "email" = ?)`), strings.ToLower(user.Email))
			if err := row.Scan(&emailExists); err != nil {
				return err
			}
			if emailExists {
				return authn.ErrEmailTaken
			}
		}
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return authn.ErrEmailTaken
	}
	if passwordHash != nil {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "account"
        ("id","accountId","providerId","userId","password","createdAt","updatedAt") VALUES (?,?,'credential',?,?,?,?)`),
			rand.Text(), user.ID, user.ID, *passwordHash, s.date(user.CreatedAt), s.date(user.UpdatedAt))
		if err != nil {
			return err
		}
	}
	if err := s.persistUsernames(ctx, tx, user, false); err != nil {
		return err
	}
	admin, err := s.detectAdminSchema(ctx, tx)
	if err != nil {
		return err
	}
	if admin {
		if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "role"=? WHERE "id"=?`), s.defaultAdminRole(), user.ID); err != nil {
			return err
		}
	}
	if initial != nil {
		if err := s.insertSession(ctx, tx, *initial); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// userInsert builds the canonical profile row for each account creation transaction.
func (s *Store) userInsert(user authn.User, columns map[string]any) (string, []any) {
	cols := `"id","email","name","image","emailVerified","createdAt","updatedAt"`
	args := []any{user.ID, strings.ToLower(user.Email), user.Name, user.Image, user.EmailVerified, s.date(user.CreatedAt), s.date(user.UpdatedAt)}
	for _, column := range slices.Sorted(maps.Keys(columns)) {
		cols += `,"` + column + `"`
		args = append(args, s.fieldParameter(columns[column]))
	}
	query := `INSERT INTO "user" (` + cols + `) VALUES (?` + strings.Repeat(",?", len(args)-1) + `)`
	return query, args
}

const userColumns = `u."id",u."email",u."name",u."image",u."emailVerified",u."createdAt",u."updatedAt"`

func userFields(u *authn.User) []any {
	return []any{&u.ID, &u.Email, &u.Name, &u.Image, &u.EmailVerified, &u.CreatedAt, &u.UpdatedAt}
}

// Credential retrieves a user and the credential account's password hash.
func (s *Store) Credential(ctx context.Context, email string) (authn.User, string, error) {
	return s.findCredential(ctx, `u."email"`, strings.ToLower(email))
}

func (s *Store) findCredential(ctx context.Context, column, login string) (authn.User, string, error) {
	var u authn.User
	var passwordHash string
	columns := userColumns
	fields := userFields(&u)
	var finish func()
	if s.adminRole != "" {
		columns += "," + adminUserColumns
		fields, finish = s.adminUserScanner(&u)
	}
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT `+columns+`,a."password" FROM "user" u JOIN "account" a ON a."userId"=u."id" WHERE `+column+`=? AND a."providerId"='credential' AND a."accountId"=u."id" AND a."password" IS NOT NULL`), login)
	err := row.Scan(append(fields, &passwordHash)...)
	if err == nil && finish != nil {
		finish()
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = authn.ErrNotFound
	}
	return u, passwordHash, err
}

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) insertSession(ctx context.Context, tx *sql.Tx, ss authn.StoredSession) error {
	cols := `"id","userId","token","ipAddress","userAgent","createdAt","updatedAt","expiresAt"`
	params := "?,?,?,?,?,?,?,?"
	args := []any{ss.ID, ss.UserID, ss.Token, ss.IPAddress, ss.UserAgent, s.date(ss.CreatedAt), s.date(ss.UpdatedAt), s.date(ss.ExpiresAt)}
	additional, err := ss.PhysicalSessionFields()
	if err != nil {
		return err
	}
	for _, column := range slices.Sorted(maps.Keys(additional)) {
		if !sessionfields.NameOK(column) {
			return errors.New("sqlstore: invalid additional session column")
		}
		cols += `,"` + column + `"`
		params += ",?"
		args = append(args, s.fieldParameter(additional[column]))
	}
	admin, err := s.detectAdminSchema(ctx, tx)
	if err != nil {
		return err
	}
	if admin {
		if err := s.adminSessionGate(ctx, tx, ss.UserID, time.Now()); err != nil {
			return err
		}
		cols += `,"impersonatedBy"`
		params += ",?"
		args = append(args, ss.ImpersonatedBy)
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "session" (`+cols+`) VALUES (`+params+`)`), args...)
	return err
}

// CreateSession saves a session using its token.
func (s *Store) CreateSession(ctx context.Context, ss authn.StoredSession) error {
	// Some MySQL versions ignore inline REFERENCES. Lock the canonical owner
	// until insertion commits so concurrent deletion cannot orphan a session.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockAccount(ctx, tx, ss.UserID); err != nil {
		return err
	}
	if err := s.insertSession(ctx, tx, ss); err != nil {
		return err
	}
	return tx.Commit()
}

const sessionColumns = `s."id",s."userId",s."token",COALESCE(s."ipAddress",''),COALESCE(s."userAgent",''),s."createdAt",s."updatedAt",s."expiresAt"`

func sessionFields(ss *authn.StoredSession) []any {
	return []any{&ss.ID, &ss.UserID, &ss.Token, &ss.IPAddress, &ss.UserAgent, &ss.CreatedAt, &ss.UpdatedAt, &ss.ExpiresAt}
}

// Session retrieves session state and its owner. The auth service checks expiry.
func (s *Store) Session(ctx context.Context, token string) (authn.StoredSession, authn.User, error) {
	if s.adminSchema.Load() {
		return s.adminSession(ctx, s.db, token)
	}
	var ss authn.StoredSession
	var u authn.User
	row := s.db.QueryRowContext(ctx, s.bind(`SELECT `+sessionColumns+`, `+userColumns+`
		FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token"=?`), token)
	err := row.Scan(append(sessionFields(&ss), userFields(&u)...)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = authn.ErrNotFound
	}
	if err == nil {
		// Read the base row first. A migration that committed before that row was
		// visible must be detected before returning it as an ordinary session.
		admin, e := s.detectAdminSchema(ctx, s.db)
		if e != nil {
			return authn.StoredSession{}, authn.User{}, e
		}
		if admin {
			return s.adminSession(ctx, s.db, token)
		}
	}
	return ss, u, err
}

// ListSessions retrieves the user's stored sessions in creation order, newest first.
func (s *Store) ListSessions(ctx context.Context, userID string) ([]authn.StoredSession, error) {
	admin, err := s.detectAdminSchema(ctx, s.db)
	if err != nil {
		return nil, err
	}
	columns := sessionColumns
	if admin {
		columns += `,s."impersonatedBy"`
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+columns+` FROM "session" s
		WHERE s."userId" = ? ORDER BY s."createdAt" DESC, s."id"`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []authn.StoredSession{}
	for rows.Next() {
		var ss authn.StoredSession
		fields := sessionFields(&ss)
		if admin {
			fields = append(fields, &ss.ImpersonatedBy)
		}
		if err := rows.Scan(fields...); err != nil {
			return nil, err
		}
		sessions = append(sessions, ss)
	}
	return sessions, rows.Err()
}

// DeleteSession revokes a session by its token.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "token" = ?`), token)
	return err
}

// DeleteOtherSessions revokes every session of a user except the one specified.
func (s *Store) DeleteOtherSessions(ctx context.Context, userID, keepToken string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "userId" = ? AND "token" <> ?`), userID, keepToken)
	return err
}

// DeleteUserSession revokes a session only when it belongs to the specified user.
func (s *Store) DeleteUserSession(ctx context.Context, userID, token string) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "userId" = ? AND "token" = ?`), userID, token)
	return err
}
