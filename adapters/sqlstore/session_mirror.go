package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ authn.SessionMirrorStore = (*Store)(nil)

// sessionMirror is the SecondaryStorage this store keeps session copies in.
// Every copy of a Store shares it, so plugins holding the original store,
// such as SCIM, revoke mirrored sessions too.
type sessionMirror struct{ storage authn.SecondaryStorage }

// MirrorSessions keeps a copy of each live session in storage. The copy is
// written only while the session's rows are locked, and deleted before a
// revocation, a refresh or a change to its user commits, so a session read
// served from storage never outlives what the database allows. Attaching
// the same storage again does nothing; a different one is an error.
func (s *Store) MirrorSessions(storage authn.SecondaryStorage, _ authn.SessionMirrorOptions) error {
	if storage == nil {
		return errors.New("sqlstore: SecondaryStorage is nil")
	}
	if s.mirror == nil {
		return errors.New("sqlstore: this store cannot mirror sessions")
	}
	if s.mirror.CompareAndSwap(nil, &sessionMirror{storage}) {
		return nil
	}
	if current := s.mirror.Load(); sameStorage(current.storage, storage) {
		return nil
	}
	return errors.New("sqlstore: this store already mirrors sessions into another SecondaryStorage")
}

func sameStorage(a, b authn.SecondaryStorage) (same bool) {
	defer func() {
		if recover() != nil {
			same = false // a storage of an uncomparable type
		}
	}()
	return a == b
}

func (s *Store) sessionMirror() *sessionMirror {
	if s.mirror == nil {
		return nil
	}
	return s.mirror.Load()
}

// mirroredSession is a session copy: the base session columns and the
// owner's base user columns, plus the admin columns on an admin schema.
type mirroredSession struct {
	Session struct {
		ID        string    `json:"id"`
		UserID    string    `json:"userId"`
		Token     string    `json:"token"`
		IPAddress string    `json:"ipAddress"`
		UserAgent string    `json:"userAgent"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"session"`
	User struct {
		ID            string     `json:"id"`
		Name          string     `json:"name"`
		Email         string     `json:"email"`
		EmailVerified bool       `json:"emailVerified"`
		Image         *string    `json:"image"`
		CreatedAt     time.Time  `json:"createdAt"`
		UpdatedAt     time.Time  `json:"updatedAt"`
		Role          *string    `json:"role,omitempty"`
		Banned        *bool      `json:"banned,omitempty"`
		BanReason     *string    `json:"banReason,omitempty"`
		BanExpires    *time.Time `json:"banExpires,omitempty"`
	} `json:"user"`
}

func encodeMirroredSession(ss authn.StoredSession, u authn.User) (string, error) {
	var m mirroredSession
	m.Session.ID, m.Session.UserID, m.Session.Token = ss.ID, ss.UserID, ss.Token
	m.Session.IPAddress, m.Session.UserAgent = ss.IPAddress, ss.UserAgent
	m.Session.CreatedAt, m.Session.UpdatedAt, m.Session.ExpiresAt = ss.CreatedAt.UTC(), ss.UpdatedAt.UTC(), ss.ExpiresAt.UTC()
	m.User.ID, m.User.Name, m.User.Email, m.User.EmailVerified, m.User.Image = u.ID, u.Name, u.Email, u.EmailVerified, u.Image
	m.User.CreatedAt, m.User.UpdatedAt = u.CreatedAt.UTC(), u.UpdatedAt.UTC()
	if u.AdminUserFields != nil {
		role, banned := u.Role, u.Banned
		m.User.Role, m.User.Banned, m.User.BanReason, m.User.BanExpires = &role, &banned, u.BanReason, u.BanExpires
	}
	raw, err := json.Marshal(m)
	return string(raw), err
}

// mirrorTTL is the time left until expires in whole seconds, or 0 when less
// than a second is left and no copy should be written.
func mirrorTTL(expires time.Time) time.Duration {
	return time.Until(expires).Truncate(time.Second)
}

// readMirroredSession serves a session from storage. It reports false for a
// missing or unusable copy, which the caller then reads from the database.
func (s *Store) readMirroredSession(ctx context.Context, m *sessionMirror, token string) (authn.StoredSession, authn.User, bool, error) {
	raw, found, err := m.storage.Get(ctx, token)
	if err != nil || !found {
		return authn.StoredSession{}, authn.User{}, false, err
	}
	var entry mirroredSession
	if json.Unmarshal([]byte(raw), &entry) != nil || entry.Session.Token != token || entry.Session.UserID != entry.User.ID || !entry.Session.ExpiresAt.After(time.Now()) {
		return authn.StoredSession{}, authn.User{}, false, nil
	}
	admin := entry.User.Role != nil && entry.User.Banned != nil
	if admin && !s.adminSchema.Load() {
		if _, err := s.detectAdminSchema(ctx, s.db); err != nil {
			return authn.StoredSession{}, authn.User{}, false, err
		}
	}
	if admin != s.adminSchema.Load() {
		return authn.StoredSession{}, authn.User{}, false, nil
	}
	var ss authn.StoredSession
	ss.ID, ss.UserID, ss.Token = entry.Session.ID, entry.Session.UserID, entry.Session.Token
	ss.IPAddress, ss.UserAgent = entry.Session.IPAddress, entry.Session.UserAgent
	ss.CreatedAt, ss.UpdatedAt, ss.ExpiresAt = entry.Session.CreatedAt, entry.Session.UpdatedAt, entry.Session.ExpiresAt
	u := authn.User{ID: entry.User.ID, Name: entry.User.Name, Email: entry.User.Email, EmailVerified: entry.User.EmailVerified, Image: entry.User.Image,
		CreatedAt: entry.User.CreatedAt, UpdatedAt: entry.User.UpdatedAt}
	if admin {
		u.AdminUserFields = &authn.AdminUserFields{Role: *entry.User.Role, Banned: *entry.User.Banned, BanReason: entry.User.BanReason, BanExpires: entry.User.BanExpires}
		if u.Banned && (u.BanExpires == nil || u.BanExpires.After(time.Now())) {
			return authn.StoredSession{}, authn.User{}, true, authn.ErrNotFound
		}
	}
	return ss, u, true, nil
}

// readForShare locks the rows a read returns until the transaction ends.
// SQLite serializes write transactions instead.
func (s *Store) readForShare(query string) string {
	if s.dialect != "sqlite" {
		query += " FOR SHARE"
	}
	return s.bind(query)
}

// repopulateSession reads a session the storage lacks and copies it back
// while holding its owner's row and then its own row, in that order, so a
// revocation, refresh or user change either finishes first or waits. A few
// statements lock a session before its owner, so a deadlock is retried.
func (s *Store) repopulateSession(ctx context.Context, m *sessionMirror, token string) (authn.StoredSession, authn.User, error) {
	for attempt := 0; ; attempt++ {
		ss, u, err := s.repopulateSessionOnce(ctx, m, token)
		if attempt == 2 || !lockConflict(err) {
			return ss, u, err
		}
	}
}

// lockConflict reports a deadlock or serialization failure.
func lockConflict(err error) bool {
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1213
	}
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "40001" || pg.Code == "40P01")
}

func (s *Store) repopulateSessionOnce(ctx context.Context, m *sessionMirror, token string) (authn.StoredSession, authn.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return authn.StoredSession{}, authn.User{}, err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "userId" FROM "session" WHERE "token"=?`), token).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.StoredSession{}, authn.User{}, authn.ErrNotFound
	}
	if err != nil {
		return authn.StoredSession{}, authn.User{}, err
	}
	var locked string
	if err = tx.QueryRowContext(ctx, s.readForShare(`SELECT "id" FROM "user" WHERE "id"=?`), userID).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = authn.ErrNotFound
		}
		return authn.StoredSession{}, authn.User{}, err
	}
	ss, u, err := s.lockedSession(ctx, tx, token)
	if err != nil {
		return ss, u, err
	}
	if ttl := mirrorTTL(ss.ExpiresAt); ss.ImpersonatedBy == nil && ss.UserID == userID && ttl >= time.Second {
		if raw, err := encodeMirroredSession(ss, u); err == nil {
			// The database answered, so a failed copy only costs the next
			// read. A failed write may still run later, so delete it while
			// the rows are locked.
			if m.storage.Set(ctx, token, raw, ttl) != nil {
				_ = m.storage.Delete(ctx, token)
			}
		}
	}
	return ss, u, tx.Commit()
}

// lockedSession reads a session and its owner for share inside tx.
func (s *Store) lockedSession(ctx context.Context, tx *sql.Tx, token string) (authn.StoredSession, authn.User, error) {
	admin, err := s.detectAdminSchema(ctx, tx)
	if err != nil {
		return authn.StoredSession{}, authn.User{}, err
	}
	if admin {
		return s.adminSession(ctx, shareQuerier{tx, s}, token)
	}
	var ss authn.StoredSession
	var u authn.User
	err = tx.QueryRowContext(ctx, s.readForShare(`SELECT `+sessionColumns+`, `+userColumns+`
		FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token"=?`), token).Scan(append(sessionFields(&ss), userFields(&u)...)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = authn.ErrNotFound
	}
	return ss, u, err
}

// shareQuerier adds FOR SHARE to the session read adminSession makes, so
// it returns the latest committed rows under MySQL's repeatable reads too.
type shareQuerier struct {
	tx *sql.Tx
	s  *Store
}

func (q shareQuerier) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if q.s.dialect != "sqlite" {
		query += " FOR SHARE"
	}
	return q.tx.QueryRowContext(ctx, query, args...)
}

// mirrorNewSession copies a session inserted in tx. Its owner's row is read
// for share, which the insert's foreign key check already allows, so a user
// change waits for this transaction and then deletes the copy, and the
// client only learns the token after the transaction commits.
func (s *Store) mirrorNewSession(ctx context.Context, tx *sql.Tx, ss authn.StoredSession, admin bool) error {
	m := s.sessionMirror()
	if m == nil || ss.ImpersonatedBy != nil {
		return nil
	}
	ttl := mirrorTTL(ss.ExpiresAt)
	if ttl < time.Second {
		return nil
	}
	var u authn.User
	fields := userFields(&u)
	finish := func() {}
	columns := userColumns
	if admin {
		fields, finish = s.adminUserScanner(&u)
		columns += `,` + adminUserColumns
	}
	if err := tx.QueryRowContext(ctx, s.readForShare(`SELECT `+columns+` FROM "user" u WHERE u."id"=?`), ss.UserID).Scan(fields...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authn.ErrNotFound
		}
		return err
	}
	finish()
	// The copy holds the times as stored: UTC milliseconds.
	stored := func(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }
	ss.CreatedAt, ss.UpdatedAt, ss.ExpiresAt = stored(ss.CreatedAt), stored(ss.UpdatedAt), stored(ss.ExpiresAt)
	raw, err := encodeMirroredSession(ss, u)
	if err != nil {
		return err
	}
	return m.storage.Set(ctx, ss.Token, raw, ttl)
}

type sessionQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// forgetUserSessions deletes the copies of a user's sessions after a change
// to a column they hold. A failed delete fails the change.
func (s *Store) forgetUserSessions(ctx context.Context, db sessionQuerier, userID string) error {
	m := s.sessionMirror()
	if m == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, s.bind(`SELECT "token" FROM "session" WHERE "userId"=?`), userID)
	if err != nil {
		return err
	}
	tokens, err := scanStrings(rows)
	if err != nil {
		return err
	}
	return m.forget(ctx, tokens)
}

// forgetAgainAfter is when forget deletes the copies a second time.
const forgetAgainAfter = 2 * time.Second

// forget deletes the copies of tokens. A read whose copy write timed out
// may still have that write in flight, and the storage can run it after
// this delete, so the copies are deleted once more shortly afterwards.
func (m *sessionMirror) forget(ctx context.Context, tokens []string) error {
	if m == nil || len(tokens) == 0 {
		return nil
	}
	for _, token := range tokens {
		if err := m.storage.Delete(ctx, token); err != nil {
			return err
		}
	}
	tokens = slices.Clone(tokens)
	time.AfterFunc(forgetAgainAfter, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, token := range tokens {
			_ = m.storage.Delete(ctx, token)
		}
	})
	return nil
}

// execUserUpdate runs an UPDATE of user id's row and then deletes the
// copies of that user's sessions, inside tx so a failed delete rolls the
// change back.
func (s *Store) execUserUpdate(ctx context.Context, tx *sql.Tx, userID, query string, args ...any) (sql.Result, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if err == nil {
		err = s.forgetUserSessions(ctx, tx, userID)
	}
	return result, err
}
