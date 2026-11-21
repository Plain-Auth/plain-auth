package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strings"

	auth "github.com/FineStack/finestack-auth"
)

var _ auth.MagicLinkStore = (*Store)(nil)

type magicLinkRecord struct {
	Type  string `json:"type"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

func (s *Store) SaveMagicLink(ctx context.Context, ch auth.MagicLinkChallenge) error {
	var err error
	for range 3 {
		err = s.saveMagicLink(ctx, ch)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}

func (s *Store) saveMagicLink(ctx context.Context, ch auth.MagicLinkChallenge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "expiresAt"<=? AND ("identifier" LIKE 'magic-link:%' OR "identifier" LIKE 'magic-link-owner:%')`), s.date(ch.CreatedAt)); err != nil {
		return err
	}
	email := strings.ToLower(ch.Email)
	raw, err := json.Marshal(magicLinkRecord{Type: "magic-link", Email: email, Name: ch.Name})
	if err != nil {
		return err
	}
	tokenHash := sha256.Sum256([]byte(ch.Key))
	id := "ml-" + hex.EncodeToString(tokenHash[:16])
	insert := s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`)
	save := func(id, key, value string) error {
		_, err := tx.ExecContext(ctx, insert, id, key, value, s.date(ch.ExpiresAt), s.date(ch.CreatedAt), s.date(ch.CreatedAt))
		return err
	}
	if err = save(id, "magic-link:"+ch.Key, string(raw)); err != nil {
		return err
	}
	var owner string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "user" WHERE "email"=?`), email).Scan(&owner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// The separate owner binding keeps the canonical mail-link value readable
	// by other runtimes and prevents a deleted account's link from being reassigned.
	if owner != "" {
		if err = save(rand.Text(), "magic-link-owner:"+id, owner); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CompleteMagicLink(ctx context.Context, key, newID string, session auth.StoredSession, allowSignup bool) (auth.User, bool, error) {
	var user auth.User
	var created bool
	var err error
	for range 3 {
		user, created, err = s.completeMagicLink(ctx, key, newID, session, allowSignup)
		if !retryIdentity(err) {
			break
		}
	}
	return user, created, err
}

func (s *Store) completeMagicLink(ctx context.Context, key, newID string, session auth.StoredSession, allowSignup bool) (auth.User, bool, error) {
	var user auth.User
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return user, false, err
	}
	defer tx.Rollback()
	var id, identifier, data string
	now := s.date(session.CreatedAt)
	purpose := "magic-link:" + key
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","identifier","value" FROM "verification" WHERE "identifier"=? AND "expiresAt">? ORDER BY "createdAt" DESC LIMIT 1`), purpose, now).Scan(&id, &identifier, &data)
	if err != nil {
		return user, false, factorRowError(err)
	}
	// Some database collations fold case. Bearer credentials are byte-exact.
	if identifier != purpose {
		return user, false, auth.ErrNotFound
	}
	var rec magicLinkRecord
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&rec) != nil || decoder.Decode(new(any)) != io.EOF || rec.Type != "magic-link" {
		return user, false, auth.ErrNotFound
	}
	addr, err := mail.ParseAddress(rec.Email)
	if err != nil || addr.Address != rec.Email || !strings.Contains(rec.Email, "@") {
		return user, false, auth.ErrNotFound
	}
	var bound string
	ownerKey := "magic-link-owner:" + id
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE "identifier"=?`), ownerKey).Scan(&bound)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return user, false, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? OR "identifier"=?`), id, ownerKey); err != nil {
		return user, false, err
	}
	finishDenial := func(reason error) (auth.User, bool, error) {
		if err := tx.Commit(); err != nil {
			return auth.User{}, false, err
		}
		return auth.User{}, false, reason
	}
	email := strings.ToLower(rec.Email)
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`), email).Scan(userFields(&user)...)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return user, false, err
	}
	if bound != "" && (created || user.ID != bound) {
		return finishDenial(auth.ErrNotFound)
	}
	if created {
		if !allowSignup {
			return finishDenial(auth.ErrMagicLinkSignUpDisabled)
		}
		user = auth.User{ID: newID, Email: email, Name: rec.Name, EmailVerified: true, CreatedAt: session.CreatedAt, UpdatedAt: session.CreatedAt}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), newID, email, rec.Name, true, now, now)
		if err != nil {
			return user, false, err
		}
	} else if !user.EmailVerified {
		if err = s.promoteMagicLinkOwner(ctx, tx, user.ID, session); err != nil {
			return user, false, err
		}
		user.EmailVerified = true
		user.UpdatedAt = session.CreatedAt
	}
	session.UserID = user.ID
	if err = s.insertSession(ctx, tx, session); err != nil {
		return user, false, err
	}
	return user, created, tx.Commit()
}

// Remove standing access created before this mailbox was proven. The caller
// holds the owning user lock until the new verified session has been committed.
func (s *Store) promoteMagicLinkOwner(ctx context.Context, tx *sql.Tx, id string, session auth.StoredSession) error {
	for _, q := range []string{
		`DELETE FROM "account" WHERE "userId"=?`,
		`DELETE FROM "session" WHERE "userId"=?`,
		`DELETE FROM "verification" WHERE "value"=? AND ("identifier" LIKE 'reset-password:%' OR "identifier" LIKE 'delete-account-%')`,
	} {
		if _, err := tx.ExecContext(ctx, s.bind(q), id); err != nil {
			return err
		}
	}
	factor, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return err
	}
	if factor {
		if err = s.invalidateFactorChallenges(ctx, tx, id); err != nil {
			return err
		}
		for _, q := range []string{`DELETE FROM "twoFactor" WHERE "userId"=?`, `UPDATE "user" SET "twoFactorEnabled"=false WHERE "id"=?`} {
			if _, err = tx.ExecContext(ctx, s.bind(q), id); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=?`), "2fa-totp-step-"+id); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=true,"updatedAt"=? WHERE "id"=?`), s.date(session.CreatedAt), id)
	return err
}
