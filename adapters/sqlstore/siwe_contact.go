package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/emailaddress"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
)

var _ siwe.ContactStore = (*Store)(nil)
var errContactCollision = errors.New("siwe: contact was occupied during wallet registration")

func (s *Store) ReserveWalletContact(ctx context.Context, email, address string) (*siwe.ContactClaim, error) {
	if !emailaddress.ValidWalletContact(email) || email != strings.ToLower(email) || address == "" {
		return nil, nil
	}
	identifier := "siwe-email-claim-" + email
	if s.dialect == "mysql" && len(identifier) > 255 {
		return nil, nil
	}
	id := s.verificationReservationID(identifier)
	var claim *siwe.ContactClaim
	err := s.emailOTPTransaction(ctx, walletLock("contact", email), func(tx *sql.Tx) (error, error) {
		claim = nil
		now := time.Now().UTC().Truncate(time.Millisecond)
		var unavailable bool
		err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "verification" WHERE "identifier"=? AND "expiresAt">?) OR EXISTS(SELECT 1 FROM "user" WHERE LOWER("email")=?)`), identifier, s.date(now), email).Scan(&unavailable)
		if err != nil || unavailable {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt"<=?`), id, identifier, s.date(now)); err != nil {
			return nil, err
		}
		claim = &siwe.ContactClaim{ID: id, Address: address, Email: email, Receipt: address + ":" + rand.Text(), ExpiresAt: now.Add(time.Minute)}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, identifier, claim.Receipt, s.date(claim.ExpiresAt), s.date(now), s.date(now))
		return nil, err
	})
	if duplicateConstraint(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return claim, nil
}

type walletClaimDeleter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (s *Store) deleteWalletClaim(ctx context.Context, db walletClaimDeleter, c siwe.ContactClaim, live bool) (bool, error) {
	id := "siwe-email-claim-" + c.Email
	if s.verificationReservationID(id) != c.ID || !strings.HasPrefix(c.Receipt, c.Address+":") || !emailaddress.ValidWalletContact(c.Email) || c.Email != strings.ToLower(c.Email) {
		return false, nil
	}
	exact := s.exactSQLValue("?")
	q := `DELETE FROM "verification" WHERE "id"=` + exact + ` AND "identifier"=` + exact + ` AND "value"=` + exact + ` AND "expiresAt"=?`
	args := []any{c.ID, id, c.Receipt, s.date(c.ExpiresAt)}
	if live {
		q += ` AND "expiresAt">?`
		args = append(args, s.date(time.Now()))
	}
	res, err := db.ExecContext(ctx, s.bind(q), args...)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	return affected == 1, err
}

func (s *Store) ReleaseWalletContact(ctx context.Context, c siwe.ContactClaim) error {
	_, err := s.deleteWalletClaim(ctx, s.db, c, false)
	return err
}

func (s *Store) FinishWalletContactLogin(ctx context.Context, in siwe.Login, session auth.StoredSession, c siwe.ContactClaim) (auth.User, error) {
	user, err := s.finishWalletLogin(ctx, in, session, &c)
	if !errors.Is(err, errContactCollision) {
		return user, err
	}
	// The failed transaction released every write. Read through a new transaction
	// so a concurrent registration is visible even under repeatable read.
	var occupied bool
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE LOWER("email")=?)`), c.Email).Scan(&occupied); err != nil {
		return auth.User{}, err
	}
	if !occupied {
		return auth.User{}, walletRegistrationConflict()
	}
	return s.finishWalletLogin(ctx, in, session, nil)
}

func walletRegistrationConflict() error {
	return &auth.APIError{Status: 409, Code: "WALLET_ACCOUNT_CONFLICT", Message: "Unable to register this wallet"}
}

func (s *Store) createWalletUser(ctx context.Context, tx *sql.Tx, in siwe.Login, now any, claim *siwe.ContactClaim) error {
	email := in.Email
	if claim != nil && claim.Address == in.Address {
		live, err := s.deleteWalletClaim(ctx, tx, *claim, true)
		if err != nil {
			return err
		}
		if live {
			// Include mixed-case addresses imported into case-sensitive databases.
			var occupied bool
			if err := tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" WHERE LOWER("email")=?)`), claim.Email).Scan(&occupied); err != nil {
				return err
			}
			if !occupied {
				email = claim.Email
			}
		}
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "user" ("id","name","email","emailVerified","image","createdAt","updatedAt") VALUES(?,?,?,?,?,?,?)`), in.CandidateID, in.Profile.Name, email, false, in.Profile.Avatar, now, now)
	if duplicateConstraint(err) {
		if email != in.Email {
			return errContactCollision
		}
		return walletRegistrationConflict()
	}
	return err
}
