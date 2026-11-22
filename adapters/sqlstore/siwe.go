package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
)

var _ siwe.Store = (*Store)(nil)

func (s *Store) CheckWalletSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT w."id",w."userId",w."address",w."chainId",w."isPrimary",w."createdAt" FROM "walletAddress" w WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}

func walletLock(purpose, id string) emailOTPKey {
	sum := sha256.Sum256([]byte("siwe:" + purpose + ":" + id))
	digest := hex.EncodeToString(sum[:])
	return emailOTPKey{owner: "siwe:" + purpose + ":" + digest, digest: digest}
}

func (s *Store) SaveWalletNonce(ctx context.Context, nonce string, now, expires time.Time) error {
	return s.saveWalletNonce(ctx, nonce, now, expires, false)
}

func (s *Store) saveWalletNonce(ctx context.Context, nonce string, now, expires time.Time, custom bool) error {
	id := walletLock("nonce", nonce).digest[:36]
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	history := custom
	if !history {
		history, err = s.hasKeyOwnerTable(ctx, tx, "plainauth_siwe_nonce_digest")
		if err != nil {
			return err
		}
	}
	if history {
		digest := sha256.Sum256([]byte(nonce))
		if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "plainauth_siwe_nonce_digest" ("digest") VALUES (?)`), digest[:]); err != nil {
			if duplicateConstraint(err) {
				return &auth.APIError{Status: 500, Code: "SIWE_INVALID_NONCE", Message: "The nonce generator repeated a previous challenge"}
			}
			return err
		}
		var live bool
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS (SELECT 1 FROM "verification" WHERE "identifier"=?)`), "siwe:"+nonce).Scan(&live); err != nil {
			return err
		}
		if live {
			// Retain this discovered legacy value even after its live row is consumed.
			if err := tx.Commit(); err != nil {
				return err
			}
			return &auth.APIError{Status: 500, Code: "SIWE_INVALID_NONCE", Message: "The nonce generator repeated a previous challenge"}
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE 'siwe:%' AND "expiresAt"<=?`), s.date(now)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, "siwe:"+nonce, nonce, s.date(expires), s.date(now), s.date(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TakeWalletNonce(ctx context.Context, nonce string, now time.Time) (bool, error) {
	deadline, err := s.TakeTimedWalletNonce(ctx, nonce, now)
	return !deadline.IsZero(), err
}

func (s *Store) TakeTimedWalletNonce(ctx context.Context, nonce string, now time.Time) (time.Time, error) {
	var taken time.Time
	err := s.emailOTPTransaction(ctx, walletLock("nonce", nonce), func(tx *sql.Tx) (error, error) {
		taken = time.Time{}
		rows, err := tx.QueryContext(ctx, s.readForUpdate(`SELECT "id","identifier","value","expiresAt" FROM "verification" WHERE "identifier"=? AND "expiresAt">?`), "siwe:"+nonce, s.date(now))
		if err != nil {
			return nil, err
		}
		var ids []string
		var expiry time.Time
		for rows.Next() {
			var id, identifier, value string
			var end time.Time
			if err := rows.Scan(&id, &identifier, &value, &end); err != nil {
				rows.Close()
				return nil, err
			}
			// Verify byte equality even on case-insensitive database collations.
			if identifier == "siwe:"+nonce && value == nonce {
				ids = append(ids, id)
				expiry = end
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), id)
			if err != nil {
				return nil, err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return nil, err
			}
			if len(ids) == 1 && n == 1 {
				taken = expiry
			}
		}
		return nil, nil
	})
	return taken, err
}

type walletQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) walletMembership(ctx context.Context, db walletQueryer, address string, chain int64) (owner string, matched bool, err error) {
	rows, err := db.QueryContext(ctx, s.bind(`SELECT "userId","address","chainId" FROM "walletAddress" WHERE LOWER("address")=?`), strings.ToLower(address))
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var user, actual string
		var network int64
		if err := rows.Scan(&user, &actual, &network); err != nil {
			return "", false, err
		}
		if !strings.EqualFold(address, actual) || user == "" || owner != "" && owner != user || network == chain && matched {
			return "", false, errors.New("siwe: ambiguous wallet ownership")
		}
		owner = user
		if network == chain {
			matched = true
		}
	}
	return owner, matched, rows.Err()
}

func (s *Store) WalletOwner(ctx context.Context, address string) (string, error) {
	owner, _, err := s.walletMembership(ctx, s.db, address, 0)
	return owner, err
}

// The public account schema permits duplicate provider subjects. Read every
// matching record and refuse ambiguous or collation-equivalent imported data.
func (s *Store) walletAccountOwner(ctx context.Context, db walletQueryer, subject string, contract bool) (string, error) {
	rows, err := db.QueryContext(ctx, s.bind(`SELECT "id","providerId","accountId","userId" FROM "account" WHERE "providerId"='siwe' AND "accountId"=?`), subject)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var owner string
	for rows.Next() {
		var id, provider, account, user string
		if err := rows.Scan(&id, &provider, &account, &user); err != nil {
			return "", err
		}
		if owner != "" || user == "" || provider != "siwe" || account != subject || contract && id != walletLock("contract", subject).digest[:36] {
			return "", errors.New("siwe: ambiguous wallet account binding")
		}
		owner = user
	}
	return owner, rows.Err()
}

func contractSubject(address string, chain int64) string {
	return "contract:" + strconv.FormatInt(chain, 10) + ":" + address
}

func (s *Store) ContractWalletOwner(ctx context.Context, address string, chain int64) (string, error) {
	return s.walletAccountOwner(ctx, s.db, contractSubject(address, chain), true)
}

func (s *Store) FinishWalletLogin(ctx context.Context, in siwe.Login, session auth.StoredSession) (auth.User, error) {
	return s.finishWalletLogin(ctx, in, session, nil)
}

func (s *Store) finishWalletLogin(ctx context.Context, in siwe.Login, session auth.StoredSession, claim *siwe.ContactClaim) (auth.User, error) {
	var user auth.User
	if in.Profile.Name == "" {
		in.Profile.Name = in.Address
	}
	if session.UserID == "" || session.UserID != in.CandidateID {
		return user, auth.ErrNotFound
	}
	err := s.emailOTPTransaction(ctx, walletLock("wallet", strings.ToLower(in.Address)), func(tx *sql.Tx) (error, error) {
		if in.Existing {
			if _, err := s.lockAllowedAccount(ctx, tx, in.CandidateID, session.CreatedAt); err != nil {
				return nil, err
			}
		}
		acct := in.Address + ":" + strconv.FormatInt(in.ChainID, 10)
		if in.Contract {
			acct = contractSubject(in.Address, in.ChainID)
		}
		owner, err := s.walletAccountOwner(ctx, tx, acct, in.Contract)
		if err != nil {
			return nil, err
		}
		matched := owner != ""
		if !in.Contract {
			walletOwner, hasChain, err := s.walletMembership(ctx, tx, in.Address, in.ChainID)
			if err != nil {
				return nil, err
			}
			if matched != hasChain || matched && owner != walletOwner {
				return nil, errors.New("siwe: inconsistent wallet account binding")
			}
			owner = walletOwner
		}
		if owner != "" && owner != in.CandidateID || owner == "" && in.Existing {
			return siwe.ErrOwnerChanged, nil
		}
		now := s.date(session.CreatedAt)
		if owner == "" {
			if !in.AllowSignUp {
				return &auth.APIError{Status: 403, Code: "SIGN_UP_DISABLED", Message: "Sign up is disabled"}, nil
			}
			if err := s.createWalletUser(ctx, tx, in, now, claim); err != nil {
				return nil, err
			}
		}
		if !matched && !in.Contract {
			if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "walletAddress" ("id","userId","address","chainId","isPrimary","createdAt") VALUES(?,?,?,?,?,?)`), rand.Text(), in.CandidateID, in.Address, in.ChainID, owner == "", now); err != nil {
				return nil, err
			}
		}
		if !matched {
			id := rand.Text()
			if in.Contract {
				id = walletLock("contract", acct).digest[:36]
			}
			if _, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES(?,'siwe',?,?,?,?)`), id, acct, in.CandidateID, now, now); err != nil {
				return nil, err
			}
		}
		if !in.ValidUntil.IsZero() && !time.Now().Before(in.ValidUntil) {
			return nil, &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Wallet verification expired"}
		}
		if err = s.insertSession(ctx, tx, session); err != nil {
			return nil, err
		}
		err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), in.CandidateID).Scan(userFields(&user)...)
		return nil, err
	})
	return user, err
}

func (s *Store) walletTable(ctx context.Context, tx *sql.Tx) (bool, error) {
	var q string
	switch s.dialect {
	case "sqlite":
		q = `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='walletAddress' COLLATE NOCASE)`
	case "postgres":
		q = `SELECT pg_catalog.to_regclass('"walletAddress"') IS NOT NULL`
	case "mysql":
		q = `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=database() AND table_name='walletAddress'
            AND (@@lower_case_table_names<>0 OR (BINARY table_schema=BINARY DATABASE() AND BINARY table_name=BINARY 'walletAddress')))`
	}
	var exists bool
	err := tx.QueryRowContext(ctx, q).Scan(&exists)
	return exists, err
}

func (s *Store) unlinkWallet(ctx context.Context, tx *sql.Tx, userID, accountID string) error {
	var wallet string
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "accountId" FROM "account" WHERE "id"=? AND "userId"=? AND "providerId"='siwe'`), accountID, userID).Scan(&wallet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	address, chain, ok := strings.Cut(wallet, ":")
	id, err := strconv.ParseInt(chain, 10, 64)
	if !ok || err != nil || id <= 0 || len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return nil
	}
	exists, err := s.walletTable(ctx, tx)
	if err != nil || !exists {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "walletAddress" WHERE "userId"=? AND lower("address")=? AND "chainId"=?`), userID, strings.ToLower(address), id); err != nil {
		return err
	}
	var primary string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "id" FROM "walletAddress" WHERE "userId"=? ORDER BY "isPrimary" DESC,"createdAt","id" LIMIT 1`), userID).Scan(&primary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "walletAddress" SET "isPrimary"=? WHERE "id"=? AND "userId"=?`), true, primary, userID)
	return err
}

func (s *Store) cleanupWallets(ctx context.Context, tx *sql.Tx, userID string) error {
	if s.dialect != "mysql" {
		return nil
	}
	return s.deleteOwnerWalletAddresses(ctx, tx, userID)
}

func (s *Store) deleteOwnerWalletAddresses(ctx context.Context, tx *sql.Tx, userID string) error {
	exists, err := s.walletTable(ctx, tx)
	if err != nil || !exists {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "walletAddress" WHERE "userId"=`+s.exactSQLValue("?")), userID)
	return err
}
