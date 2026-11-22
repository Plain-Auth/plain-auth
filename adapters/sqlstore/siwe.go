package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"maps"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
)

var _ siwe.Store = (*Store)(nil)

func (s *Store) CheckWalletSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.walletSQL(`SELECT w."id",w."userId",w."address",w."chainId",w."isPrimary",w."createdAt" FROM "walletAddress" w WHERE 1=0`))
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

func (s *Store) walletMembership(ctx context.Context, db walletQueryer, address string, chain int64) (string, bool, error) {
	// Read both sides of the binding in a single snapshot. The account subject
	// remains canonical even when the wallet table and columns are renamed.
	wallets := s.mapWalletSQL(`SELECT "userId","address","chainId",0 FROM "walletAddress" WHERE LOWER("address")=?`)
	accounts := `SELECT "userId","accountId",0,1 FROM "account" WHERE "providerId"=` + s.exactSQLValue("?") + ` AND LOWER("accountId") LIKE ?`
	lower := strings.ToLower(address)
	rows, err := db.QueryContext(ctx, s.bind(wallets+" UNION ALL "+accounts), lower, "siwe", lower+":%")
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	var owner string
	links := map[int64]bool{}
	subjects := map[int64]bool{}
	for rows.Next() {
		var user, actual string
		var network int64
		var account bool
		if err := rows.Scan(&user, &actual, &network, &account); err != nil {
			return "", false, err
		}
		seen := links
		if account {
			var ok bool
			actual, network, ok = walletSubject(actual)
			if !ok {
				return "", false, errWalletLayout
			}
			seen = subjects
		}
		if !strings.EqualFold(actual, address) || user == "" || owner != "" && user != owner || network <= 0 || seen[network] {
			return "", false, errWalletLayout
		}
		owner = user
		seen[network] = true
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if !maps.Equal(links, subjects) {
		return "", false, errWalletLayout
	}
	return owner, links[chain], nil
}

// EOA subjects are address:chain. Contract subjects use their own namespace.
func walletSubject(subject string) (string, int64, bool) {
	address, chain, ok := strings.Cut(subject, ":")
	if !ok || len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return "", 0, false
	}
	if _, err := hex.DecodeString(address[2:]); err != nil {
		return "", 0, false
	}
	network, err := strconv.ParseInt(chain, 10, 32)
	return address, network, err == nil && network > 0 && strconv.FormatInt(network, 10) == chain
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
			if _, err = tx.ExecContext(ctx, s.walletSQL(`INSERT INTO "walletAddress" ("id","userId","address","chainId","isPrimary","createdAt") VALUES(?,?,?,?,?,?)`), rand.Text(), in.CandidateID, in.Address, in.ChainID, owner == "", now); err != nil {
				return nil, err
			}
		}
		if !matched {
			id := rand.Text()
			if in.Contract {
				id = walletLock("contract", acct).digest[:36]
			}
			if err = s.insertAccount(ctx, tx, `"id","providerId","accountId","userId","createdAt","updatedAt"`, "?,'siwe',?,?,?,?", []any{id, acct, in.CandidateID, now, now}, nil); err != nil {
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

func (s *Store) unlinkWallet(ctx context.Context, tx *sql.Tx, userID, accountID string) error {
	var wallet string
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "accountId" FROM "account" WHERE "id"=? AND "userId"=? AND "providerId"='siwe'`), accountID, userID).Scan(&wallet)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	address, id, ok := walletSubject(wallet)
	if !ok {
		return nil
	}
	owner, matched, err := s.walletMembership(ctx, tx, address, id)
	if err != nil {
		return err
	}
	if owner != userID || !matched {
		return errWalletLayout
	}
	if _, err := tx.ExecContext(ctx, s.walletSQL(`DELETE FROM "walletAddress" WHERE "userId"=? AND lower("address")=? AND "chainId"=?`), userID, strings.ToLower(address), id); err != nil {
		return err
	}
	var primary string
	err = tx.QueryRowContext(ctx, s.walletSQL(`SELECT "id" FROM "walletAddress" WHERE "userId"=? ORDER BY "isPrimary" DESC,"createdAt","id" LIMIT 1`), userID).Scan(&primary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.walletSQL(`UPDATE "walletAddress" SET "isPrimary"=? WHERE "id"=? AND "userId"=?`), true, primary, userID)
	return err
}

func (s *Store) deleteOwnerWalletAddresses(ctx context.Context, tx *sql.Tx, userID string) error {
	// A core-only node may be using a different wallet layout. Validate each
	// established EOA against this layout before deleting its shared account row.
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "accountId" FROM "account" WHERE "providerId"='siwe' AND "userId"=`+s.exactSQLValue("?")), userID)
	if err != nil {
		return err
	}
	addresses := map[string]bool{}
	for rows.Next() {
		var subject string
		if err := rows.Scan(&subject); err != nil {
			rows.Close()
			return err
		}
		if address, _, ok := walletSubject(subject); ok {
			addresses[address] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for address := range addresses {
		owner, _, err := s.walletMembership(ctx, tx, address, 0)
		if err != nil {
			return err
		}
		if owner != userID {
			return errWalletLayout
		}
	}
	exists, err := s.tableExists(ctx, tx, s.walletNames().Table)
	if err != nil || !exists {
		return err
	}
	_, err = tx.ExecContext(ctx, s.walletSQL(`DELETE FROM "walletAddress" WHERE "userId"=`+s.exactSQLValue("?")), userID)
	return err
}
