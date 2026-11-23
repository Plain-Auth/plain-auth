package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

var _ auth.JWTStore = (*Store)(nil)

// CheckJWKS validates the selected optional schema before serving requests.
func (s *Store) CheckJWKS() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT k."id",k."publicKey",k."privateKey",k."createdAt",k."expiresAt",k."alg",k."crv" FROM "jwks" k WHERE 1=0`))
	if err != nil {
		return errors.New("jwt: install the jwt schema profile before enabling the plugin")
	}
	return rows.Close()
}

func (s *Store) PublicJWTKeys(ctx context.Context, cutoff time.Time) ([]auth.PublicJWTKey, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "id","publicKey","alg","crv","createdAt","expiresAt" FROM "jwks" WHERE "expiresAt" IS NULL OR "expiresAt">? ORDER BY "createdAt","id"`), s.date(cutoff))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auth.PublicJWTKey{}
	for rows.Next() {
		var row auth.PublicJWTKey
		var alg, curve sql.NullString
		if err = rows.Scan(&row.ID, &row.PublicKey, &alg, &curve, &row.CreatedAt, &row.ExpiresAt); err != nil {
			return nil, err
		}
		row.Algorithm, row.Curve = alg.String, curve.String
		out = append(out, row)
	}
	return out, rows.Err()
}
func (s *Store) readSigningKey(ctx context.Context, db rowQuerier, alg string, now time.Time) (auth.StoredJWTKey, error) {
	var row auth.StoredJWTKey
	var curve sql.NullString
	err := db.QueryRowContext(ctx, s.bind(`SELECT "id","publicKey","privateKey","crv","createdAt","expiresAt" FROM "jwks" WHERE "alg"=? AND ("expiresAt" IS NULL OR "expiresAt">?) ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`), alg, s.date(now)).Scan(&row.ID, &row.PublicKey, &row.EncryptedPrivateKey, &curve, &row.CreatedAt, &row.ExpiresAt)
	row.Algorithm, row.Curve = alg, curve.String
	return row, err
}

// ActiveJWTKey serializes only bootstrap and rotation. The common signing
// path reads an existing live key on any pooled connection.
func (s *Store) ActiveJWTKey(ctx context.Context, alg string, now time.Time, generate func() (auth.StoredJWTKey, error)) (auth.StoredJWTKey, error) {
	row, err := s.readSigningKey(ctx, s.db, alg, now)
	if !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	const lockName = "CONCAT('authn/jwks/',MD5(DATABASE()))"
	tx, end, err := s.beginTransactionWithMySQLLock(ctx, nil, lockName, 15, errors.New("jwt: signing key lock unavailable"))
	if err != nil {
		return row, err
	}
	defer end.rollback()
	// SQLite begins an immediate transaction. PostgreSQL locks only during
	// cold key generation, including an initially empty key table.
	if s.dialect == "postgres" {
		if _, err = tx.ExecContext(ctx, `LOCK TABLE "jwks" IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return row, err
		}
	}
	row, err = s.readSigningKey(ctx, tx, alg, now)
	if err == nil {
		return row, end.commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	row, err = generate()
	if err != nil {
		return row, err
	}
	var expires any
	if row.ExpiresAt != nil {
		expires = s.date(*row.ExpiresAt)
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "jwks" ("id","publicKey","privateKey","alg","crv","createdAt","expiresAt") VALUES (?,?,?,?,?,?,?)`), row.ID, row.PublicKey, row.EncryptedPrivateKey, row.Algorithm, row.Curve, s.date(row.CreatedAt), expires)
	if err != nil {
		return row, err
	}
	return row, end.commit()
}

// JWTKeyByID resolves an explicit signing key and never generates a replacement.
func (s *Store) JWTKeyByID(ctx context.Context, id string) (auth.StoredJWTKey, error) {
	var row auth.StoredJWTKey
	var curve sql.NullString
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","publicKey","privateKey","alg","crv","createdAt","expiresAt" FROM "jwks" WHERE "id"=?`), id).Scan(&row.ID, &row.PublicKey, &row.EncryptedPrivateKey, &row.Algorithm, &curve, &row.CreatedAt, &row.ExpiresAt)
	row.Curve = curve.String
	return row, err
}
