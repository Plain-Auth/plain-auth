package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.BrowserAuthorizationStore = (*Store)(nil)

const browserClientSelect = "SELECT " + machineClientColumns + `,"scopes","redirectUris","requirePKCE","skipConsent","applicationType" FROM "oauthClient"` + localClientFilter

func scanBrowserClient(row rowScanner, id string) (op.BrowserClient, error) {
	var c op.BrowserClient
	var scopes, uris []byte
	var skip sql.NullBool
	var app sql.NullString
	m, err := scanMachineClient(row, id, &scopes, &uris, &c.RequirePKCE, &skip, &app)
	if err != nil {
		return c, err
	}
	c.RowID, c.ClientID, c.AuthMethod, c.ApplicationType = m.RowID, m.ClientID, m.AuthMethod, app.String
	c.GrantTypes, c.Disabled, c.SkipConsent, c.RequireDPoP = m.GrantTypes, m.Disabled, skip.Bool, m.RequireDPoP
	if scopes != nil {
		if err := json.Unmarshal(scopes, &c.Scopes); err != nil {
			return c, err
		}
	}
	if uris != nil {
		err = json.Unmarshal(uris, &c.RedirectURIs)
	}
	return c, err
}

func (s *Store) LookupAuthorizationClient(ctx context.Context, id string) (op.BrowserClient, error) {
	return scanBrowserClient(s.db.QueryRowContext(ctx, s.bind(browserClientSelect), id), id)
}

func (s *Store) IssueBrowserCode(ctx context.Context, input op.BrowserCodeIssue) error {
	return s.finishBrowserCode(ctx, input, nil, false)
}

func (s *Store) FinishBrowserConsent(ctx context.Context, input op.BrowserCodeIssue, prompt op.BrowserConsentPrompt, accept bool) error {
	return s.finishBrowserCode(ctx, input, &prompt, accept)
}

func (s *Store) finishBrowserCode(ctx context.Context, input op.BrowserCodeIssue, prompt *op.BrowserConsentPrompt, accept bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if prompt == nil || accept {
		client, err := scanBrowserClient(tx.QueryRowContext(ctx, s.readForUpdate(browserClientSelect), input.Client.ClientID), input.Client.ClientID)
		if err != nil {
			return err
		}
		if client.Disabled || !reflect.DeepEqual(client, input.Client) {
			return op.ErrBrowserClientChanged
		}
	}
	p := s.exactSQLValue("?")
	q := `SELECT "createdAt","expiresAt" FROM "session" WHERE "id"=` + p + ` AND "userId"=` + p + ` AND "token"=` + p
	if s.adminRole != "" {
		q += ` AND "impersonatedBy" IS NULL`
	}
	var created, expires time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(q), input.SessionID, input.UserID, input.SessionToken).Scan(&created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return op.ErrAuthorizationSessionExpired
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if !expires.After(now) || !input.SessionFresh(created, now) {
		return op.ErrAuthorizationSessionExpired
	}
	if prompt != nil {
		if err := s.consumeConsentPrompt(ctx, tx, *prompt, now); err != nil {
			return err
		}
		if !accept {
			return tx.Commit()
		}
	}
	if prompt != nil || !input.Client.SkipConsent {
		approval, err := s.findBrowserConsent(ctx, tx, input)
		switch {
		case err != nil && !errors.Is(err, auth.ErrNotFound):
			return err
		case prompt != nil:
			if err := s.writeBrowserConsent(ctx, tx, input, approval.ID, now); err != nil {
				return err
			}
		case errors.Is(err, auth.ErrNotFound):
			return op.ErrBrowserConsentRequired
		default:
			for _, scope := range input.Scopes {
				if !slices.Contains(approval.Scopes, scope) {
					return op.ErrBrowserConsentRequired
				}
			}
		}
	}
	// Existing foreign-issued codes can have arbitrary row IDs. Also avoid
	// reusing an identifier whose redeemed grant still has live descendants.
	exists := `SELECT EXISTS(SELECT 1 FROM "verification" WHERE "identifier"=` + p + `) OR EXISTS(SELECT 1 FROM "oauthAccessToken" WHERE "authorizationCodeId"=` + p + `) OR EXISTS(SELECT 1 FROM "oauthRefreshToken" WHERE "authorizationCodeId"=` + p + `)`
	var collision bool
	if err := tx.QueryRowContext(ctx, s.bind(exists), input.Identifier, input.Identifier, input.Identifier).Scan(&collision); err != nil {
		return err
	}
	if collision {
		return errors.New("sqlstore: authorization code identifier already exists")
	}
	now = time.Now().UTC()
	if !expires.After(now) || !input.SessionFresh(created, now) {
		return op.ErrAuthorizationSessionExpired
	}
	value, err := input.VerificationValue(created)
	if err != nil {
		return err
	}
	// A deterministic primary key serializes simultaneous inserts for the same
	// digest even if two different clients issued them on separate nodes.
	sum := sha256.Sum256([]byte("oauth-code/" + input.Identifier))
	id := hex.EncodeToString(sum[:16])
	start := now.Truncate(time.Second)
	const insert = `INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), id, input.Identifier, string(value), s.date(start), s.date(start), s.date(start.Add(input.Lifetime))); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) findBrowserConsent(ctx context.Context, tx *sql.Tx, input op.BrowserCodeIssue) (op.Consent, error) {
	p := s.exactSQLValue("?")
	query := consentSelect + ` WHERE "clientId"=` + p + ` AND "userId"=` + p
	args := []any{input.Client.ClientID, input.UserID}
	if input.ReferenceID != "" {
		query += ` AND "referenceId"=` + p + ` ORDER BY "id"`
		args = append(args, input.ReferenceID)
	} else {
		query += ` AND ("referenceId" IS NULL OR "referenceId"=` + p + `) ORDER BY CASE WHEN "referenceId" IS NULL THEN 0 ELSE 1 END,"id"`
		args = append(args, "")
	}
	return scanConsent(tx.QueryRowContext(ctx, s.readForUpdate(query+" LIMIT 1"), args...))
}
