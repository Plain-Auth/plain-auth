package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/scim"
)

var _ scim.ManagedStore = (*Store)(nil)

const managedConnCols = `"id","revision","creationRequestId","connectionId","provisioningDomainId","status","createdAt","createdBy","decommissionStartedAt","decommissionStartedBy","decommissionedAt","decommissionedBy"`
const managedCredCols = `"credentialId","status","serializedScopes","expiresAt","createdAt","createdBy","lastUsedAt","revokedAt","revokedBy"`

type catalogConnection struct {
	scim.ManagedConnection
	id       string
	revision int
}

func scanManagedConn(r rowScanner) (c catalogConnection, e error) {
	e = r.Scan(&c.id, &c.revision, &c.CreationRequestID, &c.ConnectionID, &c.ProvisioningDomainID, &c.Status, &c.CreatedAt, &c.CreatedBy, &c.DecommissionStartedAt, &c.DecommissionStartedBy, &c.DecommissionedAt, &c.DecommissionedBy)
	return
}
func managedScopes(raw string) ([]string, error) {
	var scopes []string
	if e := json.Unmarshal([]byte(raw), &scopes); e != nil {
		return nil, e
	}
	if len(scopes) == 0 || len(scopes) > 4 {
		return nil, errors.New("sqlstore: invalid directory credential scopes")
	}
	for i, s := range scopes {
		if slices.Contains(scopes[:i], s) || !slices.Contains([]string{scim.UsersRead, scim.UsersWrite, scim.GroupsRead, scim.GroupsWrite}, s) {
			return nil, errors.New("sqlstore: invalid directory credential scopes")
		}
	}
	return scopes, nil
}
func scanManagedCred(r rowScanner, now time.Time) (c scim.ManagedCredential, e error) {
	var raw string
	e = r.Scan(&c.CredentialID, &c.Status, &raw, &c.ExpiresAt, &c.CreatedAt, &c.CreatedBy, &c.LastUsedAt, &c.RevokedAt, &c.RevokedBy)
	if e == nil {
		c.Scopes, e = managedScopes(raw)
		if c.Status == "active" && !c.ExpiresAt.After(now) {
			c.Status = "expired"
		}
	}
	return
}
func (s *Store) managedConn(ctx context.Context, tx *sql.Tx, d scim.Directory, lock bool) (catalogConnection, error) {
	q := `SELECT ` + managedConnCols + ` FROM "scimManagedConnection" WHERE ` + s.scimScope()
	sqlQuery := s.bind(q)
	if lock {
		sqlQuery = s.readForUpdate(q)
	}
	c, e := scanManagedConn(tx.QueryRowContext(ctx, sqlQuery, d.ID, d.ProvisioningDomainID))
	if errors.Is(e, sql.ErrNoRows) {
		e = scim.ErrManagedNotFound
	}
	return c, e
}
func (s *Store) managedEvent(ctx context.Context, tx *sql.Tx, record string, seq int, typ, actor string, credential any, now time.Time) error {
	_, e := tx.ExecContext(ctx, s.bind(`INSERT INTO "scimManagedConnectionEvent" ("id","connectionRecordId","eventKey","sequence","type","actorId","credentialId","createdAt") VALUES (?,?,?,?,?,?,?,?)`), rand.Text(), record, record+":"+strconv.Itoa(seq), seq, typ, actor, credential, s.date(now))
	return e
}
func (s *Store) managedState(ctx context.Context, tx *sql.Tx, c catalogConnection) (scim.ManagedState, error) {
	out := scim.ManagedState{Connection: c.ManagedConnection, Credentials: []scim.ManagedCredential{}}
	rows, e := tx.QueryContext(ctx, s.bind(`SELECT `+managedCredCols+` FROM "scimManagedCredential" WHERE "connectionRecordId"=? ORDER BY "createdAt" DESC,"id" DESC`), c.id)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		cred, e := scanManagedCred(rows, now)
		if e != nil {
			return out, e
		}
		out.Credentials = append(out.Credentials, cred)
	}
	return out, rows.Err()
}
func (s *Store) SCIMManagedConnections(ctx context.Context, domain string) ([]scim.ManagedConnection, error) {
	rows, e := s.db.QueryContext(ctx, s.bind(`SELECT `+managedConnCols+` FROM "scimManagedConnection" WHERE `+s.scimExact(`"provisioningDomainId"`)+`=? ORDER BY "createdAt" DESC,"id" DESC`), domain)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []scim.ManagedConnection{}
	for rows.Next() {
		c, e := scanManagedConn(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, c.ManagedConnection)
	}
	return out, rows.Err()
}
func (s *Store) SCIMManagedState(ctx context.Context, d scim.Directory) (scim.ManagedState, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return scim.ManagedState{}, e
	}
	defer tx.Rollback()
	c, e := s.managedConn(ctx, tx, d, true)
	if e != nil {
		return scim.ManagedState{}, e
	}
	return s.managedState(ctx, tx, c)
}
func (s *Store) SCIMManagedEvents(ctx context.Context, d scim.Directory, q scim.EventQuery) (scim.ManagedEvents, error) {
	out := scim.ManagedEvents{Limit: q.Limit, Offset: q.Offset, Events: []scim.ManagedEvent{}}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	c, e := s.managedConn(ctx, tx, d, true)
	if e != nil {
		return out, e
	}
	if e = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "scimManagedConnectionEvent" WHERE "connectionRecordId"=?`), c.id).Scan(&out.Total); e != nil {
		return out, e
	}
	order := "DESC"
	if q.SortDirection == "asc" {
		order = "ASC"
	}
	rows, e := tx.QueryContext(ctx, s.bind(`SELECT "sequence","type","actorId","credentialId","createdAt" FROM "scimManagedConnectionEvent" WHERE "connectionRecordId"=? ORDER BY "sequence" `+order+` LIMIT ? OFFSET ?`), c.id, q.Limit, q.Offset)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var ev scim.ManagedEvent
		if e = rows.Scan(&ev.Sequence, &ev.Type, &ev.ActorID, &ev.CredentialID, &ev.CreatedAt); e != nil {
			return out, e
		}
		out.Events = append(out.Events, ev)
	}
	if q.SortDirection == "" {
		slices.Reverse(out.Events)
	}
	return out, rows.Err()
}
func (s *Store) managedSlot(ctx context.Context, tx *sql.Tx, record string, limit int, now time.Time) (string, error) {
	rows, e := tx.QueryContext(ctx, s.readForUpdate(`SELECT "credentialId","activeSlotKey","expiresAt" FROM "scimManagedCredential" WHERE "connectionRecordId"=? AND "status"='active'`), record)
	if e != nil {
		return "", e
	}
	slots := map[string]bool{}
	var expired []string
	for rows.Next() {
		var id, slot string
		var expiry time.Time
		if e = rows.Scan(&id, &slot, &expiry); e != nil {
			rows.Close()
			return "", e
		}
		if !expiry.After(now) {
			expired = append(expired, id)
		} else {
			slots[slot] = true
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return "", e
	}
	for _, id := range expired {
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedCredential" SET "status"='expired',"activeSlotKey"=? WHERE "credentialId"=? AND "connectionRecordId"=? AND "status"='active'`), id+":inactive", id, record)
		if e != nil {
			return "", e
		}
	}
	if len(slots) >= limit {
		return "", scim.ErrManagedConflict
	}
	for i := 0; i < limit; i++ {
		key := fmt.Sprintf("%s:active:%d", record, i)
		if !slots[key] {
			return key, nil
		}
	}
	return "", scim.ErrManagedConflict
}
func (s *Store) SCIMIssueCredential(ctx context.Context, i scim.ManagedIssue) (connection scim.ManagedConnection, credential scim.ManagedCredential, err error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return connection, credential, e
	}
	defer tx.Rollback()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if !i.ExpiresAt.After(now) {
		return connection, credential, scim.ErrManagedConflict
	}
	var record, slot string
	var seq int
	kind := "credential.issued"
	if i.CreationRequestID != "" {
		record = rand.Text()
		seq = 2
		slot = record + ":active:0"
		_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimManagedConnection" ("id","creationRequestId","connectionId","provisioningDomainId","status","revision","createdAt","createdBy") VALUES (?,?,?,?,'active',2,?,?)`), record, i.CreationRequestID, i.ID, i.ProvisioningDomainID, s.date(i.CreatedAt), i.ActorID)
		if duplicateConstraint(e) {
			return connection, credential, scim.ErrCreationRequestConflict
		}
		if e != nil {
			return connection, credential, e
		}
		if e = s.managedEvent(ctx, tx, record, 1, "connection.created", i.ActorID, nil, i.CreatedAt); e != nil {
			return connection, credential, e
		}
		connection = scim.ManagedConnection{ConnectionID: i.ID, ProvisioningDomainID: i.ProvisioningDomainID, CreationRequestID: i.CreationRequestID, Status: "active", CreatedAt: i.CreatedAt, CreatedBy: i.ActorID}
	} else {
		c, e := s.managedConn(ctx, tx, i.Directory, true)
		if e != nil {
			return connection, credential, e
		}
		if c.Status != "active" {
			return connection, credential, scim.ErrManagedConflict
		}
		now = time.Now().UTC().Truncate(time.Millisecond)
		if !i.ExpiresAt.After(now) {
			return connection, credential, scim.ErrManagedConflict
		}
		connection = c.ManagedConnection
		record = c.id
		slot, e = s.managedSlot(ctx, tx, record, i.MaxActive, now)
		if e != nil {
			return connection, credential, e
		}
		seq = c.revision + 1
		kind = "credential.rotated"
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedConnection" SET "revision"=? WHERE "id"=?`), seq, record)
		if e != nil {
			return connection, credential, e
		}
	}
	scopeJSON, e := json.Marshal(i.Scopes)
	if e != nil {
		return connection, credential, e
	}
	_, e = tx.ExecContext(ctx, s.bind(`INSERT INTO "scimManagedCredential" ("id","connectionRecordId","credentialId","tokenDigest","hashVersion","activeSlotKey","status","serializedScopes","expiresAt","createdAt","createdBy") VALUES (?,?,?,?,'v1',?,'active',?,?,?,?)`), rand.Text(), record, i.CredentialID, i.TokenDigest, slot, string(scopeJSON), s.date(i.ExpiresAt), s.date(i.CreatedAt), i.ActorID)
	if e != nil {
		return connection, credential, e
	}
	if e = s.managedEvent(ctx, tx, record, seq, kind, i.ActorID, i.CredentialID, i.CreatedAt); e != nil {
		return connection, credential, e
	}
	credential = scim.ManagedCredential{CredentialID: i.CredentialID, CreatedBy: i.ActorID, CreatedAt: i.CreatedAt, Status: "active", Scopes: i.Scopes, ExpiresAt: i.ExpiresAt}
	return connection, credential, tx.Commit()
}
func (s *Store) SCIMRevokeCredential(ctx context.Context, d scim.Directory, id, actor string) (scim.ManagedState, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return scim.ManagedState{}, e
	}
	defer tx.Rollback()
	c, e := s.managedConn(ctx, tx, d, true)
	if e != nil {
		return scim.ManagedState{}, e
	}
	var status string
	e = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "status" FROM "scimManagedCredential" WHERE "connectionRecordId"=? AND `+s.scimExact(`"credentialId"`)+`=?`), c.id, id).Scan(&status)
	if errors.Is(e, sql.ErrNoRows) {
		e = scim.ErrManagedNotFound
	}
	if e != nil {
		return scim.ManagedState{}, e
	}
	if status != "revoked" {
		if c.Status != "active" || status != "active" {
			return scim.ManagedState{}, scim.ErrManagedConflict
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedCredential" SET "status"='revoked',"activeSlotKey"=?,"revokedAt"=?,"revokedBy"=? WHERE "connectionRecordId"=? AND "credentialId"=?`), id+":inactive", s.date(now), actor, c.id, id)
		if e != nil {
			return scim.ManagedState{}, e
		}
		c.revision++
		_, e = tx.ExecContext(ctx, s.bind(`UPDATE "scimManagedConnection" SET "revision"=? WHERE "id"=?`), c.revision, c.id)
		if e != nil {
			return scim.ManagedState{}, e
		}
		if e = s.managedEvent(ctx, tx, c.id, c.revision, "credential.revoked", actor, id, now); e != nil {
			return scim.ManagedState{}, e
		}
	}
	out, e := s.managedState(ctx, tx, c)
	if e != nil {
		return scim.ManagedState{}, e
	}
	return out, tx.Commit()
}

const managedPrincipalJoin = ` FROM "scimManagedCredential" k JOIN "scimManagedConnection" c ON k."connectionRecordId"=c."id" WHERE k."status"='active' AND c."status"='active' AND k."hashVersion"='v1' AND `

func (s *Store) SCIMVerifyCredential(ctx context.Context, id, digest string, interval time.Duration) (*scim.Principal, error) {
	p := scim.Principal{Kind: "managed-bearer", CredentialID: id}
	var saved, scopes string
	var last sql.NullTime
	now := time.Now().UTC().Truncate(time.Millisecond)
	e := s.db.QueryRowContext(ctx, s.bind(`SELECT c."connectionId",c."provisioningDomainId",k."tokenDigest",k."serializedScopes",k."expiresAt",k."lastUsedAt"`+managedPrincipalJoin+s.scimExact(`k."credentialId"`)+`=?`), id).Scan(&p.ID, &p.ProvisioningDomainID, &saved, &scopes, &p.ExpiresAt, &last)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if subtle.ConstantTimeCompare([]byte(saved), []byte(digest)) != 1 || !p.ExpiresAt.After(now) {
		return nil, nil
	}
	p.Scopes, e = managedScopes(scopes)
	if e != nil {
		return nil, e
	}
	if !last.Valid || !last.Time.Add(interval).After(now) {
		_, _ = s.db.ExecContext(ctx, s.bind(`UPDATE "scimManagedCredential" SET "lastUsedAt"=? WHERE "credentialId"=? AND "status"='active' AND ("lastUsedAt" IS NULL OR "lastUsedAt"<=?)`), s.date(now), id, s.date(now.Add(-interval)))
	}
	return &p, nil
}

// Recheck the credential with the connection and credential locked before a
// directory operation. A revocation that committed after initial verification
// therefore cannot authorize a later resource mutation.
func (s *Store) lockManagedPrincipal(ctx context.Context, tx *sql.Tx, d scim.Directory, p scim.Principal) error {
	denied := &scim.Error{Status: 401, Detail: "Invalid SCIM bearer token"}
	c, e := s.managedConn(ctx, tx, d, true)
	if errors.Is(e, scim.ErrManagedNotFound) {
		return denied
	}
	if e != nil {
		return e
	}
	if c.Status != "active" {
		return denied
	}
	var raw string
	var expires time.Time
	e = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "serializedScopes","expiresAt" FROM "scimManagedCredential" WHERE "connectionRecordId"=? AND "credentialId"=? AND "hashVersion"='v1' AND "status"='active'`), c.id, p.CredentialID).Scan(&raw, &expires)
	if errors.Is(e, sql.ErrNoRows) {
		return denied
	}
	if e != nil {
		return e
	}
	if !expires.After(time.Now()) {
		return denied
	}
	scopes, e := managedScopes(raw)
	if e != nil {
		return e
	}
	if !slices.Equal(scopes, p.Scopes) {
		return denied
	}
	return nil
}
