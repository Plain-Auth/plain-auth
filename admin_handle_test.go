package frostauth

import (
	"strings"
	"testing"
	"time"
)

type listedAdminSession struct {
	AdminTransaction
	row                         Session
	revokedUser, revokedSession string
}

func (s *listedAdminSession) UserSessions(string) ([]Session, error) {
	return []Session{s.row}, nil
}

func (s *listedAdminSession) RevokeListedSession(user, session string) error {
	s.revokedUser, s.revokedSession = user, session
	return nil
}

func TestAdministrativeRevocationHandleLifetimeAndKeyRotation(t *testing.T) {
	now := time.Now().UTC()
	expiry := now.Add(time.Hour)
	previous := VersionedSecret{Version: 11, Value: strings.Repeat("p", 32)}
	current := VersionedSecret{Version: 12, Value: strings.Repeat("c", 32)}
	a := &Auth{opts: Options{Secrets: []VersionedSecret{previous}}}
	store := &listedAdminSession{row: Session{ID: "row", UserID: "owner", Token: "private-session-credential", ExpiresAt: expiry}}
	rows, err := a.listAdminSessions(store, "operator", "owner")
	if err != nil {
		t.Fatal(err)
	}
	handle := rows[0].Token
	payload, err := a.openRecord("admin-session-revoke:operator", strings.TrimPrefix(handle, adminHandlePrefix))
	if err != nil || strings.Contains(string(payload), store.row.Token) {
		t.Fatal("revocation handle contains a login credential", err)
	}
	a.opts.Secrets = []VersionedSecret{current, previous}
	if err := a.revokeAdminSession(store, "operator", handle, now); err != nil || store.revokedUser != "owner" || store.revokedSession != "row" {
		t.Fatal("rotated key failed to revoke the selected session", err)
	}
	store.revokedSession = ""
	if err := a.revokeAdminSession(store, "operator", handle, expiry); err == nil || store.revokedSession != "" {
		t.Fatal("expired handle reached the database")
	}
	a.opts.Secrets = []VersionedSecret{current}
	if err := a.revokeAdminSession(store, "operator", handle, now); err == nil || store.revokedSession != "" {
		t.Fatal("retired encryption key still authorized revocation")
	}
}
