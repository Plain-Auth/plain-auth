package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sync"

	authn "github.com/Plain-Org/plain-auth"
)

var _ authn.SessionEndReporter = (*Store)(nil)

// sessionEndReports holds the receivers a host attached and the sessions
// each open transaction has ended so far. Every copy of a Store shares one.
type sessionEndReports struct {
	mu        sync.Mutex
	receivers []func(context.Context, []authn.EndedSession)
	open      map[*sql.Tx]*sessionEnds
}

// ReportSessionEnds attaches report to every session this store ends, on
// every path, replacing the report attached before, so a second New on the
// same store does not report twice. The store calls it once per committed
// transaction that ended sessions, after the commit and outside the
// transaction, with the context the transaction began with. Rolled-back
// transactions report nothing.
func (s *Store) ReportSessionEnds(report func(context.Context, []authn.EndedSession)) {
	if s.ends == nil || report == nil {
		return
	}
	s.ends.mu.Lock()
	defer s.ends.mu.Unlock()
	s.ends.receivers = []func(context.Context, []authn.EndedSession){report}
}

// strictSessionEnds makes every untracked session end an error, receivers
// or not; without it only a store with a receiver refuses one. The package
// tests set it, so the whole suite checks that each transaction able to
// end a session is tracked.
var strictSessionEnds bool

// sessionEnds collects the sessions one transaction ends.
type sessionEnds struct {
	reports   *sessionEndReports
	ctx       context.Context
	tx        *sql.Tx
	tracked   bool
	receivers []func(context.Context, []authn.EndedSession)
	sessions  []authn.EndedSession
}

// trackSessionEnds starts collecting the sessions tx ends. Owners of a
// transaction that can end sessions call it after BeginTx, defer close and
// commit through it, so the report follows the commit.
func (s *Store) trackSessionEnds(ctx context.Context, tx *sql.Tx) *sessionEnds {
	e := &sessionEnds{reports: s.ends, ctx: ctx, tx: tx}
	if s.ends == nil {
		return e
	}
	// Every transaction is registered, so one that began before the first
	// receiver was attached is known and simply reports nothing.
	s.ends.mu.Lock()
	defer s.ends.mu.Unlock()
	e.tracked = true
	e.receivers = slices.Clone(s.ends.receivers)
	if s.ends.open == nil {
		s.ends.open = make(map[*sql.Tx]*sessionEnds)
	}
	s.ends.open[tx] = e
	return e
}

// commit commits the transaction and then reports what it ended.
func (e *sessionEnds) commit() error {
	err := e.tx.Commit()
	e.finish(err == nil)
	return err
}

// close drops the collected sessions of a transaction that did not commit.
func (e *sessionEnds) close() { e.finish(false) }

func (e *sessionEnds) finish(committed bool) {
	if e == nil || !e.tracked {
		return
	}
	e.tracked = false
	e.reports.mu.Lock()
	delete(e.reports.open, e.tx)
	e.reports.mu.Unlock()
	if !committed || len(e.sessions) == 0 {
		return
	}
	for _, report := range e.receivers {
		report(e.ctx, e.sessions)
	}
}

// errUntrackedSessionEnd keeps a path that forgot trackSessionEnds from
// ending sessions no receiver hears about.
var errUntrackedSessionEnd = errors.New("sqlstore: a session ended in a transaction that does not report session ends")

// sessionEndsFor returns the batch of tx, or nil when no receiver hears
// it. With a receiver attached, an untracked transaction is refused.
func (s *Store) sessionEndsFor(tx *sql.Tx) (*sessionEnds, error) {
	if s.ends == nil {
		return nil, nil
	}
	s.ends.mu.Lock()
	defer s.ends.mu.Unlock()
	e := s.ends.open[tx]
	if e == nil && (len(s.ends.receivers) > 0 || strictSessionEnds) {
		return nil, errUntrackedSessionEnd
	}
	if e == nil || len(e.receivers) == 0 {
		return nil, nil
	}
	return e, nil
}

// sessionClients reads the OAuth clients that held access or refresh
// tokens on the given sessions, revoked or not, before the delete clears
// their session references.
func (s *Store) sessionClients(ctx context.Context, tx *sql.Tx, params string, ids []any) (map[string][]string, error) {
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "sessionId","clientId" FROM "oauthAccessToken" WHERE "sessionId" IN (`+params+`) UNION SELECT "sessionId","clientId" FROM "oauthRefreshToken" WHERE "sessionId" IN (`+params+`)`), append(slices.Clone(ids), ids...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make(map[string][]string)
	for rows.Next() {
		var session, client string
		if err := rows.Scan(&session, &client); err != nil {
			return nil, err
		}
		clients[session] = append(clients[session], client)
	}
	return clients, rows.Err()
}
