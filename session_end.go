package plainauth

import "context"

// EndedSession is a session a store ended. OAuthClients lists the OAuth
// clients that held access or refresh tokens on it, revoked or not, when it
// ended.
type EndedSession struct {
	ID, UserID   string
	OAuthClients []string
}

// SessionEndReporter is a store that reports every session it ends,
// whatever path ends it. After the transaction commits, and outside it, the
// store calls the attached report once with the context of the call. New
// attaches one report when a plugin sets OnSessionsEnded; attaching another
// replaces it, so the Auth created last on a store hears its session ends.
type SessionEndReporter interface {
	ReportSessionEnds(report func(context.Context, []EndedSession))
}

// SessionsEnded describes sessions a store ended to Plugin.OnSessionsEnded.
type SessionsEnded struct {
	Auth     *Auth
	Store    Store
	Sessions []EndedSession
}

// attachSessionEnds connects the plugins' OnSessionsEnded observers to a
// store that reports session ends. It runs last in New, so a New that fails
// leaves the store unattached. Another runtime observes ends through its
// session delete hook; a store reports them here after commit instead, so
// sessions ended inside a store's own transactions are seen too.
func (a *Auth) attachSessionEnds() {
	reporter, ok := a.opts.Store.(SessionEndReporter)
	if !ok {
		return
	}
	var observers []func(context.Context, SessionsEnded)
	for _, plugin := range a.opts.Plugins {
		if plugin.OnSessionsEnded != nil {
			observers = append(observers, plugin.OnSessionsEnded)
		}
	}
	if len(observers) == 0 {
		return
	}
	reporter.ReportSessionEnds(func(ctx context.Context, sessions []EndedSession) {
		ended := SessionsEnded{Auth: a, Store: a.opts.Store, Sessions: sessions}
		for _, observe := range observers {
			func() {
				defer func() {
					if p := recover(); p != nil {
						a.Logger().ErrorContext(ctx, "A session end observer panicked", "panic", p)
					}
				}()
				observe(ctx, ended)
			}()
		}
	})
}
