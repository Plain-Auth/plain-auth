package plainauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// endReporter is a store that reports ended sessions to its attached report.
type endReporter struct {
	Store
	report   func(context.Context, []EndedSession)
	attached int
}

func (r *endReporter) ReportSessionEnds(report func(context.Context, []EndedSession)) {
	r.report, r.attached = report, r.attached+1
}

// New attaches one report for every OnSessionsEnded observer, in plugin
// order, a panicking observer is logged and the next still runs, and a New
// that fails or has no observer attaches nothing.
func TestSessionEndObservers(t *testing.T) {
	var calls []string
	observer := func(name string, fail bool) Plugin {
		return Plugin{ID: name, OnSessionsEnded: func(_ context.Context, e SessionsEnded) {
			calls = append(calls, name+" "+e.Sessions[0].ID)
			if e.Auth == nil || e.Store == nil {
				t.Error("an observer lost the auth or store")
			}
			if fail {
				panic("observer failed")
			}
		}}
	}
	store := &endReporter{}
	a, err := New(Options{Store: store, BaseURL: "http://auth.test", Secret: strings.Repeat("s", 32), Plugins: []Plugin{observer("first", true), observer("second", false)}})
	if err != nil {
		t.Fatal(err)
	}
	if store.attached != 1 {
		t.Fatal("the report was not attached exactly once", store.attached)
	}
	store.report(t.Context(), []EndedSession{{ID: "s", UserID: "u", OAuthClients: []string{"app"}}})
	if !slices.Equal(calls, []string{"first s", "second s"}) || a == nil {
		t.Fatal("observers did not run in plugin order past a panic", calls)
	}
	quiet := &endReporter{}
	if _, err := New(Options{Store: quiet, BaseURL: "http://auth.test", Secret: strings.Repeat("s", 32)}); err != nil || quiet.attached != 0 {
		t.Fatal("a report was attached without an observer", quiet.attached, err)
	}
	broken := &endReporter{}
	failing := Plugin{ID: "broken", WellKnown: func(*Auth, Store) (map[string]WellKnownDocument, error) { return nil, errors.New("discovery failed") }}
	if _, err := New(Options{Store: broken, BaseURL: "http://auth.test", Secret: strings.Repeat("s", 32), Plugins: []Plugin{observer("first", false), failing}}); err == nil || broken.attached != 0 {
		t.Fatal("a failed New attached its observers", broken.attached, err)
	}
}
