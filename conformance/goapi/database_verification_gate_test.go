package goapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// ledger is a plugin store that decides its records inside a transaction:
// each call works on a copy and commits it only when it returns nil.
type ledger struct {
	mu      sync.Mutex
	records map[string]bool
	sides   int
}

type ledgerTx struct {
	records map[string]bool
	sides   int
}

// tx runs call on a copy of the ledger and commits the copy when call
// returns nil.
func (l *ledger) tx(call func(*ledgerTx) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := &ledgerTx{records: map[string]bool{}, sides: l.sides}
	for k, v := range l.records {
		t.records[k] = v
	}
	if err := call(t); err != nil {
		return err
	}
	l.records, l.sides = t.records, t.sides
	return nil
}

func (l *ledger) state() (map[string]bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]bool{}
	for k, v := range l.records {
		out[k] = v
	}
	return out, l.sides
}

// gatedLedger marks a store whose ledger asks the request's gate.
type gatedLedger struct{ authn.Store }

func (gatedLedger) GatesLedger() {}

var ledgerExpiry = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func ledgerRecord(token string) authn.VerificationRecord {
	return authn.VerificationRecord{ID: "ledger-" + token, Identifier: "ledger", UserID: "owner", ExpiresAt: ledgerExpiry}
}

var errLedgerRefused = &authn.APIError{Status: 400, Code: "LEDGER_REFUSED", Message: "Refused"}

func (l *ledger) plugin(hooks authn.DatabaseHooks) authn.Plugin {
	issue := func(ctx context.Context, token string) error {
		return l.tx(func(t *ledgerTx) error {
			t.sides++ // the rest of the call, which a declined record leaves standing
			ok, err := authn.VerificationGateFrom(ctx).Create(ledgerRecord(token))
			if err != nil {
				return err
			}
			if ok {
				t.records[token] = true
			}
			return nil
		})
	}
	redeem := func(ctx context.Context, token string) error {
		return l.tx(func(t *ledgerTx) error {
			if !t.records[token] {
				return errLedgerRefused
			}
			ok, err := authn.VerificationGateFrom(ctx).Delete(ledgerRecord(token))
			if err != nil {
				return err
			}
			if !ok {
				return errLedgerRefused
			}
			delete(t.records, token)
			return nil
		})
	}
	return authn.Plugin{ID: "ledger", DatabaseHooks: hooks,
		ValidateVerificationStore: func(s authn.Store, _ authn.VerificationHookSet) error {
			if _, ok := s.(interface{ GatesLedger() }); !ok {
				return errors.New("auth: verification hooks with the ledger plugin require a store implementing GatesLedger")
			}
			return nil
		},
		Endpoints: []authn.Endpoint{
			{Method: "POST", Path: "/ledger/issue", Handler: func(c authn.EndpointContext) (any, error) {
				token, _ := c.Body["token"].(string)
				return map[string]bool{"status": true}, c.GateVerifications(func(ctx context.Context) error { return issue(ctx, token) })
			}},
			{Method: "POST", Path: "/ledger/redeem", Handler: func(c authn.EndpointContext) (any, error) {
				token, _ := c.Body["token"].(string)
				return map[string]bool{"status": true}, c.GateVerifications(func(ctx context.Context) error { return redeem(ctx, token) })
			}},
			{Method: "POST", Path: "/ledger/careless", Handler: func(c authn.EndpointContext) (any, error) {
				token, _ := c.Body["token"].(string)
				return map[string]bool{"status": true}, c.GateVerifications(func(ctx context.Context) error {
					return l.tx(func(t *ledgerTx) error {
						// A store that ignores the stop and commits.
						authn.VerificationGateFrom(ctx).Create(ledgerRecord(token))
						t.records[token] = true
						return nil
					})
				})
			}},
			{Method: "POST", Path: "/ledger/pair", Handler: func(c authn.EndpointContext) (any, error) {
				token, _ := c.Body["token"].(string)
				old, _ := c.Body["old"].(string)
				return map[string]bool{"status": true}, c.GateVerifications(func(ctx context.Context) error {
					return l.tx(func(t *ledgerTx) error {
						g := authn.VerificationGateFrom(ctx)
						// Both records are asked about before the call stops.
						keep, e1 := g.Create(ledgerRecord(token))
						drop, e2 := g.Delete(ledgerRecord(old))
						if err := errors.Join(e1, e2); err != nil {
							return err
						}
						if keep {
							t.records[token] = true
						}
						if drop {
							delete(t.records, old)
						}
						return nil
					})
				})
			}},
		}}
}

// A plugin whose store decides its verification records inside a
// transaction runs their hooks through EndpointContext.GateVerifications:
// the call stops before writing, the before hooks run outside it, and the
// call runs again bound to what they said. A declined record is left
// unwritten while the call commits the rest, and the after hooks run once
// the call commits.
func TestPluginVerificationGate(t *testing.T) {
	l := &ledger{records: map[string]bool{}}
	var mu sync.Mutex
	var events []string
	var paths []string
	skip := map[string]bool{}
	var sidesSeen []int
	note := func(source, event string, r authn.VerificationRecord, c *authn.HookContext) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, source+":"+event+":"+r.ID)
		if c != nil {
			paths = append(paths, c.Path)
		} else {
			paths = append(paths, "")
		}
		if source == "app" && strings.HasSuffix(event, "before") {
			_, sides := l.state()
			sidesSeen = append(sidesSeen, sides)
		}
		if strings.HasSuffix(event, "after") && source == "app" {
			records, _ := l.state()
			if committed := records[strings.TrimPrefix(r.ID, "ledger-")]; committed != (event == "create-after") {
				return errors.New("an after hook saw the record before its call committed")
			}
		}
		if skip[source+":"+event+":"+r.ID] {
			return authn.ErrSkipWrite
		}
		return nil
	}
	hooks := func(source string) authn.DatabaseHooks {
		var h authn.DatabaseHooks
		h.Verification.Create.Before = func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
			return note(source, "create-before", *r, c)
		}
		h.Verification.Create.After = func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
			return note(source, "create-after", r, c)
		}
		h.Verification.Delete.Before = func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
			return note(source, "delete-before", *r, c)
		}
		h.Verification.Delete.After = func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
			return note(source, "delete-after", r, c)
		}
		return h
	}
	off := false
	logs := &bytes.Buffer{}
	opts := authn.Options{BaseURL: "https://auth.example", Store: gatedLedger{memory.New()}, Secret: strings.Repeat("s", 32), RateLimit: &off,
		Logger: slog.New(slog.NewTextHandler(logs, nil)), Plugins: []authn.Plugin{l.plugin(hooks("plugin"))}, DatabaseHooks: hooks("app")}
	a, err := authn.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	call := func(path string, body map[string]string, status int) {
		t.Helper()
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(string(raw)))
		r.Header.Set("Origin", "https://auth.example")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s answered %d %s, want %d", path, w.Code, w.Body.String(), status)
		}
	}
	drain := func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		e, p := events, paths
		events, paths = nil, nil
		return e, p
	}
	same := func(got []string, want ...string) {
		t.Helper()
		if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
			t.Fatalf("hooks ran as %q, want %q", got, want)
		}
	}

	// An issue stops before writing, runs the plugin's and then the
	// application's before hooks once, and commits on its second run; the
	// after hooks see the committed record.
	call("/ledger/issue", map[string]string{"token": "a"}, 200)
	got, at := drain()
	same(got, "plugin:create-before:ledger-a", "app:create-before:ledger-a", "plugin:create-after:ledger-a", "app:create-after:ledger-a")
	if !reflect.DeepEqual(at, []string{"/ledger/issue", "/ledger/issue", "/ledger/issue", "/ledger/issue"}) {
		t.Fatal("the hooks saw the paths", at)
	}
	if records, sides := l.state(); !records["a"] || sides != 1 || !reflect.DeepEqual(sidesSeen, []int{0}) {
		t.Fatal("the issue committed", records, sides, "and its before hook saw", sidesSeen, "side rows")
	}
	// A declined record is left unwritten while the call commits the rest.
	skip["app:create-before:ledger-b"] = true
	call("/ledger/issue", map[string]string{"token": "b"}, 200)
	got, _ = drain()
	same(got, "plugin:create-before:ledger-b", "app:create-before:ledger-b")
	if records, sides := l.state(); records["b"] || sides != 2 {
		t.Fatal("a declined issue committed", records, sides)
	}
	// A declined spend keeps the record, and the plugin refuses.
	skip["plugin:delete-before:ledger-a"] = true
	call("/ledger/redeem", map[string]string{"token": "a"}, 400)
	got, _ = drain()
	same(got, "plugin:delete-before:ledger-a")
	delete(skip, "plugin:delete-before:ledger-a")
	if records, _ := l.state(); !records["a"] {
		t.Fatal("a declined spend removed the record")
	}
	// A record the store refuses runs no hooks.
	call("/ledger/redeem", map[string]string{"token": "missing"}, 400)
	got, _ = drain()
	same(got)
	// Two records in one call run their before hooks in one pass, and their
	// after hooks in the order the store asked.
	call("/ledger/pair", map[string]string{"token": "c", "old": "a"}, 200)
	got, _ = drain()
	same(got, "plugin:create-before:ledger-c", "app:create-before:ledger-c", "plugin:delete-before:ledger-a", "app:delete-before:ledger-a",
		"plugin:create-after:ledger-c", "app:create-after:ledger-c", "plugin:delete-after:ledger-a", "app:delete-after:ledger-a")
	if records, _ := l.state(); records["a"] || !records["c"] {
		t.Fatal("the pair committed", records)
	}
	// A store that commits while a record awaits its hooks fails the request,
	// runs no hook and is logged.
	call("/ledger/careless", map[string]string{"token": "careless"}, 500)
	got, _ = drain()
	same(got)
	if !strings.Contains(logs.String(), "awaited its before hooks") {
		t.Fatal("a store that ignored a stop was not logged:", logs.String())
	}
	// A direct Go call gets no HookContext.
	c := authn.EndpointContext{Auth: a, Request: httptest.NewRequest("POST", "https://auth.example/", nil)}
	if err := c.GateVerifications(func(ctx context.Context) error {
		return l.tx(func(t *ledgerTx) error {
			ok, err := authn.VerificationGateFrom(ctx).Create(ledgerRecord("d"))
			t.records["d"] = ok
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	got, at = drain()
	same(got, "plugin:create-before:ledger-d", "app:create-before:ledger-d", "plugin:create-after:ledger-d", "app:create-after:ledger-d")
	if !reflect.DeepEqual(at, []string{"", "", "", ""}) {
		t.Fatal("a direct call's hooks saw the paths", at)
	}

	// New asks the plugin about the store: the ledger needs its marker.
	opts.Store = memory.New()
	if _, err := authn.New(opts); err == nil || !strings.Contains(err.Error(), "GatesLedger") {
		t.Fatal("New accepted a ledger store that does not ask the gate:", err)
	}
}
