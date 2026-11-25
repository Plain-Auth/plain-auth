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

// vault is a plugin that keeps single-use records in its own store and runs
// the verification hooks around them through EndpointContext.
type vault struct {
	mu      sync.Mutex
	records map[string]time.Time
	events  []string
	// saveErr fails the next save; findMiss makes find report nothing.
	saveErr  error
	findMiss bool
}

func (v *vault) note(event string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.events = append(v.events, event)
}

func (v *vault) drain() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.events
	v.events = nil
	return out
}

func (v *vault) record(token string, expires time.Time) authn.VerificationRecord {
	return authn.VerificationRecord{ID: "vault-" + token, Identifier: "vault", UserID: "owner", ExpiresAt: expires}
}

func (v *vault) plugin(validate func(authn.Store, authn.VerificationHookSet) error) authn.Plugin {
	// An expiry with nanoseconds in another zone, which the hooks see in UTC
	// to the millisecond.
	expires := time.Date(2030, 1, 2, 4, 5, 6, 789654321, time.FixedZone("UTC+1", 3600))
	return authn.Plugin{ID: "vault", ValidateVerificationStore: validate, Endpoints: []authn.Endpoint{
		{Method: "POST", Path: "/vault/issue", Handler: func(c authn.EndpointContext) (any, error) {
			token, _ := c.Body["token"].(string)
			declined, err := c.CreateVerification(v.record(token, expires), func(ctx context.Context) error {
				v.note("save")
				v.mu.Lock()
				defer v.mu.Unlock()
				if err := v.saveErr; err != nil {
					v.saveErr = nil
					return err
				}
				v.records[token] = expires
				return nil
			})
			if err != nil {
				return nil, err
			}
			return map[string]bool{"declined": declined}, nil
		}},
		{Method: "POST", Path: "/vault/redeem", Handler: func(c authn.EndpointContext) (any, error) {
			token, _ := c.Body["token"].(string)
			refused, err := c.SpendVerification(func(context.Context) (authn.VerificationRecord, error) {
				v.note("find")
				v.mu.Lock()
				defer v.mu.Unlock()
				at, ok := v.records[token]
				if !ok || v.findMiss {
					return authn.VerificationRecord{}, authn.ErrNotFound
				}
				return v.record(token, at), nil
			}, func(context.Context) error {
				v.note("spend")
				v.mu.Lock()
				defer v.mu.Unlock()
				if _, ok := v.records[token]; !ok {
					return authn.ErrNotFound
				}
				delete(v.records, token)
				return nil
			})
			if err != nil {
				return nil, err
			}
			return map[string]bool{"refused": refused}, nil
		}},
	}}
}

// Plugin packages run the verification hooks around records they keep in
// their own stores: a declined create stores nothing, a declined spend keeps
// the record, a spend its hooks did not see is refused, and New asks the
// plugin whether its store can follow the hooks that are set.
func TestPluginVerificationHooks(t *testing.T) {
	v := &vault{records: map[string]time.Time{}}
	var mu sync.Mutex
	var seen []authn.VerificationRecord
	var paths []string
	skip, edit, fail := map[string]bool{}, false, map[string]bool{}
	note := func(event string, rec authn.VerificationRecord, c *authn.HookContext) error {
		v.note(event)
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, rec)
		if c != nil {
			paths = append(paths, c.Path)
		}
		if skip[event] {
			return authn.ErrSkipWrite
		}
		if fail[event] {
			return errors.New("hook failed")
		}
		return nil
	}
	set := func(m map[string]bool, event string, on bool) {
		mu.Lock()
		defer mu.Unlock()
		m[event] = on
	}
	hooks := authn.ModelHooks[authn.VerificationRecord]{
		Create: authn.OperationHooks[authn.VerificationRecord]{
			Before: func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
				if err := note("create-before", *r, c); err != nil {
					return err
				}
				mu.Lock()
				defer mu.Unlock()
				if edit {
					r.UserID = "someone-else"
				}
				return nil
			},
			After: func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
				return note("create-after", r, c)
			},
		},
		Delete: authn.OperationHooks[authn.VerificationRecord]{
			Before: func(_ context.Context, r *authn.VerificationRecord, c *authn.HookContext) error {
				return note("delete-before", *r, c)
			},
			After: func(_ context.Context, r authn.VerificationRecord, c *authn.HookContext) error {
				return note("delete-after", r, c)
			},
		},
	}
	var asked []authn.VerificationHookSet
	validate := func(_ authn.Store, set authn.VerificationHookSet) error {
		asked = append(asked, set)
		return nil
	}
	logs := &bytes.Buffer{}
	newAuth := func(hooks authn.ModelHooks[authn.VerificationRecord]) *authn.Auth {
		t.Helper()
		off := false
		o := authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32), RateLimit: &off,
			Logger: slog.New(slog.NewJSONHandler(logs, nil)), Plugins: []authn.Plugin{v.plugin(validate)}}
		o.DatabaseHooks.Verification = hooks
		a, err := authn.New(o)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := newAuth(hooks)
	call := func(a *authn.Auth, path, token string, status int) map[string]bool {
		t.Helper()
		r := httptest.NewRequest("POST", "https://auth.example/api/auth"+path, strings.NewReader(`{"token":"`+token+`"}`))
		r.Header.Set("Origin", "https://auth.example")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s answered %d %s, want %d", path, w.Code, w.Body.String(), status)
		}
		var out map[string]bool
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	same := func(got []string, want ...string) {
		t.Helper()
		if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
			t.Fatalf("ran %q, want %q", got, want)
		}
	}
	stored := func(token string) bool {
		v.mu.Lock()
		defer v.mu.Unlock()
		_, ok := v.records[token]
		return ok
	}

	// A create runs its before hook, the save and its after hook, with the
	// endpoint's HookContext and the expiry in UTC to the millisecond.
	if out := call(a, "/vault/issue", "a", 200); out["declined"] {
		t.Fatal("an approved create was declined")
	}
	same(v.drain(), "create-before", "save", "create-after")
	want := authn.VerificationRecord{ID: "vault-a", Identifier: "vault", UserID: "owner", ExpiresAt: time.Date(2030, 1, 2, 3, 5, 6, 789000000, time.UTC)}
	mu.Lock()
	if len(seen) != 2 || seen[0] != want || seen[1] != want || !reflect.DeepEqual(paths, []string{"/vault/issue", "/vault/issue"}) {
		t.Fatal("the create hooks saw", seen, paths)
	}
	seen, paths = nil, nil
	mu.Unlock()
	if asked == nil || asked[0] != (authn.VerificationHookSet{CreateBefore: true, Delete: true}) {
		t.Fatal("New asked the plugin about", asked)
	}

	// A declined create never calls save; a failed save runs no after hook;
	// an after hook's error is returned with the record stored.
	set(skip, "create-before", true)
	if out := call(a, "/vault/issue", "b", 200); !out["declined"] || stored("b") {
		t.Fatal("a declined create stored its record")
	}
	same(v.drain(), "create-before")
	set(skip, "create-before", false)
	v.mu.Lock()
	v.saveErr = errors.New("disk full")
	v.mu.Unlock()
	call(a, "/vault/issue", "b", 500)
	same(v.drain(), "create-before", "save")
	set(fail, "create-after", true)
	call(a, "/vault/issue", "c", 500)
	same(v.drain(), "create-before", "save", "create-after")
	set(fail, "create-after", false)
	if !stored("c") {
		t.Fatal("a failed after hook removed the record")
	}
	// A before hook may not change the record.
	mu.Lock()
	edit = true
	mu.Unlock()
	call(a, "/vault/issue", "d", 500)
	same(v.drain(), "create-before")
	mu.Lock()
	edit = false
	mu.Unlock()

	// A spend runs find, its before hook, the spend and its after hook, on the
	// record find read, with its expiry in UTC to the millisecond.
	mu.Lock()
	seen, paths = nil, nil
	mu.Unlock()
	if out := call(a, "/vault/redeem", "a", 200); out["refused"] || stored("a") {
		t.Fatal("an approved spend was refused")
	}
	same(v.drain(), "find", "delete-before", "spend", "delete-after")
	mu.Lock()
	if len(seen) != 2 || seen[0] != want || seen[1] != want || !reflect.DeepEqual(paths, []string{"/vault/redeem", "/vault/redeem"}) {
		t.Fatal("the delete hooks saw", seen, paths)
	}
	mu.Unlock()
	// A declined spend keeps the record and never calls spend.
	set(skip, "delete-before", true)
	if out := call(a, "/vault/redeem", "c", 200); !out["refused"] || !stored("c") {
		t.Fatal("a declined spend spent its record")
	}
	same(v.drain(), "find", "delete-before")
	set(skip, "delete-before", false)
	// A record find cannot see runs no hooks, and a spend of nothing is refused.
	if out := call(a, "/vault/redeem", "missing", 200); !out["refused"] {
		t.Fatal("a spend of nothing was accepted")
	}
	same(v.drain(), "find", "spend")
	// A spend of a record its hooks did not see is refused and logged.
	v.mu.Lock()
	v.findMiss = true
	v.mu.Unlock()
	if out := call(a, "/vault/redeem", "c", 200); !out["refused"] || stored("c") {
		t.Fatal("an unseen spend was accepted")
	}
	same(v.drain(), "find", "spend")
	if !strings.Contains(logs.String(), "did not see") {
		t.Fatal("an unseen spend was not logged:", logs.String())
	}
	v.mu.Lock()
	v.findMiss = false
	v.mu.Unlock()
	// An after hook's error is returned with the record spent.
	call(a, "/vault/issue", "e", 200)
	v.drain()
	set(fail, "delete-after", true)
	call(a, "/vault/redeem", "e", 500)
	same(v.drain(), "find", "delete-before", "spend", "delete-after")
	set(fail, "delete-after", false)
	if stored("e") {
		t.Fatal("a failed delete after hook kept the record")
	}

	// With only create hooks, a spend never calls find.
	asked = nil
	creates := newAuth(authn.ModelHooks[authn.VerificationRecord]{Create: hooks.Create})
	if asked == nil || asked[0] != (authn.VerificationHookSet{CreateBefore: true}) {
		t.Fatal("New asked the plugin about", asked)
	}
	call(creates, "/vault/issue", "f", 200)
	call(creates, "/vault/redeem", "f", 200)
	same(v.drain(), "create-before", "save", "create-after", "spend")
	asked = nil
	afterOnly := newAuth(authn.ModelHooks[authn.VerificationRecord]{Create: authn.OperationHooks[authn.VerificationRecord]{After: hooks.Create.After}})
	if asked == nil || asked[0] != (authn.VerificationHookSet{}) {
		t.Fatal("New asked the plugin about", asked)
	}
	call(afterOnly, "/vault/issue", "g", 200)
	same(v.drain(), "save", "create-after")
	mu.Lock()
	seen, paths = nil, nil
	mu.Unlock()

	// Without verification hooks, New never asks; with them, it fails with
	// the plugin's error.
	asked = nil
	newAuth(authn.ModelHooks[authn.VerificationRecord]{})
	if asked != nil {
		t.Fatal("New asked the plugin without verification hooks:", asked)
	}
	o := authn.Options{BaseURL: "https://auth.example", Store: memory.New(), Secret: strings.Repeat("s", 32),
		Plugins: []authn.Plugin{v.plugin(func(authn.Store, authn.VerificationHookSet) error { return errors.New("the vault cannot read records") })}}
	o.DatabaseHooks.Verification.Delete = hooks.Delete
	if _, err := authn.New(o); err == nil || !strings.Contains(err.Error(), "the vault cannot read records") {
		t.Fatal("New ignored the plugin's refusal:", err)
	}
}
