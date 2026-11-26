package apikey

import (
	"context"
	"testing"
	"time"
)

type deadlineStore struct {
	Store
	deadlines []bool
}

func (d *deadlineStore) DeleteExpiredAPIKeys(ctx context.Context, _ string, _ time.Time) (int64, error) {
	_, limited := ctx.Deadline()
	d.deadlines = append(d.deadlines, limited)
	return 0, nil
}

// The purge before an answer gives up after sweepTimeout; a deferred one,
// which nothing waits on, has no deadline.
func TestSweepDeadline(t *testing.T) {
	store := &deadlineStore{}
	inline, err := New(Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	inline.sweep(context.Background())
	var tasks []func()
	deferred, err := New(Options{Store: store, DeferUpdates: true, BackgroundTasks: func(task func()) { tasks = append(tasks, task) }})
	if err != nil {
		t.Fatal(err)
	}
	deferred.sweep(context.Background())
	for _, task := range tasks {
		task()
	}
	if len(store.deadlines) != 2 || !store.deadlines[0] || store.deadlines[1] {
		t.Fatal("only the purge before an answer should have a deadline", store.deadlines)
	}
}
