package scim

import (
	"strings"
	"testing"
	"time"
)

type managedOnly struct {
	Store
	ManagedStore
}

// The managed catalog defaults its credential cap and last-use interval
// and refuses values outside their bounds.
func TestSCIMManagedCatalogOptionBounds(t *testing.T) {
	build := func(o ManagedOptions) (*Catalog, error) {
		o.CredentialHashSecret = strings.Repeat("k", 32)
		return newCatalog(managedOnly{}, &o)
	}
	if c, err := build(ManagedOptions{}); err != nil || c.limit != 5 {
		t.Fatal("the managed credential cap does not default to five", err)
	}
	if c, err := build(ManagedOptions{MaxActiveCredentials: 100}); err != nil || c.limit != 100 {
		t.Fatal("a managed credential cap of 100 was refused", err)
	}
	for _, limit := range []int{101, -1} {
		if _, err := build(ManagedOptions{MaxActiveCredentials: limit}); err == nil || !strings.Contains(err.Error(), "1 through 100") {
			t.Fatal("a managed credential cap outside 1 through 100 was accepted", limit, err)
		}
	}
	if c, err := build(ManagedOptions{}); err != nil || c.interval != 5*time.Minute {
		t.Fatal("the last-used write interval does not default to five minutes", err)
	}
	interval := func(d time.Duration) *time.Duration { return &d }
	if c, err := build(ManagedOptions{LastUsedWriteInterval: interval(0)}); err != nil || c.interval != 0 {
		t.Fatal("a zero last-used write interval was not kept", err)
	}
	if c, err := build(ManagedOptions{LastUsedWriteInterval: interval(90 * time.Second)}); err != nil || c.interval != 90*time.Second {
		t.Fatal("a custom last-used write interval was not kept", err)
	}
	if _, err := build(ManagedOptions{LastUsedWriteInterval: interval(-time.Second)}); err == nil || !strings.Contains(err.Error(), "nonnegative") {
		t.Fatal("a negative last-used write interval was accepted", err)
	}
}
