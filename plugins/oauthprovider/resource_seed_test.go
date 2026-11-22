package oauthprovider

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestResourceSeedCacheCancellation(t *testing.T) {
	var cache ResourceSeedCache
	key := sha256.Sum256([]byte("fixture"))
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- cache.run(t.Context(), key, func() (bool, error) { close(started); <-release; return true, nil })
	}()
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	waiter := func() (bool, error) { t.Error("second caller became a writer"); return false, nil }
	err := cache.run(ctx, key, waiter)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting caller did not cancel: %v", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := cache.run(t.Context(), key, waiter); err != nil {
		t.Fatal(err)
	}
}

func TestResourceSeedConfigSnapshot(t *testing.T) {
	var defs []ResourceDefinition
	if err := json.Unmarshal([]byte(`["urn:example:a",{"identifier":"urn:example:b","name":"B","allowedScopes":[],"metadata":{"v":1},"signingKeyId":null}]`), &defs); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareResourceSeeds(defs, SeedMerge)
	if err != nil {
		t.Fatal(err)
	}
	(*defs[1].Policy.Metadata.value)["v"] = json.RawMessage("2")
	if plan.entries[0].Identifier != "urn:example:a" || plan.entries[1].Policy.AllowedScopes.value == nil || *plan.entries[1].Policy.AllowedScopes.value == nil ||
		!plan.entries[1].Policy.SigningKeyID.present || string((*plan.entries[1].Policy.Metadata.value)["v"]) != "1" {
		t.Fatal("seed plan retained mutable input or lost a policy")
	}
	if _, err := prepareResourceSeeds(defs, "replace"); err == nil {
		t.Fatal("accepted unknown seed mode")
	}
}
