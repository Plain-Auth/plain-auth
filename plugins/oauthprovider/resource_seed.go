package oauthprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	auth "github.com/Plain-Org/plain-auth"
)

// ResourceDefinition configures one audience. In JSON it can be an identifier
// string or an object with identifier and the fields of ResourcePatch.
type ResourceDefinition struct {
	Identifier string
	Policy     ResourcePatch
}

func (d ResourceDefinition) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Identifier string `json:"identifier"`
		ResourcePatch
	}{d.Identifier, d.Policy})
}

func (d *ResourceDefinition) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	var input ResourceDefinition
	if len(b) != 0 && b[0] == '"' {
		if err := json.Unmarshal(b, &input.Identifier); err != nil {
			return err
		}
	} else {
		var id struct{ Identifier string }
		if err := json.Unmarshal(b, &id); err != nil {
			return err
		}
		input.Identifier = id.Identifier
		if err := json.Unmarshal(b, &input.Policy); err != nil {
			return err
		}
	}
	*d = input
	return nil
}

type ResourceSeedMode string

// ResourcePolicyReplacer replaces all policy fields, including policyVersion,
// in one write while preserving the row identity and creation time.
type ResourcePolicyReplacer interface {
	ReplaceOAuthResourcePolicy(context.Context, Resource) error
}

const (
	SeedInsertOnly ResourceSeedMode = "insertOnly"
	SeedMerge      ResourceSeedMode = "merge"
	SeedOverwrite  ResourceSeedMode = "overwrite"
)

// ResourceSeedCache remembers completed entries across managers in one process.
// Allocate a separate cache for each logical database. Its zero value is ready
// to use. A waiting caller can cancel without interrupting another caller's seed.
type ResourceSeedCache struct {
	mu sync.Mutex
	// A nil channel marks completion. A live channel is closed when the writer exits.
	entries map[[sha256.Size]byte]chan struct{}
}

func (c *ResourceSeedCache) run(ctx context.Context, key [sha256.Size]byte, work func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.mu.Lock()
		done, exists := c.entries[key]
		if !exists {
			if c.entries == nil {
				c.entries = make(map[[sha256.Size]byte]chan struct{})
			}
			done = make(chan struct{})
			c.entries[key] = done
			c.mu.Unlock()
			completed := false
			defer func() {
				c.mu.Lock()
				if completed {
					c.entries[key] = nil
				} else {
					delete(c.entries, key)
				}
				close(done)
				c.mu.Unlock()
			}()
			ok, err := work()
			completed = ok && err == nil
			return err
		}
		c.mu.Unlock()
		if done == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
}

type resourceSeed struct {
	ResourceDefinition
	key [sha256.Size]byte
}

type resourceSeeds struct {
	entries []resourceSeed
	mode    ResourceSeedMode
	local   ResourceSeedCache
	done    atomic.Bool
}

func prepareResourceSeeds(defs []ResourceDefinition, mode ResourceSeedMode) (*resourceSeeds, error) {
	if mode == "" {
		mode = SeedInsertOnly
	}
	if mode != SeedInsertOnly && mode != SeedMerge && mode != SeedOverwrite {
		return nil, fmt.Errorf("oauthprovider: unknown resource seed mode %q", mode)
	}
	if len(defs) == 0 {
		return nil, nil
	}
	seeds := &resourceSeeds{mode: mode}
	for _, d := range defs {
		// Snapshot caller-owned maps and slices before publishing the manager.
		encoded, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		var definition ResourceDefinition
		if err := json.Unmarshal(encoded, &definition); err != nil {
			return nil, err
		}
		key := sha256.Sum256(append([]byte(string(mode)+"\x00"), encoded...))
		seeds.entries = append(seeds.entries, resourceSeed{definition, key})
	}
	return seeds, nil
}

// Seed applies the configured resources from trusted startup configuration.
// It can be called explicitly before serving requests. A failed seed is retried
// on the next call, including the next authorized registry operation.
func (m *ResourceManager) Seed(ctx context.Context) error {
	if m.seeds == nil || m.seeds.done.Load() {
		return nil
	}
	shared := m.opts.SharedSeeds
	for i, entry := range m.seeds.entries {
		cache, key := shared, entry.key
		if cache == nil {
			cache = &m.seeds.local
			// Distinct positions preserve the declared order of repeated entries.
			binary.BigEndian.PutUint64(key[:8], uint64(i))
		}
		if err := cache.run(ctx, key, func() (bool, error) {
			applied, err := m.seedResource(ctx, entry.ResourceDefinition)
			// Another manager sharing a cache may accept a locally rejected identifier.
			return applied || shared == nil, err
		}); err != nil {
			return err
		}
	}
	if shared == nil {
		m.seeds.done.Store(true)
	}
	return nil
}

func (m *ResourceManager) seedResource(ctx context.Context, d ResourceDefinition) (bool, error) {
	valid, err := m.validIdentifier(ctx, d.Identifier)
	if err != nil {
		return false, err
	}
	if d.Identifier == "" || !valid {
		m.auth.Logger().WarnContext(ctx, "Skipping invalid OAuth resource identifier", "identifier", d.Identifier)
		return false, nil
	}
	fields := d.Policy
	if alg := fields.SigningAlgorithm.value; alg != nil && !slices.Contains(resourceSigningAlgorithms(), *alg) {
		m.auth.Logger().WarnContext(ctx, "Ignoring unsupported OAuth resource signing algorithm", "identifier", d.Identifier, "algorithm", *alg)
		fields.SigningAlgorithm = Setting[string]{}
	}
	_, err = m.store.OAuthResource(ctx, d.Identifier)
	switch {
	case errors.Is(err, auth.ErrNotFound):
		row, err := newResource(d.Identifier, fields, resourceNow())
		if err != nil {
			return false, err
		}
		err = m.store.CreateOAuthResource(ctx, row)
		if !errors.Is(err, ErrResourceExists) {
			return err == nil, err
		}
		// Another process inserted this audience. Merge and overwrite still apply.
	case err != nil:
		return false, err
	}
	if m.seeds.mode == SeedInsertOnly {
		return true, nil
	}
	if m.seeds.mode == SeedOverwrite {
		row := Resource{Identifier: d.Identifier, Name: d.Identifier, PolicyVersion: 1, UpdatedAt: resourceNow()}
		if err := fields.Apply(&row); err != nil {
			return false, err
		}
		err = m.store.(ResourcePolicyReplacer).ReplaceOAuthResourcePolicy(ctx, row)
		return err == nil, err
	}
	_, err = m.store.UpdateOAuthResource(ctx, d.Identifier, fields, resourceNow())
	return err == nil, err
}
