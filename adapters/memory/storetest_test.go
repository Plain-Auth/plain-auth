package memory_test

import (
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/storetest"
)

// The memory store passes the exported store contract, with its AccountStore
// and SessionRefreshStore groups.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) auth.Store { return memory.New() })
}
