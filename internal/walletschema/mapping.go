// Package walletschema describes physical names in the wallet association model.
package walletschema

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
)

// Mapping overrides the wallet table or any of its five configurable columns.
// Omitted names use their canonical spelling. The id column is fixed.
type Mapping struct {
	Table, UserID, Address, ChainID, IsPrimary, CreatedAt string
}

func Default() Mapping {
	return Mapping{"walletAddress", "userId", "address", "chainId", "isPrimary", "createdAt"}
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

func (m Mapping) Normalize() (Mapping, error) {
	d := Default()
	fields := []*string{&m.Table, &m.UserID, &m.Address, &m.ChainID, &m.IsPrimary, &m.CreatedAt}
	defaults := []string{d.Table, d.UserID, d.Address, d.ChainID, d.IsPrimary, d.CreatedAt}
	seen := map[string]bool{"id": true}
	for i, target := range fields {
		if *target == "" {
			*target = defaults[i]
		}
		if !identifier.MatchString(*target) {
			return Mapping{}, fmt.Errorf("siwe: invalid SQL identifier %q", *target)
		}
		k := strings.ToLower(*target)
		if i == 0 {
			if strings.HasPrefix(k, "plainauth_") || strings.HasPrefix(k, "sqlite_") || strings.HasPrefix(k, "pg_") {
				return Mapping{}, fmt.Errorf("siwe: reserved wallet table %q", *target)
			}
			continue
		}
		if seen[k] {
			return Mapping{}, fmt.Errorf("siwe: duplicate wallet column %q", *target)
		}
		seen[k] = true
	}
	return m, nil
}

func (m Mapping) IndexName() string {
	name := m.Table + "_" + m.UserID + "_idx"
	if len(name) <= 63 {
		return name
	}
	h := fnv.New32a()
	h.Write([]byte(name))
	suffix := fmt.Sprintf("_%08x_idx", h.Sum32())
	return name[:63-len(suffix)] + suffix
}

// Replacer transforms only fully quoted identifiers in wallet statements.
// A single pass also permits swapping two logical column names.
func (m Mapping) Replacer(quote string) *strings.Replacer {
	d := Default()
	old := []string{d.Table, d.UserID, d.Address, d.ChainID, d.IsPrimary, d.CreatedAt, d.IndexName()}
	names := []string{m.Table, m.UserID, m.Address, m.ChainID, m.IsPrimary, m.CreatedAt, m.IndexName()}
	pairs := make([]string, 0, 2*len(old))
	for i, k := range old {
		pairs = append(pairs, quote+k+quote, quote+names[i]+quote)
	}
	return strings.NewReplacer(pairs...)
}
