package schema

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Plain-Auth/plain-auth/internal/walletschema"
)

// WalletSchema maps physical names in the SIWE wallet table. ID remains "id".
type WalletSchema = walletschema.Mapping

// Options configures optional physical names and extension columns.
type Options struct {
	AdditionalFields AdditionalFields
	Wallet           WalletSchema
}

// NormalizeWallet checks name collisions with all supported tables and indexes.
func NormalizeWallet(m WalletSchema) (WalletSchema, error) {
	m, err := m.Normalize()
	if err != nil {
		return WalletSchema{}, err
	}
	if m == walletschema.Default() {
		return m, nil
	}
	for _, obj := range layouts.Dialects["sqlite"] {
		if slices.Contains(obj.Profiles, "siwe") {
			continue
		}
		_, tail, ok := strings.Cut(obj.SQL, "\"")
		name, _, closed := strings.Cut(tail, "\"")
		if ok && closed && (strings.EqualFold(name, m.Table) || strings.EqualFold(name, m.IndexName())) {
			return WalletSchema{}, fmt.Errorf("schema: wallet names conflict with %q", name)
		}
	}
	return m, nil
}

func mappedObjects(dialect string, profiles []string, wallet WalletSchema) ([]statement, map[string]bool, error) {
	objects, selected, err := selection(dialect, profiles)
	if err != nil || wallet == (WalletSchema{}) {
		return objects, selected, err
	}
	m, err := NormalizeWallet(wallet)
	if err != nil {
		return nil, nil, err
	}
	if !selected["siwe"] {
		return nil, nil, fmt.Errorf("schema: wallet mapping requires the siwe profile")
	}
	if m == walletschema.Default() {
		return objects, selected, nil
	}
	quote := "\""
	if dialect == "mysql" {
		quote = "`"
	}
	replacer := m.Replacer(quote)
	objects = slices.Clone(objects)
	for i, o := range objects {
		if !slices.Contains(o.Profiles, "siwe") {
			continue
		}
		o.SQL = replacer.Replace(o.SQL)
		o.Columns = slices.Clone(o.Columns)
		for j := range o.Columns {
			o.Columns[j].SQL = replacer.Replace(o.Columns[j].SQL)
		}
		objects[i] = o
	}
	return objects, selected, nil
}
