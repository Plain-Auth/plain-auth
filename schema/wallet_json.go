package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ReadWalletSchema parses a JSON object with table, userId, address, chainId,
// isPrimary and createdAt properties. Omitted names use canonical defaults.
func ReadWalletSchema(r io.Reader) (WalletSchema, error) {
	d := json.NewDecoder(r)
	if err := startFieldObject(d); err != nil {
		return WalletSchema{}, err
	}
	var m WalletSchema
	keys := map[string]*string{"table": &m.Table, "userId": &m.UserID, "address": &m.Address, "chainId": &m.ChainID, "isPrimary": &m.IsPrimary, "createdAt": &m.CreatedAt}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return WalletSchema{}, err
		}
		name := token.(string)
		target, ok := keys[name]
		if !ok {
			return WalletSchema{}, fmt.Errorf("unknown wallet schema property %q", name)
		}
		if *target != "" {
			return WalletSchema{}, fmt.Errorf("duplicate wallet schema property %q", name)
		}
		value, err := d.Token()
		if err != nil {
			return WalletSchema{}, err
		}
		v, ok := value.(string)
		if !ok || v == "" {
			return WalletSchema{}, fmt.Errorf("wallet schema property %q requires a nonempty identifier", name)
		}
		*target = v
	}
	if _, err := d.Token(); err != nil {
		return WalletSchema{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		if err != nil {
			return WalletSchema{}, err
		}
		return WalletSchema{}, errors.New("expected exactly one wallet schema JSON object")
	}
	return NormalizeWallet(m)
}
