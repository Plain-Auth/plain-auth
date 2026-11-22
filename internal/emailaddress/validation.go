// Package emailaddress implements mailbox validation for wallet contact claims.
package emailaddress

import "regexp"

var walletContact = regexp.MustCompile(`^(?:[A-Za-z0-9_'+-]+\.)*[A-Za-z0-9_'+-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,}$`)

// ValidWalletContact accepts an ASCII contact address that fits the portable user schema.
func ValidWalletContact(email string) bool {
	return len(email) <= 254 && walletContact.MatchString(email)
}
