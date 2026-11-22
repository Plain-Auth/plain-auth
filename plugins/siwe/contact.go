package siwe

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// ContactClaim identifies a temporary, unverified mailbox reservation for one wallet registration.
type ContactClaim struct {
	ID, Email, Address, Receipt string
	ExpiresAt                   time.Time
}

// ContactStore uses an eligible reservation only to create a new, unverified account.
// A busy or occupied contact falls back to Login.Email. Never select an owner by contact address.
type ContactStore interface {
	ReserveWalletContact(ctx context.Context, email, address string) (*ContactClaim, error)
	ReleaseWalletContact(context.Context, ContactClaim) error
	FinishWalletContactLogin(context.Context, Login, auth.StoredSession, ContactClaim) (auth.User, error)
}

func releaseContact(request context.Context, store ContactStore, claim ContactClaim) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request), 3*time.Second)
	defer cancel()
	_ = store.ReleaseWalletContact(ctx, claim)
}

// walletPlaceholder reserves generated addresses for their actual wallet across chains.
func walletPlaceholder(email, domain string) bool {
	local, host, ok := strings.Cut(email, "@")
	if !ok || host != domain {
		return false
	}
	address, chain, suffixed := strings.Cut(local, "+")
	if len(address) != 42 || !strings.HasPrefix(address, "0x") {
		return false
	}
	if _, err := hex.DecodeString(address[2:]); err != nil {
		return false
	}
	if !suffixed {
		return true
	}
	id, err := strconv.ParseInt(chain, 10, 32)
	return err == nil && id > 0 && strconv.FormatInt(id, 10) == chain
}
