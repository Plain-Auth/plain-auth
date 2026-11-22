package schema

import (
	"strings"
	"testing"
)

func TestWalletSchemaDeclarations(t *testing.T) {
	for _, m := range []WalletSchema{
		{Table: "user"}, {Table: "plainauth_auth_state"}, {Table: "account_userId_idx"},
		{Table: "public.wallet"}, {Address: `field"x`}, {CreatedAt: strings.Repeat("x", 64)},
		{UserID: "ID"}, {UserID: "owner", Address: "Owner"},
	} {
		if _, err := GenerateWithOptions("postgres", []string{"siwe"}, Options{Wallet: m}); err == nil {
			t.Fatalf("accepted invalid wallet declaration %+v", m)
		}
	}
	if _, err := GenerateWithOptions("sqlite", nil, Options{Wallet: WalletSchema{Table: "wallets"}}); err == nil {
		t.Fatal("accepted mapping without a wallet profile")
	}
	before, err := Generate("sqlite", []string{"siwe"})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []WalletSchema{{Table: "wallets"}, {UserID: "address", Address: "userId"}} {
		got, err := GenerateWithOptions("sqlite", []string{"siwe"}, Options{Wallet: m})
		if err != nil || got == before {
			t.Fatal("custom declaration was ignored", err)
		}
		after, err := Generate("sqlite", []string{"siwe"})
		if err != nil || after != before {
			t.Fatal("mapping altered the default generator", err)
		}
	}
}
