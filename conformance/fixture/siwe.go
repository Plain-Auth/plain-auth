package main

import (
	"context"
	"crypto/rand"
	"os"
	"strings"

	"github.com/Plain-Auth/plain-auth/plugins/siwe"
)

func walletFixtureOptions() siwe.Options {
	o := siwe.Options{Domain: "wallet.example.test"}
	controller := os.Getenv("CONFORMANCE_WALLET_CONTROLLER")
	if controller == "" {
		return o
	}
	contract := os.Getenv("CONFORMANCE_WALLET_CONTRACT")
	o.GetNonce = func(context.Context) (string, error) { return "Custom" + rand.Text(), nil }
	o.VerifyMessage = func(ctx context.Context, a siwe.VerifyMessageArgs) (bool, error) {
		if a.Cacao.Payload.Domain != o.Domain || a.Cacao.Payload.Audience != o.Domain || a.Cacao.Payload.Issuer != o.Domain ||
			a.Cacao.Header.Type != "caip122" || a.Cacao.Payload.Version != "1" || a.Cacao.Signature.Value != a.Signature ||
			a.Cacao.Signature.Type != "eip191" || !strings.Contains(a.Message, "Nonce: "+a.Cacao.Payload.Nonce+"\n") {
			return false, nil
		}
		return a.ChainID == 1 && strings.EqualFold(a.Address, contract) && a.SignedBy(controller), nil
	}
	o.ENSLookup = func(ctx context.Context, a siwe.ENSLookupArgs) (siwe.ENSLookupResult, error) {
		if strings.EqualFold(a.WalletAddress, contract) && a.ChainID == 1 {
			return siwe.ENSLookupResult{Name: "fixture.eth", Avatar: "https://wallet.example.test/avatar.png"}, nil
		}
		return siwe.ENSLookupResult{}, nil
	}
	return o
}
