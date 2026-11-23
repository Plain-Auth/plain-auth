package main

import (
	"context"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

func fixtureAccountFields() map[string]auth.AccountField {
	return map[string]auth.AccountField{
		"providerEmail": {Type: auth.FieldString, Column: "provider_mail"},
		"grantKind":     {Type: auth.FieldString},
		"ownerClass":    {Type: auth.FieldString, ServerOnly: true, Required: true, Default: "member"},
		"privateLabel":  {Type: auth.FieldString, Hidden: true},
	}
}

func fixtureAccountMapping(_ context.Context, input auth.OAuthAccountFieldInput) (map[string]any, error) {
	var email any = input.Profile.Email
	if strings.HasPrefix(input.Profile.Email, "invalid-") {
		email = false
	}
	private := "private"
	if input.ExchangedToken != nil {
		if tag, ok := input.ExchangedToken.Extra("directory_tag").(string); ok {
			private = tag
		}
	}
	kind := "browser"
	if input.Tokens.IDToken != "" {
		kind = "native"
	}
	return map[string]any{
		"providerEmail": email, "grantKind": kind, "privateLabel": private, "ownerClass": "administrator",
		"id": "injected", "userId": "injected", "accountId": "injected", "providerId": "injected", "unknown": "ignored",
		"accessToken": "injected", "password": "injected",
	}, nil
}
