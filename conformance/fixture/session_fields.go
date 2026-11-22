package main

import auth "github.com/Plain-Auth/plain-auth"

func configuredSessionFields() map[string]auth.SessionField {
	return map[string]auth.SessionField{
		"locale":       {Type: auth.FieldString, Default: "en", Required: true, Column: "preferred_locale"},
		"count":        {Type: auth.FieldNumber, Default: 4},
		"flag":         {Type: auth.FieldBoolean},
		"deviceClass":  {Type: auth.FieldString, ServerOnly: true, Default: "browser"},
		"privateNote":  {Type: auth.FieldString, Hidden: true},
		"internalRisk": {Type: auth.FieldNumber, ServerOnly: true, Hidden: true, Default: 9},
	}
}
