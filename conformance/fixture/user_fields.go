package main

import auth "github.com/Plain-Org/plain-auth"

func configuredUserFields() map[string]auth.UserField {
	return map[string]auth.UserField{
		"locale":       {Type: auth.FieldString, Required: true, Column: "preferred_locale"},
		"count":        {Type: auth.FieldNumber, Default: 4},
		"flag":         {Type: auth.FieldBoolean},
		"accountClass": {Type: auth.FieldString, ServerOnly: true, Default: "standard"},
		"privateNote":  {Type: auth.FieldString, Hidden: true},
		"internalRisk": {Type: auth.FieldNumber, ServerOnly: true, Hidden: true, Default: 9},
	}
}
