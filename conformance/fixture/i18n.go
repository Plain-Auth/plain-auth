package main

import (
	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/i18n"
)

func fixtureI18n() (auth.Plugin, error) {
	dicts := i18n.Builtins()
	dicts["de"]["INVALID_EMAIL_OR_PASSWORD"] = "Custom sign-in message"
	dicts["xx"] = i18n.Dictionary{"INVALID_EMAIL_OR_PASSWORD": "XX sign-in"}
	return i18n.New(i18n.Options{Translations: dicts, DefaultLocale: "de", Detection: []i18n.Strategy{i18n.Cookie, i18n.Session, i18n.Callback, i18n.Header}, LocaleCookie: "lang", UserLocaleField: "name", GetLocale: func(c auth.ErrorContext) string { return c.Request.Header.Get("X-Locale") }})
}
