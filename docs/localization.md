# Localize authentication errors

Add the `plugins/i18n` plugin to send translated error messages to browser and Go clients. Each error retains its HTTP status and stable code. A translated response also includes `originalMessage`, the message the endpoint produced.

```go
import "github.com/Plain-Org/plain-auth/plugins/i18n"

dicts := i18n.Builtins()
dicts["fr"]["INVALID_EMAIL_OR_PASSWORD"] = "Adresse e-mail ou mot de passe incorrect"
messages, err := i18n.New(i18n.Options{
    Translations: dicts,
    DefaultLocale: "en",
    Detection: []i18n.Strategy{i18n.Cookie, i18n.Header},
    LocaleCookie: "lang",
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, messages)
```

`Builtins` returns independently editable dictionaries for Arabic, Bengali, Chinese, Dutch, English, French, German, Hindi, Indonesian, Italian, Japanese, Korean, Persian, Polish, Portuguese, Russian, Spanish, Swedish, Thai, Turkish, Ukrainian and Vietnamese. To load selected locales, pass a map such as `map[string]i18n.Dictionary{"es": dicts["es"], "en": dicts["en"]}`. To add a language or an application error code, add its dictionary or message to the map before calling `New`. Each installation copies its configuration.

## Choose the locale

The first configured strategy that finds an available locale wins. The default strategy reads `Accept-Language`, in quality order, and matches the base language of a regional tag such as `fr-CA`. The cookie strategy reads `locale` by default. The callback strategy invokes `GetLocale` with an `ErrorContext` containing the request and its authenticated user when available.

The session strategy reads the public user field named by `UserLocaleField`, which defaults to `locale`. If your application stores preferences separately, supply `ReadUserLocale(ctx, user, field)` to fetch that field by the verified user's ID. Session detection runs only after the route has authenticated a user. Error rendering does not initiate a session lookup or consume application-key quota.

When no strategy finds a locale, the plugin selects `DefaultLocale`, which defaults to `en`. If that dictionary is absent or the selected dictionary lacks a nonempty translation for the code, the endpoint returns its original error. Errors without a code and successful responses retain their normal format. [Browser contract tests](../conformance/i18n-contract.mjs)

## Read a localized error in Go

```go
var localized *plainauth.LocalizedError
if errors.As(err, &localized) {
    log.Printf("%s: %s", localized.Code, localized.OriginalMessage)
    return showMessage(localized.Message)
}
```

Existing `errors.As(err, &apiErr)` checks with `var apiErr *plainauth.APIError` continue to expose the status, code and message. [Native client tests](../plugins/i18n/i18n_test.go)
