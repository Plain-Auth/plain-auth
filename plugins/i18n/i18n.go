// Package i18n translates coded authentication errors for each request.
package i18n

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	auth "github.com/Plain-Org/plain-auth"
)

// Dictionary maps stable error codes to messages in one locale.
type Dictionary map[string]string

type Strategy string

const (
	Header   Strategy = "header"
	Cookie   Strategy = "cookie"
	Session  Strategy = "session"
	Callback Strategy = "callback"
)

type Options struct {
	Translations    map[string]Dictionary
	DefaultLocale   string
	Detection       []Strategy
	LocaleCookie    string
	UserLocaleField string
	// ReadUserLocale returns the named application profile field for a verified user.
	// When omitted, session detection reads the public JSON field on User.
	ReadUserLocale func(context.Context, auth.User, string) string
	GetLocale      func(auth.ErrorContext) string
}

//go:embed locales.json
var localeData []byte

var builtin = sync.OnceValue(func() map[string]Dictionary {
	var out map[string]Dictionary
	if err := json.Unmarshal(localeData, &out); err != nil {
		panic(err)
	}
	return out
})

// Builtins returns an independently editable copy of all bundled dictionaries.
func Builtins() map[string]Dictionary {
	return clone(builtin())
}

func clone(input map[string]Dictionary) map[string]Dictionary {
	out := make(map[string]Dictionary, len(input))
	for lang, dict := range input {
		out[lang] = maps.Clone(dict)
	}
	return out
}

// New installs the supplied dictionaries. An empty Detection slice uses only DefaultLocale.
func New(opts Options) (auth.Plugin, error) {
	if len(opts.Translations) == 0 {
		return auth.Plugin{}, errors.New("i18n: at least one translation dictionary is required")
	}
	opts.Translations = clone(opts.Translations)
	if opts.DefaultLocale == "" {
		opts.DefaultLocale = "en"
	}
	if opts.Detection == nil {
		opts.Detection = []Strategy{Header}
	} else {
		opts.Detection = slices.Clone(opts.Detection)
	}
	for _, s := range opts.Detection {
		switch s {
		case Header, Cookie, Session, Callback:
		default:
			return auth.Plugin{}, errors.New("i18n: unknown detection strategy")
		}
	}
	if opts.LocaleCookie == "" {
		opts.LocaleCookie = "locale"
	}
	if opts.UserLocaleField == "" {
		opts.UserLocaleField = "locale"
	}
	if opts.ReadUserLocale == nil {
		opts.ReadUserLocale = publicUserLocale
	}
	return auth.Plugin{ID: "i18n", TranslateError: func(c auth.ErrorContext, e auth.APIError) string {
		if e.Code == "" {
			return ""
		}
		return opts.Translations[opts.detect(c)][e.Code]
	}}, nil
}

func publicUserLocale(_ context.Context, u auth.User, field string) string {
	data, err := json.Marshal(u)
	if err != nil {
		return ""
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return ""
	}
	var locale string
	_ = json.Unmarshal(fields[field], &locale)
	return locale
}

func (opts Options) detect(c auth.ErrorContext) string {
	for _, strategy := range opts.Detection {
		var locale string
		switch strategy {
		case Header:
			if c.Request != nil {
				locale = opts.headerLocale(strings.Join(c.Request.Header.Values("Accept-Language"), ","))
			}
		case Cookie:
			if c.Request == nil {
				continue
			}
			for _, cookie := range c.Request.CookiesNamed(opts.LocaleCookie) {
				locale = cookie.Value
			}
			if decoded, err := url.PathUnescape(locale); err == nil {
				locale = decoded
			}
		case Session:
			if c.User != nil {
				ctx := context.Background()
				if c.Request != nil {
					ctx = c.Request.Context()
				}
				locale = opts.ReadUserLocale(ctx, *c.User, opts.UserLocaleField)
			}
		case Callback:
			if opts.GetLocale != nil {
				locale = opts.GetLocale(c)
			}
		}
		if _, known := opts.Translations[locale]; locale != "" && known {
			return locale
		}
	}
	return opts.DefaultLocale
}

func (opts Options) headerLocale(header string) string {
	type preference struct {
		language string
		weight   float64
	}
	var preferred []preference
	for part := range strings.SplitSeq(header, ",") {
		tag, param, weighted := strings.Cut(strings.TrimSpace(part), ";")
		language, _, _ := strings.Cut(strings.TrimSpace(tag), "-")
		if language == "" {
			continue
		}
		q := 1.0
		if weighted {
			param, _, _ = strings.Cut(param, ";")
			var err error
			q, err = strconv.ParseFloat(strings.TrimSpace(strings.Replace(param, "q=", "", 1)), 64)
			if err != nil {
				q = math.NaN()
			}
		}
		preferred = append(preferred, preference{language, q})
	}
	sort.SliceStable(preferred, func(i, j int) bool { return preferred[i].weight > preferred[j].weight })
	for _, lang := range preferred {
		if _, ok := opts.Translations[lang.language]; ok {
			return lang.language
		}
	}
	return ""
}
