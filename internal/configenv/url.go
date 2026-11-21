// Package configenv reads settings shared by server and client construction.
package configenv

import "os"

// BaseURL resolves public auth URL aliases common to the native server and
// client. BASE_URL="/" is a framework's relative public asset path.
func BaseURL() string {
	for _, name := range []string{"BETTER_AUTH_URL", "AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL", "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL"} {
		value := os.Getenv(name)
		if value != "" && !(name == "BASE_URL" && value == "/") {
			return value
		}
	}
	return ""
}
