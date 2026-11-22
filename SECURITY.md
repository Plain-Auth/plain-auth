# Security reports

For a suspected vulnerability, use **Security → Report a vulnerability** to send the maintainers a private report. Include the affected commit or Go module version, which plugins or stores you enabled, the impact, and the smallest sanitized example that demonstrates the issue. Remove live secrets, cookies, tokens, and personal data. [Report privately on GitHub](https://github.com/Plain-Auth/plain-auth/security/advisories/new)

If GitHub has not enabled the private form for this repository yet, open a [general issue](https://github.com/Plain-Auth/plain-auth/issues/new) asking for a private contact channel. Keep the issue limited to that request. Share the technical details once a private channel is available.

During the developer preview, security fixes land on `main`. Deploy with a currently patched Go toolchain. [Go security policy](https://go.dev/security/policy)

## Dependency review

On November 22, 2026, Go's vulnerability checker reported GO-2026-6909 for the optional SAML integration. Its machine-readable version range is open-ended, while the advisory describes versions through v0.5.1. Plain Auth pins v0.6.3. In that source, the assertion issuer is a value field, the service provider checks it against the configured identity provider, and the subject identifier has an explicit SAML assertion namespace. Recheck the advisory and dependency version when changing SAML support. [Go advisory](https://pkg.go.dev/vuln/GO-2026-6909) · [Pinned assertion types](https://github.com/crewjam/saml/blob/v0.6.3/schema.go#L1158) · [Pinned issuer check](https://github.com/crewjam/saml/blob/v0.6.3/service_provider.go#L2174)
