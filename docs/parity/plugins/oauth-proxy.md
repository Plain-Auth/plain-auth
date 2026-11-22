# OAuth proxy

[Feature index](../README.md)

## Interfaces

- [ ] OAuth proxy endpoints, types and options
  - [x] Use one registered callback with independent deployments and session stores ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
  - [ ] `GET /callback/:id/oauth-proxy`
    - [x] Consume the originating browser state once and verify the provider before creating the preview session ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L171))
    - [x] Complete a popup across sites and return its session to the trusted opener ([test](../../../conformance/core.test.mjs#L1676))
  - [ ] `GET /oauth-proxy-callback`
    - [x] Accept the unqualified return path for a returning account through the released browser client ([test](../../../conformance/core.test.mjs#L1666))
  - [x] `OAuthProxyOptions` ([test](../../../oauth_proxy_test.go#L12))
    - [x] Configure the registered origin, current origin, lifetime and shared key ([test](../../../oauth_proxy_test.go#L12))
    - [x] `currentURL` ([test](../../../oauth_proxy_test.go#L101))
      - [x] Discover a hosting origin or fall back to the configured public URL ([test](../../../oauth_proxy_test.go#L101))
    - [x] `productionURL` ([test](../../../oauth_proxy_test.go#L12))
      - [x] Override the registered origin or load it from the process environment ([test](../../../oauth_proxy_test.go#L12))
    - [x] `maxAge` ([test](../../../oauth_proxy_test.go#L53))
      - [x] Check the profile lifetime and tolerate bounded clock skew ([test](../../../oauth_proxy_test.go#L53))
    - [x] `secret` ([test](../../../oauth_proxy_test.go#L53))
      - [x] Reject wrong-purpose records and honor only keys in the configured ring ([test](../../../oauth_proxy_test.go#L53))
  - [x] `oAuthProxy` ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
    - [x] Install the plugin with separate provider credentials, databases and signing keys ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))

## OAuth Proxy

- [ ] OAuth Proxy
  - [ ] Upgrading existing deployments
  - [x] How it works ([test](../../../conformance/core.test.mjs#L1671))
    - [x] Follow the complete production-to-preview return with host-scoped cookies in Chrome ([test](../../../conformance/core.test.mjs#L1671))
  - [ ] Options
    - [x] productionURL ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L157))
      - [x] Send the production redirect URI and bypass the proxy on production itself ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L157))
    - [x] currentURL ([test](../../../oauth_proxy_test.go#L101))
      - [x] Check all supported host environment fallbacks ([test](../../../oauth_proxy_test.go#L101))
    - [x] maxAge ([test](../../../oauth_proxy_test.go#L53))
      - [x] Accept the configured boundary and reject expired or future-dated profiles ([test](../../../oauth_proxy_test.go#L53))
    - [x] secret ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
      - [x] Complete a flow with shared proxy credentials and per-environment session secrets ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
