# OAuth proxy

[Feature index](../README.md)

## Interfaces

- [ ] OAuth proxy endpoints, types and options
  - [x] Use one registered callback with independent deployments and session stores ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
  - [ ] `GET /callback/:id/oauth-proxy`
    - [x] Consume the originating browser state once and verify the provider before creating the preview session ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L176))
    - [x] Complete a popup across sites and return its session to the trusted opener ([test](../../../conformance/core.test.mjs#L1702))
    - [x] Enforce verification required by the production provider when completing sign-in on a separately configured preview ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L272))
  - [ ] `GET /oauth-proxy-callback`
    - [x] Accept the unqualified return path for a returning account through the released browser client ([test](../../../conformance/core.test.mjs#L1692))
  - [x] `OAuthProxyOptions` ([test](../../../oauth_proxy_test.go#L15))
    - [x] Configure the registered origin, current origin, lifetime and shared key ([test](../../../oauth_proxy_test.go#L15))
    - [x] `currentURL` ([test](../../../oauth_proxy_test.go#L104))
      - [x] Discover a hosting origin or fall back to the configured public URL ([test](../../../oauth_proxy_test.go#L104))
    - [x] `productionURL` ([test](../../../oauth_proxy_test.go#L15))
      - [x] Override the registered origin or load it from the process environment ([test](../../../oauth_proxy_test.go#L15))
    - [x] `maxAge` ([test](../../../oauth_proxy_test.go#L56))
      - [x] Check the profile lifetime and tolerate bounded clock skew ([test](../../../oauth_proxy_test.go#L56))
    - [x] `secret` ([test](../../../oauth_proxy_test.go#L56))
      - [x] Reject wrong-purpose records and honor only keys in the configured ring ([test](../../../oauth_proxy_test.go#L56))
  - [x] `oAuthProxy` ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
    - [x] Install the plugin with separate provider credentials, databases and signing keys ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))

## OAuth Proxy

- [ ] OAuth Proxy
  - [ ] Upgrading existing deployments
  - [x] How it works ([test](../../../conformance/core.test.mjs#L1697))
    - [x] Follow the complete production-to-preview return with host-scoped cookies in Chrome ([test](../../../conformance/core.test.mjs#L1697))
  - [ ] Options
    - [x] productionURL ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L162))
      - [x] Send the production redirect URI and bypass the proxy on production itself ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L162))
    - [x] currentURL ([test](../../../oauth_proxy_test.go#L104))
      - [x] Check all supported host environment fallbacks ([test](../../../oauth_proxy_test.go#L104))
    - [x] maxAge ([test](../../../oauth_proxy_test.go#L56))
      - [x] Accept the configured boundary and reject expired or future-dated profiles ([test](../../../oauth_proxy_test.go#L56))
    - [x] secret ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
      - [x] Complete a flow with shared proxy credentials and per-environment session secrets ([test](../../../adapters/sqlstore/oauth_proxy_test.go#L42))
