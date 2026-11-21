# Generic OAuth

[Feature index](../README.md)

## Interfaces

- [ ] Generic OAuth endpoints, types and options
  - [ ] `BaseOAuthProviderOptions`
    - [ ] `authorization_endpoint`
    - [ ] `token_endpoint`
    - [ ] `userinfo_endpoint`
    - [ ] `issuer`
    - [ ] `jwks_uri`
    - [ ] `end_session_endpoint`
    - [ ] `id_token_signing_alg_values_supported`
  - [ ] `genericOAuth`
  - [ ] `GenericOAuthUserInfo`
  - [ ] `GenericOAuthOptions`
    - [ ] `config`
  - [ ] `GenericOAuthConfig`

## Generic OAuth

- [ ] Generic OAuth
  - [ ] When to Use This Plugin
    - [ ] Customization Options
      - [ ] Provider uses non-standard token exchange (GET, custom params)
      - [ ] Provider returns a non-standard user profile
      - [ ] You need to map profile fields to your user model
      - [ ] Provider requires extra authorization parameters
      - [ ] Provider requires extra token parameters
      - [ ] Provider requires custom HTTP headers
      - [ ] Provider does not support OIDC discovery
      - [ ] Provider uses a non-standard immutable user identifier
      - [ ] Provider rejects PKCE
  - [ ] Usage
    - [ ] Sign In
    - [ ] Sign In with an ID Token
    - [ ] Link Account
    - [ ] Handle OAuth Callback
  - [ ] Validate OAuth User Info
    - [ ] RP-Initiated Logout
  - [ ] Provider Helpers
  - [ ] Configuration
    - [ ] Manual Configuration
    - [ ] Other Provider Configurations
      - [ ] providerId
      - [ ] accountSubject
      - [ ] discoveryUrl
      - [ ] requireIdTokenVerification
      - [ ] disableIdTokenNonceBinding
      - [ ] authorizationUrl
      - [ ] tokenUrl
      - [ ] userInfoUrl
      - [ ] endSessionEndpoint
      - [ ] postLogoutRedirectURI
      - [ ] disableProviderLogout
      - [ ] clientId
      - [ ] clientSecret
      - [ ] tokenEndpointAuth
      - [ ] scopes
      - [ ] redirectURI
      - [ ] responseType
      - [ ] responseMode
      - [ ] prompt
      - [ ] pkce
      - [ ] accessType
      - [ ] accessTokenExpiresIn
      - [ ] getToken
      - [ ] getUserInfo
      - [ ] mapProfileToUser
      - [ ] authorizationUrlParams
      - [ ] tokenUrlParams
      - [ ] refreshTokenParams
      - [ ] disableImplicitSignUp
      - [ ] disableSignUp
      - [ ] authentication
      - [ ] discoveryHeaders
      - [ ] authorizationHeaders
      - [ ] overrideUserInfo
  - [ ] Advanced Usage
    - [ ] Custom Token Exchange
    - [ ] Custom User Info Fetching
    - [ ] Map User Info Fields
    - [ ] Accessing Raw Token Data
    - [ ] IDP-Initiated Flows
    - [ ] Error Handling
