# Authentication

[Feature index](README.md)

## Apple

- [ ] Apple
  - [ ] Get your OAuth credentials
    - [ ] Navigate to Certificates, Identifiers & Profiles:
    - [ ] Create an App ID:
    - [ ] Create a Service ID:
    - [x] Identifier: Set a unique identifier for the service. Use a reverse domain format, distinct from your App ID (e.g., `com.yourcompany.yourapp.si`, where `.si` indicates service identifier - this is for your organization and not required). This Service ID will be your `clientId`. ([test](../../providers/apple_audiences_test.go#L47))
      - [x] AppleWithOptions keeps the Services ID as the browser client ID when a bundle ID is also configured ([test](../../providers/apple_audiences_test.go#L47))
      - [x] The browser code exchange rejects an ID token issued for the bundle ID and accepts one issued for the Services ID ([test](../../providers/apple_audiences_test.go#L54))
    - [ ] Configure the Service ID:
      - [x] Apple's cross-site form POST to /api/auth/callback/apple is redirected to the same route as a GET, which completes sign-in for the bound browser ([test](../../providers/apple_microsoft_test.go#L116))
      - [x] For a hand-built provider, the redirect_uri sent at sign-in points at /api/auth/callback/local, and the provider double accepts the code exchange only with that same redirect_uri ([test](../../conformance/goapi/oauth_test.go#L141))
    - [x] Create a Client Secret Key: ([test](../../providers/apple_secret_test.go#L41))
      - [x] GenerateAppleClientSecret signs ES256 with the PKCS#8 .p8 key, puts the Key ID in the kid header and the Team ID in iss ([test](../../providers/apple_secret_test.go#L41))
      - [x] GenerateAppleClientSecret refuses, and issues no secret for, a key that is not a single PKCS#8 P-256 PEM block: a P-384 key, a doubled PEM or malformed text, whose text does not appear in the error ([test](../../providers/apple_secret_test.go#L81))
    - [x] Generate the Client Secret (JWT): ([test](../../providers/apple_secret_test.go#L30))
      - [x] Sign the case-sensitive client ID and Apple audience with a PKCS#8 P-256 developer key and verify expiry bounds ([test](../../providers/apple_secret_test.go#L30))
  - [ ] Configure the provider
    - [x] A client secret from GenerateAppleClientSecret reaches Apple's token endpoint as client_secret, where its ES256 signature, kid, issuer, audience and subject verify during the code exchange ([test](../../providers/apple_microsoft_test.go#L64))
    - [x] With AppBundleIdentifier set, an ID token issued for the bundle ID signs in through POST /api/auth/sign-in/social ([test](../../providers/apple_audiences_test.go#L39))
    - [x] NativeAudiences replaces the bundle ID with an explicit audience list, and a multi-audience token needs an azp naming a listed audience ([test](../../providers/apple_audiences_test.go#L82))
    - [ ] Localhost and Non-TLS Restrictions
  - [ ] Usage
    - [x] Sign In with Apple ([test](../../providers/apple_microsoft_test.go#L102))
      - [x] POST /api/auth/sign-in/social with provider apple answers with appleid.apple.com's authorization URL asking for scope email name, response_type code id_token, form_post and a PKCE challenge, and the callback then issues a session ([test](../../providers/apple_microsoft_test.go#L102))
      - [x] `provider` ([test](../../providers/apple_microsoft_test.go#L91))
        - [x] A sign-in/social body with provider "apple" returns status 200 with the Apple authorization URL in Location ([test](../../providers/apple_microsoft_test.go#L91))
    - [ ] Sign In with Apple With ID Token
      - [x] POST /api/auth/sign-in/social with provider apple and idToken {token, nonce} for the bundle ID answers 200 with a session token, the token's email and session cookies ([test](../../providers/apple_audiences_test.go#L80))
      - [x] With the released client against both runtimes, signIn.social with an Apple idToken signs in accepted audiences and answers 401 for others ([test](../../conformance/apple-native.mjs#L37))
  - [x] Generate Apple Client Secret (JWT) ([test](../../providers/apple_secret_test.go#L30))
    - [x] Sign the case-sensitive client ID and Apple audience with a PKCS#8 P-256 developer key and verify expiry bounds ([test](../../providers/apple_secret_test.go#L30))
    - [x] Use the generated assertion during a local Apple authorization code exchange ([test](../../providers/apple_microsoft_test.go#L65))

## Atlassian

- [ ] Atlassian
  - [ ] Get your Credentials
    - [x] In the atlassian subtest, sign-in asks auth.atlassian.com/authorize for scope read:jira-user offline_access ([test](../../providers/catalog_test.go#L162))
    - [x] In the atlassian subtest, the return to /api/auth/callback/atlassian with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
    - [x] For the gumroad, hubspot, line, patreon, slack and yandex presets with BasePath /identity, the authorization URL carries redirect_uri https://app.example/identity/callback/<id>, and the token request must send the same redirect_uri ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] In the atlassian subtest, providers.New("atlassian", id, secret) registered in SocialProviders sends that client ID and secret with the code to the token endpoint ([test](../../providers/catalog_test.go#L79))
  - [x] Sign In with Atlassian ([test](../../providers/catalog_test.go#L203))
    - [x] In the atlassian subtest, POST /api/auth/sign-in/social answers with the Atlassian authorization URL, and after the callback the session user has the mapped Atlassian name, email, image and verification flag ([test](../../providers/catalog_test.go#L203))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] In the atlassian subtest, the sign-in/social body names provider "atlassian" and starts that provider's flow ([test](../../providers/catalog_test.go#L147))

## Cloudflare

- [ ] Cloudflare
  - [ ] Get your Cloudflare credentials
    - [x] In the cloudflare subtest, sign-in starts an authorization-code flow at dash.cloudflare.com/oauth2/auth with scope user-details.read ([test](../../providers/catalog_test.go#L162))
    - [x] In the cloudflare subtest, the code exchange authenticates the client ID and secret with HTTP Basic ([test](../../providers/catalog_test.go#L58))
    - [x] In the cloudflare subtest, the return to /api/auth/callback/cloudflare with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] In the cloudflare subtest, providers.New("cloudflare", id, secret) sends that client ID and secret to the token endpoint, and sign-in requests user-details.read ([test](../../providers/catalog_test.go#L79))
    - [x] In the cloudflare subtest, the profile is read from https://api.cloudflare.com/client/v4/user with the access token as a bearer ([test](../../providers/catalog_test.go#L91))
  - [ ] Usage
    - [x] Sign in with Cloudflare ([test](../../providers/catalog_test.go#L203))
      - [x] In the cloudflare subtest, POST /api/auth/sign-in/social with provider cloudflare answers with the Cloudflare authorization URL, and after the callback the session user has the mapped Cloudflare profile ([test](../../providers/catalog_test.go#L203))
  - [ ] Options
    - [ ] Scopes
      - [x] In the cloudflare subtest, sign-in requests exactly the default user-details.read scope ([test](../../providers/catalog_test.go#L162))
      - [x] Setting the Google preset's Config.Scopes to [openid] replaces its default scopes, and the sign-in and link authorization URLs send scope openid ([test](../../conformance/goapi/provider_contract_test.go#L67))
    - [x] Token authentication method ([test](../../providers/token_auth_test.go#L43))
      - [x] In the cloudflare subtest, with a client secret the code exchange uses HTTP Basic client authentication ([test](../../providers/catalog_test.go#L58))
      - [x] Each catalog provider's refresh, cloudflare's included, uses its listed client authentication style, which is HTTP Basic with the client ID and secret for cloudflare ([test](../../providers/catalog_test.go#L309))
      - [x] The token authentication method selects HTTP Basic or the form secret for Cloudflare's code exchange and refresh ([test](../../providers/token_auth_test.go#L43))
    - [x] Clients without a secret ([test](../../providers/provider_flows_test.go#L195))
      - [x] A Cloudflare client without a secret keeps PKCE, sends neither a client secret nor a Basic header, and refreshes with only client_id, grant_type and refresh_token ([test](../../providers/provider_flows_test.go#L195))
    - [ ] Client visibility
    - [x] Refresh tokens ([test](../../providers/token_auth_test.go#L43))
      - [x] In the cloudflare subtest, sign-in requests only user-details.read, so offline_access is not requested by default ([test](../../providers/catalog_test.go#L162))
      - [x] Each catalog provider with a refresh contract, cloudflare included, refreshes at its token URL with grant_type refresh_token and exactly its listed fields, and returns the new access and refresh tokens ([test](../../providers/catalog_test.go#L283))
      - [x] With offline_access requested, the refresh token from the code exchange refreshes through /refresh-token with the chosen authentication ([test](../../providers/token_auth_test.go#L43))
    - [ ] Profile and email verification
      - [x] In the cloudflare subtest, the /user result maps to a session user named "A Person" from first_name and last_name, with the email, no image and emailVerified false ([test](../../providers/catalog_test.go#L203))
      - [x] In the cloudflare subtest, account-info returns the /user result object as the account data ([test](../../providers/catalog_test.go#L230))

## Cognito

- [ ] Cognito
  - [ ] Get your Cognito Credentials
    - [x] In the cognito subtest, a provider built from a hosted domain, region and user-pool ID sends sign-in to that domain's /oauth2/authorize with scope openid profile email ([test](../../providers/issuer_test.go#L112))
    - [x] In the cognito subtest, the return to /api/auth/callback/cognito with the code and state completes the authorization-code exchange and issues a session ([test](../../providers/issuer_test.go#L115))
  - [ ] Configure the provider
    - [x] Cognito(id, secret, CognitoOptions{Domain, Region, UserPoolID}) signs in through the hosted domain and verifies ID tokens against the pool's cognito-idp issuer and JWKS ([test](../../providers/issuer_test.go#L48))
    - [x] In the cognito subtest, the token request carries the configured client ID and secret with the code ([test](../../providers/issuer_test.go#L60))
  - [ ] Sign In with Cognito
    - [x] In the cognito subtest, POST /api/auth/sign-in/social with provider cognito answers with the hosted authorization URL, with spaces in the scope encoded as %20 ([test](../../providers/issuer_test.go#L107))
  - [ ] Additional Options:
    - [ ] `scope`
      - [x] In the cognito subtest, sign-in requests the default scope openid profile email ([test](../../providers/issuer_test.go#L112))
      - [x] Setting the Google preset's Config.Scopes to [openid] replaces its default scopes, and the sign-in and link authorization URLs send scope openid ([test](../../conformance/goapi/provider_contract_test.go#L41))
    - [x] `openid` ([test](../../providers/issuer_test.go#L121))
      - [x] In the cognito subtest, sign-in requests openid, and the callback fetches the pool's signing keys once to verify the returned ID token before issuing a session ([test](../../providers/issuer_test.go#L121))
    - [x] `profile` ([test](../../providers/issuer_test.go#L135))
      - [x] In the cognito subtest, the session user's name comes from the ID token's given_name when name is empty, and the image from picture ([test](../../providers/issuer_test.go#L135))
    - [x] `email` ([test](../../providers/issuer_test.go#L135))
      - [x] In the cognito subtest, the session user's email and verification flag come from the ID token's email and email_verified claims ([test](../../providers/issuer_test.go#L135))
      - [x] Without an ID token, the Cognito provider's Resolve reads the hosted /oauth2/userinfo with the bearer token and counts email_verified "true" as verified ([test](../../providers/issuer_test.go#L142))
    - [x] `phone` ([test](../../providers/provider_flows_test.go#L245))
      - [x] The phone scope added to the configured or requested scopes reaches the hosted authorize URL ([test](../../providers/provider_flows_test.go#L245))
    - [x] `aws.cognito.signin.user.admin` ([test](../../providers/provider_flows_test.go#L245))
      - [x] The aws.cognito.signin.user.admin scope reaches the hosted authorize URL with %20 between scopes ([test](../../providers/provider_flows_test.go#L245))
    - [ ] `getUserInfo`
      - [x] Without an ID token, the Cognito provider's Resolve reads the hosted /oauth2/userinfo with the bearer token and maps sub, username and the verification flag ([test](../../providers/issuer_test.go#L142))
      - [x] A provider's own Resolve function fetches the profile with the access token, and after the browser sign-in the session user has the email it returned ([test](../../conformance/goapi/oauth_test.go#L177))
    - [x] `identityProvider` ([test](../../providers/provider_flows_test.go#L245))
      - [x] The configured identity provider reaches the hosted authorize URL, and a call can override it ([test](../../providers/provider_flows_test.go#L245))
    - [x] `refreshAccessToken` ([test](../../conformance/provider-credentials.mjs#L70))
      - [x] Through POST /refresh-token, a provider's custom refresh function receives the stored refresh token and its rotated refresh token is returned, matching the other runtime ([test](../../conformance/provider-credentials.mjs#L70))
  - [ ] Refresh tokens
    - [x] Four concurrent GetAccessToken calls for an access token within five seconds of expiry refresh it only once, using the stored refresh token ([test](../../adapters/sqlstore/provider_credentials_test.go#L152))
    - [x] A refresh answered without a new refresh token keeps the stored refresh token and its expiry ([test](../../adapters/sqlstore/provider_credentials_test.go#L215))

## Discord

- [ ] Discord
  - [ ] Get your Discord credentials
    - [x] In the discord subtest, the code exchange sends the configured client ID and secret in the form body ([test](../../providers/catalog_test.go#L79))
    - [x] In the discord subtest, the return to /api/auth/callback/discord with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
    - [x] For the gumroad, hubspot, line, patreon, slack and yandex presets with BasePath /identity, the authorization URL carries redirect_uri https://app.example/identity/callback/<id>, and the token request must send the same redirect_uri ([test](../../providers/profile_presets_test.go#L125))
  - [ ] Configure the provider
    - [x] In the discord subtest, providers.New("discord", id, secret) sends that client ID and secret with the code to the token endpoint ([test](../../providers/catalog_test.go#L79))
    - [x] A provider profile without an email sends the browser to the error callback with error=email_not_found ([test](../../conformance/goapi/oauth_callback_errors_test.go#L108))
  - [ ] Usage
    - [x] Sign In with Discord ([test](../../providers/catalog_test.go#L203))
      - [x] In the discord subtest, sign-in answers with discord.com's authorization URL asking for identify email with prompt none, and after the callback the session user has the global name, the animated avatar URL and the verified email ([test](../../providers/catalog_test.go#L203))
      - [x] `provider` ([test](../../providers/catalog_test.go#L147))
        - [x] In the discord subtest, the sign-in/social body names provider "discord" and starts that provider's flow ([test](../../providers/catalog_test.go#L147))
  - [ ] Options
    - [x] Bot Permissions (Optional) ([test](../../providers/catalog_options_test.go#L107))
      - [x] Discord bot permissions are added to the authorization URL only with the bot scope ([test](../../providers/catalog_options_test.go#L107))

## Dropbox

- [ ] Dropbox
  - [ ] Get your Dropbox credentials
    - [x] In the dropbox subtest, sign-in sends an S256 PKCE challenge and the code exchange must present the matching code_verifier ([test](../../providers/catalog_test.go#L84))
    - [x] In the dropbox subtest, the return to /api/auth/callback/dropbox with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] In the dropbox subtest, providers.New("dropbox", id, secret) sends that client ID and secret with the code to the token endpoint ([test](../../providers/catalog_test.go#L79))
  - [x] Sign In with Dropbox ([test](../../providers/catalog_test.go#L203))
    - [x] In the dropbox subtest, POST /api/auth/sign-in/social answers with the Dropbox authorization URL, and after the callback the session user has the mapped Dropbox profile ([test](../../providers/catalog_test.go#L203))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] In the dropbox subtest, the sign-in/social body names provider "dropbox" and starts that provider's flow ([test](../../providers/catalog_test.go#L147))

## Email & Password

- [ ] Email & Password
  - [x] Enable Email and Password ([test](../../conformance/email-password-options.mjs#L77))
    - [x] With EmailAndPassword off, both runtimes refuse registration and existing-credential sign-in ([test](../../conformance/email-password-options.mjs#L77))
  - [ ] Usage
    - [x] Sign Up ([test](../../conformance/core.test.mjs#L216))
      - [x] Create a password account and return a usable session token on SQLite ([test](../../conformance/core.test.mjs#L198))
      - [x] The released client's signUp.email response and the session it creates match the reference when deep-compared across runtimes ([test](../../conformance/core.test.mjs#L216))
      - [x] `POST /sign-up/email` ([test](../../conformance/goapi/http_test.go#L71))
        - [x] An HTTP POST to sign-up/email with name, email and password returns 200 ([test](../../conformance/goapi/http_test.go#L71))
        - [x] Parameter `name` ([test](../../conformance/existing-signup.mjs#L67))
          - [x] On both runtimes, the stored owner created through sign-up carries the submitted name ([test](../../conformance/existing-signup.mjs#L67))
        - [x] Parameter `email` ([test](../../conformance/core.test.mjs#L199))
          - [x] The sign-up response user has the submitted email, compared against the reference ([test](../../conformance/core.test.mjs#L199))
        - [x] Parameter `password` ([test](../../conformance/email-password-options.mjs#L39))
          - [x] Sign-up enforces the default 8/128 bounds (and configured ones) on the password on both runtimes ([test](../../conformance/email-password-options.mjs#L39))
        - [x] Parameter `image` (optional) ([test](../../conformance/existing-signup.mjs#L68))
          - [x] On both runtimes, the image submitted at sign-up is persisted on the stored owner ([test](../../conformance/existing-signup.mjs#L68))
        - [x] Parameter `callbackURL` (optional) ([test](../../conformance/goapi/account_lifecycle_test.go#L41))
          - [x] A sign-up CallbackURL (via the native SignUpEmail RequestMeta) becomes the verification link's redirect target ([test](../../conformance/goapi/account_lifecycle_test.go#L41))
    - [x] Sign In ([test](../../conformance/goapi/http_test.go#L91))
      - [x] Reject the wrong password and issue a fresh session for valid credentials ([test](../../conformance/core.test.mjs#L207))
      - [x] An HTTP sign-in/email with email, password, rememberMe:false and callbackURL returns the token, redirect:true with the url, a Location header and a browser-session cookie with a dont_remember marker ([test](../../conformance/goapi/http_test.go#L91))
      - [x] `POST /sign-in/email` ([test](../../conformance/goapi/http_test.go#L77))
        - [x] An HTTP POST to sign-in/email returns 200 with a token, session cookies and redirect fields ([test](../../conformance/goapi/http_test.go#L77))
        - [x] Parameter `email` ([test](../../conformance/core.test.mjs#L208))
          - [x] Signing in with the registered email resolves to the same user ID the sign-up created ([test](../../conformance/core.test.mjs#L208))
        - [x] Parameter `password` ([test](../../conformance/core.test.mjs#L1429))
          - [x] A wrong password is rejected with INVALID_EMAIL_OR_PASSWORD on each runtime ([test](../../conformance/core.test.mjs#L1429))
        - [x] Parameter `rememberMe` (optional) ([test](../../conformance/goapi/http_test.go#L83))
          - [x] rememberMe:false issues a session cookie with no Max-Age plus a dont_remember marker cookie ([test](../../conformance/goapi/http_test.go#L83))
        - [x] Parameter `callbackURL` (optional) ([test](../../conformance/goapi/http_test.go#L79))
          - [x] A sign-in callbackURL sets the Location header and returns redirect:true with the url in the body ([test](../../conformance/goapi/http_test.go#L79))
    - [x] Sign Out ([test](../../conformance/core.test.mjs#L211))
      - [x] Clear the client's session cookies and return an anonymous session ([test](../../conformance/core.test.mjs#L211))
      - [x] The released client's signOut returns success, and getSession afterwards is anonymous, matching the reference ([test](../../conformance/core.test.mjs#L211))
      - [x] `POST /sign-out` ([test](../../conformance/core.test.mjs#L211))
        - [x] POST /sign-out through the released client returns {success:true} and clears the session, deep-compared with the reference ([test](../../conformance/core.test.mjs#L211))
    - [ ] Email Verification
      - [x] `user` ([test](../../conformance/goapi/account_test.go#L47))
        - [x] send-verification-email delivers exactly one MailLink whose User.Email is the signed-in account owner's ([test](../../conformance/goapi/account_test.go#L47))
      - [x] `url` ([test](../../conformance/goapi/account_test.go#L54))
        - [x] Following the delivered MailLink.URL verifies the email and 302s to the requested callbackURL ([test](../../conformance/goapi/account_test.go#L54))
      - [x] `token` ([test](../../conformance/email-verification-session.mjs#L7))
        - [x] Each runtime consumes the other's delivered MailLink.Token via verify-email ([test](../../conformance/email-verification-session.mjs#L7))
      - [x] Require Email Verification ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
        - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1467))
        - [x] Return the same default guest and phone fields on fresh and duplicate private registrations ([test](../../adapters/sqlstore/existing_signup_test.go#L271))
        - [x] With RequireEmailVerification, sign-up returns no token and an unverified sign-in fails with EMAIL_NOT_VERIFIED, resending mail ([test](../../conformance/goapi/account_lifecycle_test.go#L15))
      - [ ] Email Enumeration Protection
        - [x] change-email answers an address another account holds exactly like a free one, sends no mail and changes neither account ([test](../../conformance/goapi/change_email_test.go#L189))
        - [x] Plugins that add user fields ([test](../../adapters/sqlstore/existing_signup_test.go#L222))
          - [x] Go adds built-in plugin fields to the synthetic duplicate response automatically ([test](../../adapters/sqlstore/existing_signup_test.go#L222))
          - [x] `coreFields` ([test](../../conformance/synthetic-user.mjs#L5))
            - [x] The hook receives the requested name, the lowercased email, emailVerified false, the image and the timestamps, and the response follows it on both runtimes ([test](../../conformance/synthetic-user.mjs#L5))
          - [x] `additionalFields` ([test](../../conformance/goapi/synthetic_user_test.go#L45))
            - [x] The hook receives the public user fields after defaults, and a hidden field never reaches the response ([test](../../conformance/goapi/synthetic_user_test.go#L45))
          - [x] `id` ([test](../../conformance/goapi/synthetic_user_test.go#L45))
            - [x] The hook receives a fresh ID that differs from the owner's and becomes the response's ID ([test](../../conformance/goapi/synthetic_user_test.go#L45))
      - [x] Triggering manually Email Verification ([test](../../conformance/goapi/account_test.go#L45))
        - [x] A manual POST to send-verification-email with email and callbackURL returns 200 and delivers one link ([test](../../conformance/goapi/account_test.go#L45))
    - [x] Request Password Reset ([test](../../conformance/goapi/mail_request_test.go#L55))
      - [x] Request a password reset over HTTP and deliver the link with a copy of the request ([test](../../conformance/goapi/mail_request_test.go#L55))
      - [x] `user` ([test](../../conformance/goapi/password_reset_hook_test.go#L29))
        - [x] The reset MailLink.User ID and email must equal the account whose password OnPasswordReset reports as reset ([test](../../conformance/goapi/password_reset_hook_test.go#L29))
      - [x] `url` ([test](../../conformance/goapi/account_test.go#L82))
        - [x] Following the delivered reset MailLink.URL 302s to the application's redirect ([test](../../conformance/goapi/account_test.go#L82))
      - [x] `token` ([test](../../conformance/goapi/account_test.go#L89))
        - [x] The delivered MailLink.Token completes POST /reset-password with 200 ([test](../../conformance/goapi/account_test.go#L89))
      - [x] `POST /request-password-reset` ([test](../../conformance/goapi/account_test.go#L72))
        - [x] An HTTP POST to request-password-reset returns 200 and delivers a reset link for a registered account ([test](../../conformance/goapi/account_test.go#L72))
        - [x] Parameter `email` ([test](../../conformance/goapi/account_test.go#L76))
          - [x] Unknown and registered emails get byte-identical responses, and only the registered address receives a delivery ([test](../../conformance/goapi/account_test.go#L76))
        - [x] Parameter `redirectTo` (optional) ([test](../../conformance/goapi/account_test.go#L85))
          - [x] The reset callback redirects to the redirectTo target, keeping its query, with ?token= set to the delivered token ([test](../../conformance/goapi/account_test.go#L85))
      - [x] `newPassword` ([test](../../conformance/goapi/account_test.go#L93))
        - [x] After reset-password with a newPassword, signing in with that new password succeeds ([test](../../conformance/goapi/account_test.go#L93))
      - [x] `POST /reset-password` ([test](../../conformance/core.test.mjs#L254))
        - [x] Go's POST /reset-password consumes a reference-issued token once (200, then 400) ([test](../../conformance/core.test.mjs#L254))
        - [x] Parameter `newPassword` ([test](../../conformance/email-password-options.mjs#L70))
          - [x] newPassword is length-checked before the token is spent on both runtimes ([test](../../conformance/email-password-options.mjs#L70))
        - [x] Parameter `token` ([test](../../conformance/goapi/account_test.go#L96))
          - [x] Under concurrent use a reset token succeeds exactly once and the loser gets INVALID_TOKEN ([test](../../conformance/goapi/account_test.go#L96))
      - [x] Revoking Sessions on Password Reset ([test](../../conformance/goapi/account_test.go#L92))
        - [x] With RevokeSessionsOnPasswordReset on, the previously live session is rejected (401) after a successful reset ([test](../../conformance/goapi/account_test.go#L92))
    - [ ] Update password
      - [x] A signed-in user changes the password over HTTP and receives a replacement session cookie ([test](../../conformance/goapi/account_test.go#L63))
      - [ ] `POST /change-password`
        - [x] The released client's changePassword succeeds against each runtime ([test](../../conformance/core.test.mjs#L1431))
        - [x] Parameter `newPassword` ([test](../../conformance/core.test.mjs#L1433))
          - [x] The newPassword set via change-password becomes the working credential on the other runtime ([test](../../conformance/core.test.mjs#L1433))
        - [x] Parameter `currentPassword` ([test](../../conformance/goapi/account_test.go#L62))
          - [x] change-password with a wrong currentPassword is rejected with 400 ([test](../../conformance/goapi/account_test.go#L62))
        - [ ] Parameter `revokeOtherSessions` (optional)
          - [x] With revokeOtherSessions:true, change-password deletes the caller's and another browser's sessions and returns a replacement token ([test](../../conformance/goapi/database_session_hooks_test.go#L245))
    - [x] Configuration ([test](../../conformance/email-password-options.mjs#L18))
      - [x] On both runtimes the credential is stored in the account table under providerId 'credential', reference scrypt hashes verify, and the length bounds apply to sign-up, password change and reset ([test](../../conformance/email-password-options.mjs#L18))
      - [x] Password ([test](../../conformance/email-password-options.mjs#L54))
        - [x] On both runtimes, the sign-up password is stored in the account table under providerId 'credential' (exactly one row is updated) ([test](../../conformance/email-password-options.mjs#L54))
      - [x] Password Hashing ([test](../../conformance/core.test.mjs#L1401))
        - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1401))
      - [x] Example ([test](../../conformance/core.test.mjs#L1401))
        - [x] A custom hash/verify pair (PBKDF2 in place of the doc's Argon2) via PasswordHash/PasswordVerify interoperates across runtimes for sign-up, sign-in and change-password ([test](../../conformance/core.test.mjs#L1401))
      - [x] `emailPasswordOptionsType.enabled` ([test](../../conformance/email-password-options.mjs#L77))
        - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
      - [x] `emailPasswordOptionsType.disableSignUp` ([test](../../conformance/email-password-options.mjs#L77))
        - [x] Compare disabled email sign-in and closed registration with a pre-existing credential and a fresh browser ([test](../../conformance/email-password-options.mjs#L77))
      - [x] `emailPasswordOptionsType.minPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
        - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
      - [x] `emailPasswordOptionsType.maxPasswordLength` ([test](../../conformance/email-password-options.mjs#L18))
        - [x] Verify inclusive UTF-16 limits on registration, password changes and link recovery, and sign in with an existing shorter password ([test](../../conformance/email-password-options.mjs#L18))
      - [x] `emailPasswordOptionsType.sendResetPassword` ([test](../../client/account_test.go#L125))
        - [x] The configured SendResetPassword receives a token when the client requests a reset ([test](../../client/account_test.go#L125))
      - [x] `emailPasswordOptionsType.onPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L8))
        - [x] Compared with the reference, OnPasswordReset runs once after the credential commit and session revocation, with the request ([test](../../conformance/password-reset-hook.mjs#L8))
      - [x] `emailPasswordOptionsType.onExistingUserSignUp` ([test](../../conformance/core.test.mjs#L1467))
        - [x] Deliver the stored owner to the host while preserving private responses across both modes and ordinary 422 behavior in the released client ([test](../../conformance/core.test.mjs#L1467))
        - [x] Run the callback after storage releases the account, isolate errors and panics, and preserve owned request metadata ([test](../../adapters/sqlstore/existing_signup_test.go#L83))
        - [x] Use one committed owner for concurrent registrations across separate instances and storage connections ([test](../../adapters/sqlstore/existing_signup_test.go#L197))
      - [x] `emailPasswordOptionsType.customSyntheticUser` ([test](../../conformance/synthetic-user.mjs#L5))
        - [x] On both runtimes the hook sets the values of a duplicate sign-up's user fields but cannot add fields a real sign-up lacks ([test](../../conformance/synthetic-user.mjs#L5))
      - [x] `emailPasswordOptionsType.autoSignIn` ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
        - [x] With DisableAutoSignIn, sign-up returns no session token, while a later manual sign-in succeeds ([test](../../conformance/goapi/account_lifecycle_test.go#L54))
      - [x] `emailPasswordOptionsType.requireEmailVerification` ([test](../../conformance/goapi/account_lifecycle_test.go#L34))
        - [x] With RequireEmailVerification, an unverified credential sign-in fails with EMAIL_NOT_VERIFIED and sends a fresh verification mail ([test](../../conformance/goapi/account_lifecycle_test.go#L34))
      - [x] `emailPasswordOptionsType.revokeSessionsOnPasswordReset` ([test](../../conformance/password-reset-hook.mjs#L70))
        - [x] With revokeSessionsOnPasswordReset on, both runtimes have zero sessions left for the user by the time the reset observer runs ([test](../../conformance/password-reset-hook.mjs#L70))
      - [x] `emailPasswordOptionsType.resetPasswordTokenExpiresIn` ([test](../../conformance/goapi/account_test.go#L142))
        - [x] With PasswordResetTokenTTL set to a nanosecond, the delivered reset token is rejected with INVALID_TOKEN ([test](../../conformance/goapi/account_test.go#L142))
      - [x] `emailPasswordOptionsType.password` ([test](../../conformance/core.test.mjs#L1401))
        - [x] Open and replace host-encoded credentials from either runtime in the same account database ([test](../../conformance/core.test.mjs#L1401))

## Facebook

- [ ] Facebook
  - [ ] Get your Facebook credentials
    - [x] In the facebook subtest, the return to /api/auth/callback/facebook with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
    - [x] For the gumroad, hubspot, line, patreon, slack and yandex presets with BasePath /identity, the authorization URL carries redirect_uri https://app.example/identity/callback/<id>, and the token request must send the same redirect_uri ([test](../../providers/profile_presets_test.go#L125))
    - [x] App ID ([test](../../providers/catalog_test.go#L79))
      - [x] In the facebook subtest, the code exchange sends the configured App ID as client_id ([test](../../providers/catalog_test.go#L79))
      - [x] A Facebook access token whose debug_token app_id is another app is rejected ([test](../../providers/catalog_test.go#L254))
    - [x] App Secret ([test](../../providers/catalog_test.go#L122))
      - [x] In the facebook subtest, the token check calls debug_token with the app token "<client id>|<secret>", after the code exchange sent the App Secret as client_secret ([test](../../providers/catalog_test.go#L122))
  - [ ] Configure the provider
    - [x] In the facebook subtest, providers.New("facebook", id, secret) sends that client ID and secret with the code to the token endpoint ([test](../../providers/catalog_test.go#L79))
  - [x] Sign In with Facebook ([test](../../providers/catalog_test.go#L203))
    - [x] In the facebook subtest, sign-in answers with the v24.0 dialog URL, the callback checks the access token with debug_token, and the session user has the Graph profile's name, picture and email ([test](../../providers/catalog_test.go#L203))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] In the facebook subtest, the sign-in/social body names provider "facebook" and starts that provider's flow ([test](../../providers/catalog_test.go#L147))
  - [ ] Additional Configuration
    - [ ] Scopes
      - [ ] `scopes`
        - [x] In the facebook subtest, sign-in requests exactly the default email public_profile scopes ([test](../../providers/catalog_test.go#L162))
        - [x] Setting the Google preset's Config.Scopes to [openid] replaces its default scopes, and the sign-in and link authorization URLs send scope openid ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] `fields` ([test](../../providers/catalog_options_test.go#L43))
        - [x] Extra Graph profile fields are requested after the default ones ([test](../../providers/catalog_options_test.go#L43))
    - [ ] Sign In with Facebook With ID or Access Token
      - [x] A Limited Login ID token is accepted for the App ID or a listed audience with the request's nonce, within the hour, with an unverified email; another audience, issuer, nonce, key, an old token or a missing nonce is refused (deviation: the nonce is required) ([test](../../providers/facebook_test.go#L73))
      - [x] An access token sent as token and accessToken signs in after debug_token binds it to the app and /me names the same user; a Limited Login token for that user and App ID signs into the same account, one for a listed audience as that app's user, one without its nonce is refused, and account-info reads Graph with the stored access token (deviation: never the stored Limited Login claims) ([test](../../providers/facebook_test.go#L113))

## Figma

- [ ] Figma
  - [ ] Get your Credentials
    - [x] In the figma subtest, sign-in asks www.figma.com/oauth for the default scope current_user:read ([test](../../providers/catalog_test.go#L162))
    - [x] In the figma subtest, the return to /api/auth/callback/figma with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] In the figma subtest, providers.New("figma", id, secret) authenticates the code exchange with that client ID and secret over HTTP Basic ([test](../../providers/catalog_test.go#L79))
  - [x] Sign In with Figma ([test](../../providers/catalog_test.go#L203))
    - [x] In the figma subtest, POST /api/auth/sign-in/social answers with the Figma authorization URL, and after the callback the session user has the handle, image and email from the Figma profile ([test](../../providers/catalog_test.go#L203))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] In the figma subtest, the sign-in/social body names provider "figma" and starts that provider's flow ([test](../../providers/catalog_test.go#L147))

## GitHub

- [ ] GitHub
  - [x] Get your GitHub credentials ([test](../../providers/provider_flows_test.go#L94))
    - [x] A GitHub OAuth app signs in through the browser with its client ID and secret and the read:user and user:email scopes ([test](../../providers/provider_flows_test.go#L94))
  - [x] Configure the provider ([test](../../providers/provider_flows_test.go#L94))
    - [x] providers.GitHub registered in SocialProviders sends its client ID and secret in the code exchange ([test](../../providers/provider_flows_test.go#L94))
  - [x] Sign In with GitHub ([test](../../providers/provider_flows_test.go#L94))
    - [x] A browser sign-in through providers.GitHub stores the numeric account ID and the verified primary email ([test](../../providers/provider_flows_test.go#L94))
    - [x] `provider` ([test](../../providers/provider_flows_test.go#L94))
      - [x] Posting provider github to /sign-in/social starts the GitHub authorization ([test](../../providers/provider_flows_test.go#L94))
  - [ ] Usage
    - [x] Setting up your Github app ([test](../../providers/provider_flows_test.go#L157))
      - [x] When GitHub refuses the email list, a user without a public email gets email_not_found and no session, and a public email signs in unverified ([test](../../providers/provider_flows_test.go#L157))
    - [x] Why don't I have a refresh token? ([test](../../providers/provider_flows_test.go#L94))
      - [x] A token response without a refresh token or expiry is kept as it is: get-access-token returns it without an expiry and refresh-token answers REFRESH_TOKEN_NOT_FOUND ([test](../../providers/provider_flows_test.go#L94))

## GitLab

- [ ] GitLab
  - [ ] Get your GitLab credentials
    - [x] In the gitlab subtest, the code exchange sends the configured client ID and secret in the form body ([test](../../providers/catalog_test.go#L79))
    - [x] In the gitlab subtest, the return to /api/auth/callback/gitlab with the code and state completes the exchange and issues a session ([test](../../providers/catalog_test.go#L180))
  - [ ] Configure the provider
    - [x] In the gitlab subtest, providers.New("gitlab", id, secret) sends that client ID and secret with the code to gitlab.com's token endpoint ([test](../../providers/catalog_test.go#L79))
    - [ ] Configuration Options
      - [x] `clientId` ([test](../../providers/catalog_test.go#L80))
        - [x] For gitlab, as for every catalog provider, the code exchange carries the client ID given to providers.New, with grant_type authorization_code and the callback's code ([test](../../providers/catalog_test.go#L80))
      - [x] `clientSecret` ([test](../../providers/catalog_test.go#L80))
        - [x] For gitlab, as for every catalog provider, the code exchange carries the client secret given to providers.New ([test](../../providers/catalog_test.go#L80))
      - [x] `issuer` ([test](../../providers/catalog_options_test.go#L43))
        - [x] An issuer for a self-managed instance is used for every GitLab endpoint, and gitlab.com without one ([test](../../providers/catalog_options_test.go#L43))
    - [x] Example with self-hosted GitLab ([test](../../providers/catalog_options_test.go#L43))
      - [x] A self-hosted GitLab at https://gitlab.company.com gets its authorize, token, profile and refresh endpoints there ([test](../../providers/catalog_options_test.go#L43))
  - [x] Sign In with GitLab ([test](../../providers/catalog_test.go#L187))
    - [x] For gitlab and each other catalog provider, sign-in/social followed by the provider callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (gitlab among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))

## Google

- [ ] Google
  - [ ] Get your Google credentials
    - [x] Starting sign-in/social for the provider registered as google on each of two deployments sends redirect_uri <BaseURL>/identity/callback/google ([test](../../adapters/sqlstore/oauth_proxy_test.go#L194))
    - [x] A social sign-in started on host b.example sends redirect_uri https://b.example/api/auth/callback/local under the default mount ([test](../../conformance/goapi/dynamic_base_url_test.go#L342))
    - [ ] Creating Your Google OAuth Credentials
    - [ ] `http://localhost:3000/api/auth/callback/google`
      - [x] A social sign-in started on host b.example sends redirect_uri https://b.example/api/auth/callback/local under the default mount ([test](../../conformance/goapi/dynamic_base_url_test.go#L342))
      - [x] Starting sign-in/social for the provider registered as google sends redirect_uri <BaseURL>/identity/callback/google ([test](../../adapters/sqlstore/oauth_proxy_test.go#L194))
    - [ ] `https://your-domain.com/api/auth/callback/google`
      - [x] On HTTPS deployments, starting sign-in/social for the provider registered as google sends redirect_uri <BaseURL>/identity/callback/google ([test](../../adapters/sqlstore/oauth_proxy_test.go#L194))
      - [x] A social sign-in started on host b.example sends redirect_uri https://b.example/api/auth/callback/local under the default mount ([test](../../conformance/goapi/dynamic_base_url_test.go#L342))
  - [ ] Configure the provider
    - [x] providers.Google refuses an ID token whose audience is not the configured client ID ([test](../../providers/providers_test.go#L32))
    - [x] With providers.Google("client", "secret") registered as google, sign-in/social answers an authorization URL carrying the configured scope and prompt ([test](../../conformance/goapi/provider_contract_test.go#L67))
    - [ ] Important: Set Your Base URL
      - [x] With BaseURL set per deployment, the google authorization request's redirect_uri is that BaseURL plus /identity/callback/google ([test](../../adapters/sqlstore/oauth_proxy_test.go#L194))
      - [x] With AUTH_SECRET set but neither BaseURL nor AUTH_URL (other URL variables such as BASE_URL are ignored), New refuses to start ([test](../../env_test.go#L63))
    - [x] Option 1: Environment Variable (Recommended) ([test](../../env_test.go#L31))
      - [x] With BaseURL unset, AUTH_URL=https://auth.test/v1/login sets the base URL https://auth.test and the base path /v1/login ([test](../../env_test.go#L31))
    - [x] Option 2: Explicit Configuration ([test](../../env_test.go#L42))
      - [x] An explicit Options.BaseURL and BasePath take precedence over AUTH_URL ([test](../../env_test.go#L42))
      - [x] Without BaseURL or AUTH_URL, New refuses to start instead of falling back to a default origin ([test](../../env_test.go#L63))
  - [ ] Usage
    - [ ] Sign In with Google
      - [x] With providers.Google registered as google, sign-in/social with provider google answers an authorization URL ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] `provider` ([test](../../conformance/goapi/provider_contract_test.go#L67))
        - [x] Posting provider google to sign-in/social starts that provider's authorization and answers its URL ([test](../../conformance/goapi/provider_contract_test.go#L67))
    - [ ] Sign In with Google With ID Token
      - [x] sign-in/social with idToken {token, nonce} for google signs the user in directly with a session cookie, using a replaced VerifyIDToken ([test](../../conformance/goapi/provider_contract_test.go#L93))
      - [x] The Google provider's Resolve accepts a code-exchange ID token signed by its key with issuer https://accounts.google.com, the client ID as audience and the flow nonce, and refuses a wrong issuer, audience or nonce ([test](../../providers/providers_test.go#L19))
    - [x] Cross-Platform Sign In (Web, iOS, Android) ([test](../../providers/google_test.go#L86))
      - [x] Web, iOS and Android client IDs are accepted for directly submitted ID tokens, including an Android token whose audience is the web ID and whose authorized party is the Android ID ([test](../../providers/google_test.go#L86))
    - [ ] Restrict Sign-In to Google Workspace
      - [x] With GoogleOptions.HostedDomain example.org, One Tap refuses ID tokens whose hd claim is elsewhere.org or missing (among other bad claims) ([test](../../adapters/sqlstore/onetap_test.go#L149))
      - [x] With HostedDomain *, One Tap accepts another Workspace domain and refuses a token without an hd claim ([test](../../adapters/sqlstore/onetap_test.go#L184))
      - [x] On an OAuth proxy preview with GoogleHostedDomain social.test, a google profile whose hd is elsewhere.test is refused with INVALID_TOKEN ([test](../../adapters/sqlstore/oauth_proxy_test.go#L316))
    - [x] Always ask to select an account ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] AuthorizationParams prompt=select_account consent on providers.Google appears on the sign-in authorization URL ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] The same prompt appears on the link-social authorization URL ([test](../../conformance/goapi/provider_contract_test.go#L95))
    - [ ] Requesting Additional Google Scopes
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
      - [x] Re-linking an identity the user owns merges the new grant's scopes into the stored account scope (profile,email plus write) ([test](../../adapters/sqlstore/oauth_account_update_test.go#L88))
    - [x] Disable incremental authorization ([test](../../providers/google_test.go#L60))
      - [x] Incremental authorization is on by default through include_granted_scopes=true and DisableIncludeGrantedScopes turns it off ([test](../../providers/google_test.go#L60))
    - [x] Always get refresh token ([test](../../providers/google_test.go#L60))
      - [x] AuthorizationParams prompt=select_account consent on providers.Google appears on the sign-in authorization URL (access_type=offline is not asserted) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] AccessType offline with prompt select_account consent puts access_type=offline and the prompt on the sign-in authorization URL ([test](../../providers/google_test.go#L60))
    - [ ] Restricting to a Google Workspace domain
      - [x] On both runtimes, additionalParams on sign-in/social and link-social reach the authorization URL (prompt consent, ui_locales fr) ([test](../../conformance/social-signup.mjs#L57))

## Hugging Face

- [ ] Hugging Face
  - [ ] Get your Hugging Face credentials
    - [x] For huggingface and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] The huggingface authorization URL requests its default scopes, email among them ([test](../../providers/catalog_test.go#L162))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("huggingface", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with Hugging Face ([test](../../providers/catalog_test.go#L187))
    - [x] For huggingface and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (huggingface among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))

## Kakao

- [ ] Kakao
  - [ ] Get your Kakao Credentials
    - [x] For kakao, as for every catalog provider, the code exchange carries the client ID and secret given to providers.New ([test](../../providers/catalog_test.go#L80))
    - [x] For kakao and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("kakao", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with Kakao ([test](../../providers/catalog_test.go#L187))
    - [x] For kakao and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
  - [ ] Usage
    - [ ] Sign In with Kakao using ID Token
      - [x] A Kakao SDK ID token signs in for the REST API key or a listed native app key with its nonce, as the account the profile endpoint names, with an unverified email; another audience, issuer or nonce and a non-numeric subject are refused (deviation: the nonce is required) ([test](../../providers/kakao_test.go#L21))
  - [ ] Options
    - [ ] Scopes
      - [x] The kakao authorization URL requests exactly its default scopes account_email, profile_image and profile_nickname ([test](../../providers/catalog_test.go#L162))
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))

## Kick

- [ ] Kick
  - [ ] Get your Kick Credentials
    - [x] For kick and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] For kick, as for every catalog provider, the code exchange carries the client ID and secret given to providers.New ([test](../../providers/catalog_test.go#L80))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("kick", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with Kick ([test](../../providers/catalog_test.go#L187))
    - [x] For kick and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (kick among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))

## LINE

- [ ] LINE
  - [x] Get your LINE credentials ([test](../../providers/profile_presets_test.go#L125))
    - [x] For the LINE channel preset registered as line under BasePath /identity, the authorization URL sends redirect_uri <BaseURL>/identity/callback/line, scopes openid profile email and an S256 challenge ([test](../../providers/profile_presets_test.go#L125))
    - [x] The LINE channel's code exchange posts the configured channel ID and secret, the code, the same redirect_uri and the PKCE verifier ([test](../../providers/profile_presets_test.go#L77))
  - [ ] Configure the provider
    - [x] The LINE channel's code exchange posts the client ID and secret given to the provider constructor ([test](../../providers/profile_presets_test.go#L77))
    - [x] A provider's Config.RedirectURL replaces the callback route in both the authorization request and the code exchange ([test](../../conformance/goapi/oauth_redirect_uri_test.go#L96))
    - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
  - [ ] Usage
    - [x] Sign In with LINE ([test](../../providers/profile_presets_test.go#L140))
      - [x] With the LINE channel registered as line, sign-in/social then the callback answers 302 with a session whose user has the profile's email and unverified status ([test](../../providers/profile_presets_test.go#L140))
      - [x] For the line catalog entry and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [ ] Sign In with LINE using ID Token (optional)
      - [x] A LINE ID token signs in directly at LINE() and New("line") once LINE's verify endpoint accepts it for that channel with the nonce, sending only the client ID, token and nonce; a request without a nonce never reaches LINE (deviation: the nonce is required), a token LINE refuses answers INVALID_TOKEN, and New("line") hands hooks the raw verified claims ([test](../../providers/line_test.go#L186))
    - [ ] Notes
      - [x] providers.LINE verifies a code-flow ID token by POSTing it as a form, without an Authorization header, to https://api.line.me/oauth2/v2.1/verify ([test](../../providers/line_test.go#L43))
      - [x] providers.LINE refuses a verified ID token issued for another channel, another nonce or another issuer, or with a bad expiry, issue time or empty subject ([test](../../providers/line_test.go#L75))
      - [x] The LINE channel's authorization URL requests the default scopes openid profile email ([test](../../providers/profile_presets_test.go#L125))
  - [x] Multi-Channel Support ([test](../../providers/line_test.go#L234))
    - [x] Two LINE channels under their own keys keep their own client IDs, secrets, callbacks and account namespaces: a LINE user ID is a separate account per key, the same unverified email at a second key answers account_not_linked, a state from one key fails at the other's callback, and a direct ID token works only at its own channel's key ([test](../../providers/line_test.go#L234))

## Linear

- [ ] Linear
  - [ ] Get your Linear credentials
    - [x] For linear and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] The linear authorization URL requests exactly its default scope read ([test](../../providers/catalog_test.go#L162))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("linear", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with Linear ([test](../../providers/catalog_test.go#L187))
    - [x] For linear and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (linear among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))
  - [ ] Available scopes
    - [x] The linear authorization URL requests exactly its default scope read ([test](../../providers/catalog_test.go#L162))
    - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
    - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
    - [x] `read` ([test](../../providers/catalog_test.go#L162))
      - [x] The linear authorization URL requests exactly its default scope read ([test](../../providers/catalog_test.go#L162))
    - [ ] `write`
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
    - [ ] `issues:create`
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
    - [ ] `comments:create`
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
    - [ ] `timeSchedule:write`
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))
    - [ ] `admin`
      - [x] Replacing a provider's Config.Scopes sends exactly those scopes on the sign-in authorization URL (shown with providers.Google and scope openid) ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, sign-in/social and link-social with scopes [contacts] request the provider's default scope plus contacts ([test](../../conformance/social-signup.mjs#L54))

## LinkedIn

- [ ] LinkedIn
  - [ ] Get your LinkedIn credentials
    - [x] For linkedin and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] The linkedin authorization URL requests its default OpenID Connect scopes profile, email and openid ([test](../../providers/catalog_test.go#L162))
  - [ ] Configure the provider
    - [x] providers.New("linkedin", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with LinkedIn ([test](../../providers/catalog_test.go#L187))
    - [x] For linkedin and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (linkedin among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))

## Microsoft

- [ ] Microsoft
  - [x] Get your Microsoft credentials ([test](../../providers/microsoft_test.go#L243))
    - [x] A registered Microsoft app signs in through the browser with its client ID and secret ([test](../../providers/microsoft_test.go#L40))
    - [x] A Microsoft app with a client assertion credential instead of a secret signs in through the registered callback URL, sent on the authorization and the code exchange, with an assertion naming its certificate ([test](../../providers/microsoft_test.go#L243))
  - [ ] Configure the provider
    - [x] The Microsoft provider's ID-token check refuses consumer-tenant tokens in organizations mode and organization-tenant tokens in consumers mode, refuses a token whose issuer names a different tenant than its tid, and accepts matching tokens in organizations, consumers, common and tenant-GUID modes ([test](../../providers/apple_microsoft_test.go#L166))
    - [x] Authority URL ([test](../../providers/microsoft_test.go#L40))
      - [x] An External ID authority with a tenant GUID completes a browser sign-in against that authority's endpoints and keys ([test](../../providers/microsoft_test.go#L40))
    - [x] Client assertions ([test](../../providers/microsoft_test.go#L243))
      - [x] A client assertion authenticates Microsoft's code exchange and refresh instead of a client secret; PrivateKeyJWT with the certificate signs one with the token endpoint as audience and the x5t#S256 thumbprint ([test](../../providers/microsoft_test.go#L243))
  - [ ] Account identifiers
    - [x] A verified Microsoft ID token maps to the oid claim as the account subject, not the pairwise sub ([test](../../providers/apple_microsoft_test.go#L170))
    - [x] A single-tenant Entra provider uses the oid claim as the subject for both the code-flow and the native ID token ([test](../../providers/entra_test.go#L84))
  - [x] Large Profile Images ⚠️ ([test](../../providers/microsoft_test.go#L161))
    - [x] The Graph photo is stored as a data URI only up to 1 MiB, and DisableProfilePhoto skips it ([test](../../providers/microsoft_test.go#L161))
  - [ ] Sign In with Microsoft
    - [x] A browser sign-in through providers.Microsoft completes the callback against the v2.0 authorize and token endpoints with PKCE and the client secret ([test](../../providers/microsoft_test.go#L40))
    - [x] `provider` ([test](../../providers/microsoft_test.go#L40))
      - [x] Posting provider microsoft to /sign-in/social starts the Microsoft authorization with its scopes, client ID, PKCE and nonce ([test](../../providers/microsoft_test.go#L40))
    - [ ] Preselecting an organizational domain
      - [x] On both runtimes, additionalParams on sign-in/social and link-social reach the authorization URL (prompt consent, ui_locales fr) ([test](../../conformance/social-signup.mjs#L57))

## Naver

- [ ] Naver
  - [ ] Get your Naver Credentials
    - [x] For naver and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] For naver, as for every catalog provider, the code exchange carries the client ID and secret given to providers.New ([test](../../providers/catalog_test.go#L80))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("naver", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [x] Sign In with Naver ([test](../../providers/catalog_test.go#L187))
    - [x] For naver and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social with provider set to a catalog ID (naver among them) answers 200 with a Location at that provider's authorization endpoint, requesting exactly its default scopes ([test](../../providers/catalog_test.go#L162))

## Notion

- [ ] Notion
  - [ ] Get your Notion credentials
    - [x] For notion and each other catalog provider, the test returns the provider's code to <BaseURL>/api/auth/callback/<id> with the flow's state and cookies ([test](../../providers/catalog_test.go#L180))
    - [x] For notion, as for every catalog provider, the code exchange carries the client ID and secret given to providers.New ([test](../../providers/catalog_test.go#L80))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L80))
    - [x] providers.New("notion", clientID, secret) in SocialProviders sends that client ID and secret on the code exchange ([test](../../providers/catalog_test.go#L80))
  - [ ] Usage
    - [x] Sign In with Notion ([test](../../providers/catalog_test.go#L187))
      - [x] For notion and each other catalog provider, sign-in/social followed by the callback exchanges the code once, reads the profile once and answers 302 with a session ([test](../../providers/catalog_test.go#L187))
      - [x] `provider` ([test](../../providers/catalog_test.go#L162))
        - [x] POST /sign-in/social with each catalog provider's name, notion included, redirects to that provider's own authorization endpoint and asks for its default scopes ([test](../../providers/catalog_test.go#L162))
    - [ ] Notion Integration Types
      - [ ] Public integrations
        - [x] The notion preset's authorization URL carries owner=user. The test checks every fixed authorization parameter of each catalog preset ([test](../../providers/catalog_test.go#L167))
        - [x] For each catalog preset, notion included, the browser sign-in gives a user whose email, verification, name and image match the preset's sample profile ([test](../../providers/catalog_test.go#L203))
      - [ ] Internal integrations
    - [ ] Requesting Additional Notion Scopes
      - [x] On both runtimes, linkSocial and signIn.social with extra scopes for a configured provider ask for the configured and the extra scopes together in the authorization URL ([test](../../conformance/social-signup.mjs#L54))
      - [x] Go's /link-social for a signed-in user with a preset asks for the preset's configured scopes and prompt in the authorization URL ([test](../../conformance/goapi/provider_contract_test.go#L96))

## Other Social Providers

- [ ] Other Social Providers
  - [ ] Provider Helpers
    - [ ] Built-in Provider Helpers
      - [x] Auth0 ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Auth0, given a mixed-case tenant domain, discovers that tenant's endpoints and sends the browser there with openid profile email, a nonce and S256 PKCE. It signs in with the tenant-signed ID token under a custom base path and refuses a token from another issuer ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Auth0 refuses an empty domain, an http origin, embedded credentials, a path or a query without making any discovery request ([test](../../providers/enterprise_oidc_test.go#L129))
        - [x] The other runtime's auth0 helper, given the same tenant domain, derives the same discovery URL and the default scopes openid profile email ([test](../../conformance/enterprise-oidc.test.mjs#L6))
      - [x] Gumroad ([test](../../providers/profile_presets_test.go#L32))
        - [x] The gumroad preset completes a browser sign-in under a custom base path with its endpoints, default scope, S256 PKCE and form credentials. The linked account keeps the mapped profile and the Gumroad user ID as its subject ([test](../../providers/profile_presets_test.go#L32))
        - [x] The other runtime's gumroad helper has the same endpoints and default scopes, and maps the same sample profile to the same fields and subject ([test](../../conformance/profile-presets.test.mjs#L6))
      - [x] HubSpot ([test](../../providers/profile_presets_test.go#L32))
        - [x] The hubspot preset asks for the oauth scope and reads the profile by token introspection with the client credentials. It links the account under the HubSpot user ID ([test](../../providers/profile_presets_test.go#L32))
        - [x] The hubspot preset refuses an introspected token that is inactive, belongs to another client or is a refresh token, and keeps the email unverified ([test](../../providers/profile_presets_test.go#L193))
        - [x] The other runtime's hubspot helper has the same authorization URL and default oauth scope, and maps the same sample profile to the same fields and subject. Its token and token-lookup URLs are the older v1 ones, not the Go preset's ([test](../../conformance/profile-presets.test.mjs#L6))
      - [x] Keycloak ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Keycloak, given a realm issuer with a trailing slash, discovers the realm's endpoints, signs in with an ID token that realm signed and refuses a token from another issuer ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Keycloak refuses an issuer without https, with a fragment or with a query, without making any discovery request ([test](../../providers/enterprise_oidc_test.go#L134))
        - [x] The other runtime's keycloak helper, given the same issuer, derives the same discovery URL and the default scopes openid profile email ([test](../../conformance/enterprise-oidc.test.mjs#L6))
      - [ ] LINE
        - [x] providers.LINE verifies ID tokens at LINE's verify endpoint for its channel. It refuses another channel, another browser nonce, an unknown issuer, an expired or unissued token and an empty user ID ([test](../../providers/line_test.go#L22))
        - [x] Registered under the name line, the LINE channel preset completes a browser sign-in from its profile endpoint and links the account under the LINE user ID ([test](../../providers/profile_presets_test.go#L32))
        - [x] The other runtime's line helper has the same endpoints and default scopes, and maps the same sample profile to the same fields and subject ([test](../../conformance/profile-presets.test.mjs#L6))
        - [x] Two LINE channels under their own keys keep their own client IDs, secrets, callbacks and account namespaces: a LINE user ID is a separate account per key, the same unverified email at a second key answers account_not_linked, a state from one key fails at the other's callback, and a direct ID token works only at its own channel's key ([test](../../providers/line_test.go#L234))
      - [x] Microsoft Entra ID (Azure AD) ([test](../../providers/entra_test.go#L20))
        - [x] providers.MicrosoftEntraID for a tenant GUID asks for openid profile email at that tenant and keys accounts by the signed oid. It merges Graph fields only when the subject matches, and refuses tokens without an oid, from another tenant or for another audience ([test](../../providers/entra_test.go#L20))
        - [x] The other runtime's microsoftEntraId helper, run on the same fixtures, derives the same tenant discovery URL and scopes, refuses the common tenant, and maps the same subject, email, name and verification ([test](../../conformance/entra-profiles.test.mjs#L6))
      - [x] Okta ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Okta, for both a custom authorization server issuer and an organization issuer, discovers its endpoints, signs in with an ID token it signed and refuses a token from another issuer ([test](../../providers/enterprise_oidc_test.go#L23))
        - [x] providers.Okta refuses an issuer without https, with a fragment or with a query, without making any discovery request ([test](../../providers/enterprise_oidc_test.go#L137))
        - [x] The other runtime's okta helper, given the same issuers, derives the same discovery URLs and the default scopes openid profile email ([test](../../conformance/enterprise-oidc.test.mjs#L6))
      - [x] Patreon ([test](../../providers/profile_presets_test.go#L32))
        - [x] The patreon preset completes a browser sign-in under a custom base path with its endpoints, identity[email] scope, S256 PKCE and form credentials. The linked account keeps the mapped identity and the Patreon user ID ([test](../../providers/profile_presets_test.go#L32))
        - [x] The other runtime's patreon helper has the same endpoints and default scopes, and maps the same sample profile to the same fields and subject ([test](../../conformance/profile-presets.test.mjs#L6))
      - [x] Slack ([test](../../providers/profile_presets_test.go#L32))
        - [x] Registered as slack, the Slack OpenID preset asks for openid profile email, reads userinfo by an authenticated POST, and links the account under the sub claim with its verification ([test](../../providers/profile_presets_test.go#L32))
        - [x] The other runtime's slack helper has the same endpoints and default scopes, and maps the same sample profile to the same fields and subject ([test](../../conformance/profile-presets.test.mjs#L6))
      - [x] Yandex ([test](../../providers/profile_presets_test.go#L32))
        - [x] The yandex preset asks for login:info login:email login:avatar, reads the profile with an OAuth-scheme Authorization header, and links the account under the Yandex ID ([test](../../providers/profile_presets_test.go#L32))
        - [x] The other runtime's yandex helper has the same endpoints and default scopes, and maps the same sample profile to the same fields and subject ([test](../../conformance/profile-presets.test.mjs#L6))
      - [x] Microsoft Entra ID ([test](../../providers/entra_test.go#L52))
        - [x] providers.MicrosoftEntraID refuses an empty, common, consumers, organizations or malformed tenant, and accepts a tenant GUID in upper case ([test](../../providers/entra_test.go#L52))
        - [x] The Microsoft provider in organizations, consumers or single-tenant mode accepts only ID tokens whose tenant and issuer fit that authority ([test](../../providers/apple_microsoft_test.go#L157))
        - [x] The other runtime's microsoftEntraId helper also throws for the common tenant ([test](../../conformance/entra-profiles.test.mjs#L6))
      - [x] `clientId` ([test](../../providers/profile_presets_test.go#L77))
        - [x] Each profile preset (gumroad, hubspot, patreon, slack, yandex, LINE) sends the configured client ID and secret as form fields in its code exchange, together with the redirect URI and PKCE verifier ([test](../../providers/profile_presets_test.go#L77))
        - [x] The Auth0, Keycloak and Okta helpers send the configured client ID and secret by HTTP Basic in the code exchange ([test](../../providers/enterprise_oidc_test.go#L51))
      - [x] `clientSecret` ([test](../../providers/profile_presets_test.go#L77))
        - [x] Each profile preset (gumroad, hubspot, patreon, slack, yandex, LINE) sends the configured client secret as a form field in its code exchange ([test](../../providers/profile_presets_test.go#L77))
        - [x] The Auth0, Keycloak and Okta helpers send the configured client secret by HTTP Basic in the code exchange ([test](../../providers/enterprise_oidc_test.go#L51))
      - [ ] `tokenEndpointAuth`
        - [x] The helper presets that keep the standard token requests take each TokenEndpointAuth method, and Notion, VK, TikTok and WeChat refuse one; Auth0, Keycloak and Okta are not yet exercised ([test](../../providers/token_auth_test.go#L202))
      - [x] `scopes` ([test](../../conformance/goapi/provider_contract_test.go#L68))
        - [x] Replacing a preset's Config.Scopes puts exactly the new list in the sign-in authorization URL, without the preset's defaults ([test](../../conformance/goapi/provider_contract_test.go#L68))
        - [x] Each profile preset's authorization URL asks for that preset's default scopes, with the redirect URI under the custom base path and S256 PKCE ([test](../../providers/profile_presets_test.go#L125))
        - [x] The Auth0, Keycloak and Okta helpers ask for openid profile email, with a nonce and S256 PKCE ([test](../../providers/enterprise_oidc_test.go#L95))
      - [x] `redirectURI` ([test](../../conformance/goapi/oauth_redirect_uri_test.go#L22))
        - [x] A provider's Config.RedirectURL replaces the callback route in the authorization request and the code exchange, an application route forwards it to the callback, and a relative or non-HTTP URL is refused ([test](../../conformance/goapi/oauth_redirect_uri_test.go#L22))
        - [x] Without a RedirectURL, each profile preset sends redirect_uri https://app.example/identity/callback/<name> under BasePath /identity ([test](../../providers/profile_presets_test.go#L125))
      - [x] `pkce` ([test](../../providers/catalog_test.go#L178))
        - [x] Catalog presets whose definition turns PKCE off (DisablePKCE) send no code_challenge in the authorization URL, and the others send one ([test](../../providers/catalog_test.go#L178))
        - [x] A catalog preset with PKCE off sends no code_verifier in its code exchange ([test](../../providers/catalog_test.go#L88))
        - [x] With PKCE on, the code_verifier in the code exchange hashes to the S256 challenge from the authorization URL ([test](../../providers/catalog_test.go#L85))
      - [x] `disableImplicitSignUp` ([test](../../conformance/goapi/oauth_signup_test.go#L118))
        - [x] With DisableImplicitSignUp, a new account is refused unless requestSignUp is sent, and created when it is ([test](../../conformance/goapi/oauth_signup_test.go#L118))
      - [x] `disableSignUp` ([test](../../conformance/goapi/oauth_signup_test.go#L132))
        - [x] A provider with DisableSignUp refuses to create a new account even when sign-up is explicitly requested, for both browser and ID-token sign-in ([test](../../conformance/goapi/oauth_signup_test.go#L132))
      - [x] `overrideUserInfo` ([test](../../conformance/social-user-fields.mjs#L145))
        - [x] With profile override on, a returning sign-in through either runtime rewrites the same user's name, email, image and mapped input fields from the new provider profile. It keeps fields the provider left out and the verified status of an unchanged email, and takes the provider's verification when the email changes. A Go sign-in whose new email belongs to another user is refused with profile_conflict and changes nothing ([test](../../conformance/social-user-fields.mjs#L145))
      - [x] `endSessionEndpoint` ([test](../../conformance/goapi/oauth_logout_test.go#L70))
        - [x] Provider sign-out sends the browser to the provider's EndSessionEndpoint, keeping that endpoint's own query, with id_token_hint, client_id, state and post_logout_redirect_uri added ([test](../../conformance/goapi/oauth_logout_test.go#L70))
        - [x] The Auth0, Keycloak and Okta helpers set EndSessionEndpoint from the issuer's discovered end_session_endpoint ([test](../../providers/enterprise_oidc_test.go#L71))
      - [x] `postLogoutRedirectURI` ([test](../../conformance/goapi/oauth_logout_test.go#L70))
        - [x] Provider sign-out sends the provider's PostLogoutRedirectURI, resolved against the base URL, as post_logout_redirect_uri, unless the request names its own callbackURL ([test](../../conformance/goapi/oauth_logout_test.go#L70))
        - [x] A provider sign-out whose callbackURL is on a foreign origin is refused ([test](../../conformance/goapi/oauth_logout_test.go#L53))
      - [x] `disableProviderLogout` ([test](../../conformance/goapi/oauth_logout_test.go#L87))
        - [x] With DisableProviderLogout on the provider, which every preset returns as an OAuthProvider, sign-out ends the local session and returns no provider logout URL, also when another configured provider offers logout ([test](../../conformance/goapi/oauth_logout_test.go#L87))
    - [ ] Community Provider Helpers
      - AgentID — *not applicable: JavaScript only. It is a third-party npm package that returns a TypeScript GenericOAuthConfig. A Go host registers such an issuer with providers.OpenIDConnect or its own OAuthProvider.*
      - EVE Online — *not applicable: JavaScript only. It is a third-party npm package that returns a TypeScript GenericOAuthConfig. A Go host configures EVE SSO as its own OAuthProvider.*
      - ThunderID — *not applicable: JavaScript only. It is a third-party npm package that returns a TypeScript GenericOAuthConfig. A Go host registers the issuer with providers.OpenIDConnect.*
      - Create a Provider Helper — *not applicable: TypeScript authoring pattern. A helper typed with BaseOAuthProviderOptions returns a GenericOAuthConfig and is shared as an npm package. In Go a helper is any function that returns plainauth.OAuthProvider, like the constructors in providers/.*
  - [ ] Configure a Provider Manually
    - [x] Instagram Example ([test](../../conformance/goapi/oauth_test.go#L158))
      - [x] A hand-built OAuthProvider with only a client ID, a secret, AuthURL, TokenURL and a Resolve function completes a browser sign-in through /sign-in/social and its callback, then redirects to the requested callbackURL ([test](../../conformance/goapi/oauth_test.go#L158))
      - [x] On both runtimes, a manually configured provider with authorization and token URLs and scopes [profile] asks for exactly scope=profile ([test](../../conformance/social-signup.mjs#L60))
    - [x] Coinbase Example ([test](../../conformance/goapi/oauth_test.go#L158))
      - [x] A hand-built OAuthProvider with only a client ID, a secret, AuthURL, TokenURL and a Resolve function completes a browser sign-in through /sign-in/social and its callback, then redirects to the requested callbackURL ([test](../../conformance/goapi/oauth_test.go#L158))
      - [x] On both runtimes, a manually configured provider with authorization and token URLs and scopes [profile] asks for exactly scope=profile ([test](../../conformance/social-signup.mjs#L60))

## Paybin

- [ ] Paybin
  - [ ] Get your Paybin credentials
    - [ ] Application Name
    - [x] Redirect URIs ([test](../../providers/issuer_test.go#L121))
      - [x] For the paybin preset, a GET to /api/auth/callback/paybin with the issued code and state finishes the sign-in with a 302, after one token request and one signing-key request ([test](../../providers/issuer_test.go#L121))
      - [x] Under BasePath /identity, each profile preset sends redirect_uri https://app.example/identity/callback/<name>, so the registered URI follows the base path ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/issuer_test.go#L60))
    - [x] The paybin preset built with a client ID and secret sends both as form fields in its code exchange at Paybin's token endpoint ([test](../../providers/issuer_test.go#L60))
  - [x] Sign In with Paybin ([test](../../providers/issuer_test.go#L112))
    - [x] POST /sign-in/social with provider paybin redirects to https://idp.paybin.io/oauth2/authorize with scope openid email profile, a nonce and an S256 code challenge ([test](../../providers/issuer_test.go#L112))
  - [ ] Additional Configuration
    - [ ] Scopes
      - [x] The paybin preset's authorization URL asks for openid email profile by default ([test](../../providers/issuer_test.go#L112))
      - [x] Replacing a preset's Config.Scopes puts exactly the new list in the sign-in authorization URL (checked on the Google preset) ([test](../../conformance/goapi/provider_contract_test.go#L68))
    - [ ] User Profile Mapping
      - [x] The paybin sign-in's user takes email, emailVerified and image from the verified ID token's email, email_verified and picture claims, and takes the name from preferred_username when name is empty ([test](../../providers/issuer_test.go#L135))

## PayPal

- [ ] PayPal
  - [x] Get your PayPal Credentials ([test](../../providers/catalog_options_test.go#L43))
    - [x] Sandbox and live PayPal apps each sign in against their own environment's endpoints ([test](../../providers/catalog_options_test.go#L43))
  - [ ] Configure the provider
    - [x] The paypal preset, like each catalog preset, sends the configured client ID and secret in its code exchange ([test](../../providers/catalog_test.go#L79))
    - [x] The paypal preset authenticates to its sandbox token endpoint with HTTP Basic. The test checks each catalog preset's client authentication style ([test](../../providers/catalog_test.go#L58))
    - [ ] Options
      - [x] `environment` ([test](../../providers/catalog_options_test.go#L43))
        - [x] The sandbox endpoints by default and the live ones with Live ([test](../../providers/catalog_options_test.go#L43))
      - [ ] `requestShippingAddress`
  - [ ] Sign In with PayPal
    - [x] `provider` ([test](../../providers/catalog_test.go#L162))
      - [x] POST /sign-in/social with each catalog provider's name, paypal included, redirects to that provider's own authorization endpoint ([test](../../providers/catalog_test.go#L162))
  - [ ] Additional Options:
    - [x] `environment` ([test](../../providers/catalog_options_test.go#L43))
      - [x] The sandbox is the default environment and Live selects the live endpoints ([test](../../providers/catalog_options_test.go#L43))
    - [ ] `requestShippingAddress`
    - [ ] `scope`
      - [x] Each catalog preset's authorization URL asks for exactly its own scope list. PayPal's list is empty, so no scope is requested by default ([test](../../providers/catalog_test.go#L162))
      - [x] On both runtimes, scopes passed at sign-in are added to the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
    - [ ] `mapProfileToUser`
      - [x] A Resolve that maps the provider profile into OAuthProfile.AdditionalFields gives the new user the same mapped locale, count and flag on both runtimes. A mapped field marked not returned is stored but left out of the session, and mapped values for fields that take no input are ignored ([test](../../conformance/social-user-fields.mjs#L110))
    - [ ] `getUserInfo`
      - [x] A custom Resolve function that fetches user info with the issued access token supplies the signed-in user's email and a session ([test](../../conformance/goapi/oauth_test.go#L177))
    - [ ] `verifyIdToken`
      - [x] A custom VerifyIDToken set on a preset receives the raw token and nonce and decides the ID-token sign-in. Its error answers INVALID_TOKEN without a session (checked on the Google preset) ([test](../../conformance/goapi/provider_contract_test.go#L93))

## Polar

- [ ] Polar
  - [ ] Get your Polar credentials
    - [ ] Application Name
    - [ ] Client Type
    - [x] Redirect URIs ([test](../../providers/catalog_test.go#L186))
      - [x] For each catalog preset, polar included, a GET to /api/auth/callback/<name> with the code and state finishes the sign-in with a 302, after one token request and one profile request ([test](../../providers/catalog_test.go#L186))
      - [x] Under BasePath /identity, each profile preset sends redirect_uri https://app.example/identity/callback/<name>, so the registered URI follows the base path ([test](../../providers/profile_presets_test.go#L125))
    - [x] Scopes ([test](../../providers/catalog_test.go#L162))
      - [x] The polar preset's authorization URL asks for openid profile email, its default scopes. The test checks each catalog preset's scope list ([test](../../providers/catalog_test.go#L162))
    - [ ] Homepage URL
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The polar preset, like each catalog preset, sends the configured client ID and secret in its code exchange ([test](../../providers/catalog_test.go#L79))
  - [x] Sign In with Polar ([test](../../providers/catalog_test.go#L162))
    - [x] POST /sign-in/social with each catalog provider's name, polar included, redirects to that provider's own authorization endpoint ([test](../../providers/catalog_test.go#L162))
    - [x] For each catalog preset, polar included, the browser sign-in gives a user whose email, verification, name and image match the preset's sample profile ([test](../../providers/catalog_test.go#L203))

## Railway

- [ ] Railway
  - [x] Get your Railway credentials ([test](../../providers/catalog_test.go#L85))
    - [x] For each catalog preset that uses PKCE, railway included, the code_verifier in the code exchange hashes to the S256 challenge from the authorization URL ([test](../../providers/catalog_test.go#L85))
    - [x] For each catalog preset, railway included, a GET to /api/auth/callback/<name> with the code and state finishes the sign-in with a 302, after one token request and one profile request ([test](../../providers/catalog_test.go#L186))
    - [x] Under BasePath /identity, each profile preset sends redirect_uri https://app.example/identity/callback/<name>, so the registered URL follows the base path ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The railway preset, like each catalog preset, sends the configured client ID and secret in its code exchange ([test](../../providers/catalog_test.go#L79))
    - [x] The railway preset authenticates to its token endpoint with HTTP Basic. The test checks each catalog preset's client authentication style ([test](../../providers/catalog_test.go#L58))
  - [ ] Usage
    - [ ] Sign in with Railway
      - [x] `provider` ([test](../../providers/catalog_test.go#L162))
        - [x] POST /sign-in/social with each catalog provider's name, railway included, redirects to that provider's own authorization endpoint ([test](../../providers/catalog_test.go#L162))
  - [ ] Options
    - [ ] Available Scopes
      - [x] Setting a preset's Config.Scopes and AuthorizationParams prompt puts exactly those scopes and that prompt in the sign-in authorization URL (checked on the Google preset, with prompt select_account consent) ([test](../../conformance/goapi/provider_contract_test.go#L68))
      - [x] On both runtimes, scopes passed at sign-in are added to the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
      - [x] `openid` ([test](../../providers/catalog_test.go#L162))
        - [x] The railway preset's authorization URL asks for openid email profile by default. The test checks each catalog preset's scope list ([test](../../providers/catalog_test.go#L162))
      - [x] `email` ([test](../../providers/catalog_test.go#L162))
        - [x] The railway preset's authorization URL asks for openid email profile by default. The test checks each catalog preset's scope list ([test](../../providers/catalog_test.go#L162))
      - [x] `profile` ([test](../../providers/catalog_test.go#L162))
        - [x] The railway preset's authorization URL asks for openid email profile by default. The test checks each catalog preset's scope list ([test](../../providers/catalog_test.go#L162))
      - [ ] `offline_access`
        - [x] Each catalog preset with a refresh contract, railway included, exchanges a refresh token at its token endpoint and returns the new access token, refresh token and expiry ([test](../../providers/catalog_test.go#L333))
        - [x] The railway preset's refresh request authenticates with HTTP Basic using the configured client ID and secret ([test](../../providers/catalog_test.go#L309))
      - [ ] `workspace:viewer`
        - [x] On both runtimes, extra scopes passed to signIn.social or linkSocial are requested together with the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `workspace:member`
        - [x] On both runtimes, extra scopes passed to signIn.social or linkSocial are requested together with the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `workspace:admin`
        - [x] On both runtimes, extra scopes passed to signIn.social or linkSocial are requested together with the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `project:viewer`
        - [x] On both runtimes, extra scopes passed to signIn.social or linkSocial are requested together with the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `project:member`
        - [x] On both runtimes, extra scopes passed to signIn.social or linkSocial are requested together with the provider's configured scopes ([test](../../conformance/social-signup.mjs#L54))

## Reddit

- [ ] Reddit
  - [x] Reddit sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Reddit provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L32))
  - [x] Get your Reddit Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Reddit code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The Reddit token request uses HTTP Basic client authentication, as the catalog records ([test](../../providers/catalog_test.go#L59))
    - [x] The other runtime's Reddit provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L32))
  - [x] Sign In with Reddit ([test](../../providers/catalog_test.go#L21))
    - [x] Reddit sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "reddit" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))
  - [ ] Additional Configuration
    - [ ] Scopes
      - [x] sign-in/social for Reddit redirects to the catalog authorization endpoint with exactly the default scope identity ([test](../../providers/catalog_test.go#L162))
      - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))
      - [x] `identity` ([test](../../providers/catalog_test.go#L162))
        - [x] sign-in/social for Reddit redirects to the catalog authorization endpoint with exactly the default scope identity ([test](../../providers/catalog_test.go#L162))
        - [x] The other runtime's Reddit provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L32))
      - [ ] `read`
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
        - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `submit`
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
        - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `subscribe`
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
        - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))
      - [ ] `history`
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
        - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))

## Roblox

- [ ] Roblox
  - [x] Roblox sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Roblox provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L33))
  - [x] Get your Roblox Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
    - [x] After the Roblox callback, get-session returns the expected user, whose email is the {sub}@roblox.placeholder.invalid address ([test](../../providers/catalog_test.go#L203))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Roblox code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The other runtime's Roblox provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L33))
  - [x] Sign In with Roblox ([test](../../providers/catalog_test.go#L21))
    - [x] Roblox sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "roblox" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## Salesforce

- [ ] Salesforce
  - [x] Salesforce sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Salesforce provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L34))
  - [ ] Get your Salesforce Credentials
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] The Salesforce code exchange sends a code_verifier matching the S256 code_challenge of its authorization URL ([test](../../providers/catalog_test.go#L85))
    - [x] The other runtime's Salesforce provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L34))
  - [ ] Configure the provider
    - [x] The Salesforce code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The other runtime's Salesforce provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L34))
    - [ ] Configuration Options
      - [x] `clientId` ([test](../../providers/catalog_test.go#L79))
        - [x] The Salesforce code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
      - [x] `clientSecret` ([test](../../providers/catalog_test.go#L79))
        - [x] The Salesforce code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
      - [x] `environment` ([test](../../providers/catalog_options_test.go#L43))
        - [x] Production by default and the sandbox login host with Sandbox ([test](../../providers/catalog_options_test.go#L43))
      - [x] `loginUrl` ([test](../../providers/catalog_options_test.go#L43))
        - [x] A My Domain host is used for the authorize, token and user info endpoints ([test](../../providers/catalog_options_test.go#L43))
      - [x] `redirectURI` ([test](../../conformance/goapi/oauth_redirect_uri_test.go#L96))
        - [x] A provider's own absolute Config.RedirectURL replaces the callback route as redirect_uri in both the authorization request and the code exchange, and non-absolute values are refused ([test](../../conformance/goapi/oauth_redirect_uri_test.go#L96))
    - [x] Advanced Configuration ([test](../../providers/catalog_options_test.go#L43))
      - [x] A sandbox with a My Domain login host uses the My Domain endpoints ([test](../../providers/catalog_options_test.go#L43))
  - [x] Environment Variables ([test](../../env_test.go#L30))
    - [x] With BaseURL unset, AUTH_URL supplies the base URL and base path, and explicit options take precedence over it ([test](../../env_test.go#L30))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
  - [x] Sign In with Salesforce ([test](../../providers/catalog_test.go#L21))
    - [x] Salesforce sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "salesforce" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## Slack

- [ ] Slack
  - [x] Slack sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Slack provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L35))
  - [x] Get your Slack credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Slack code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The other runtime's Slack provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L35))
  - [ ] Usage
    - [x] Sign In with Slack ([test](../../providers/catalog_test.go#L21))
      - [x] Slack sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
      - [x] `provider` ([test](../../providers/catalog_test.go#L147))
        - [x] A sign-in/social body with provider set to "slack" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))
    - [x] Requesting Additional Scopes ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social for Slack redirects to the catalog authorization endpoint with exactly the default scope "openid profile email" ([test](../../providers/catalog_test.go#L162))
      - [x] On both runtimes, scopes sent with sign-in/social or link-social are added to the provider's default scope in the authorization URL, and a later start without them asks only for the default ([test](../../conformance/social-signup.mjs#L54))
    - [ ] Workspace-Specific Sign In
      - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
    - [ ] Using Slack API After Sign In
      - [x] On both runtimes, get-access-token returns the provider access token stored on the signed-in user's account ([test](../../conformance/provider-credentials.mjs#L69))
      - [x] After the Slack callback, account-info returns the provider profile object recorded from the other runtime's Slack provider ([test](../../providers/catalog_test.go#L230))

## Spotify

- [ ] Spotify
  - [x] Spotify sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Spotify provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L36))
  - [x] Get your Spotify Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Spotify code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] With BaseURL unset, AUTH_URL supplies the base URL and base path, and explicit options take precedence over it ([test](../../env_test.go#L30))
    - [x] The other runtime's Spotify provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L36))
  - [x] Sign In with Spotify ([test](../../providers/catalog_test.go#L21))
    - [x] Spotify sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "spotify" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## TikTok

- [ ] TikTok
  - [x] TikTok sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's TikTok provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L14))
  - [x] Get your TikTok Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
    - [x] sign-in/social for TikTok redirects to the catalog authorization endpoint with exactly the default scope user.info.profile ([test](../../providers/catalog_test.go#L162))
    - [x] After the TikTok callback, get-session returns the expected user, whose email is the {open_id}@tiktok.placeholder.invalid address ([test](../../providers/catalog_test.go#L203))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L174))
    - [x] The TikTok authorization URL carries the client key passed to New as client_key and has no client_id ([test](../../providers/catalog_test.go#L174))
    - [x] The TikTok code exchange sends client_key and client_secret in the form and no client_id ([test](../../providers/catalog_test.go#L72))
  - [x] Sign In with TikTok ([test](../../providers/catalog_test.go#L21))
    - [x] TikTok sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "tiktok" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## Twitch

- [ ] Twitch
  - [x] Twitch sign-in/social, the callback code exchange and get-session complete with an ID token signed for the Twitch issuer, giving the expected user ([test](../../providers/issuer_test.go#L25))
  - [x] Running the other runtime's Twitch provider against local fixtures reproduces the checked-in authorization endpoint, token endpoint, scope, claims request, PKCE setting and expected profile ([test](../../conformance/social-profiles.mjs#L95))
  - [x] Get your Twitch Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/issuer_test.go#L60))
    - [x] The Twitch code exchange sends the client ID and secret passed to New in the form with the callback code ([test](../../providers/issuer_test.go#L60))
    - [x] Running the other runtime's Twitch provider against local fixtures reproduces the checked-in authorization endpoint, token endpoint, scope, claims request, PKCE setting and expected profile ([test](../../conformance/social-profiles.mjs#L95))
  - [x] Sign In with Twitch ([test](../../providers/issuer_test.go#L25))
    - [x] Twitch sign-in/social, the callback code exchange and get-session complete with an ID token signed for the Twitch issuer, giving the expected user ([test](../../providers/issuer_test.go#L25))
    - [x] The Twitch authorization URL is id.twitch.tv/oauth2/authorize with scope "user:read:email openid", the email claims request, a nonce and no PKCE ([test](../../providers/issuer_test.go#L112))
    - [x] A provider profile without an email ends the callback at the error callback with error=email_not_found and no session ([test](../../conformance/goapi/oauth_callback_errors_test.go#L108))
    - [x] `provider` ([test](../../providers/issuer_test.go#L97))
      - [x] A sign-in/social body with provider set to "twitch" returns the Twitch authorization redirect, and its callback signs the user in ([test](../../providers/issuer_test.go#L97))

## Twitter (X)

- [ ] Twitter (X)
  - [x] Twitter sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Twitter provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L12))
  - [x] Get your Twitter Credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
    - [x] sign-in/social for Twitter redirects to the catalog authorization endpoint with exactly the default scope "users.read tweet.read offline.access users.email" ([test](../../providers/catalog_test.go#L162))
    - [x] The Twitter sign-in fetches confirmed_email with the access token, and the session user gets that email as verified ([test](../../providers/catalog_test.go#L128))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Twitter code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The Twitter token request uses HTTP Basic client authentication, as the catalog records ([test](../../providers/catalog_test.go#L59))
    - [x] The other runtime's Twitter provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L12))
  - [x] Sign In with Twitter ([test](../../providers/catalog_test.go#L21))
    - [x] Twitter sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "twitter" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## Vercel

- [ ] Vercel
  - [x] Vercel sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Vercel provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L37))
  - [ ] Get your Vercel credentials
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] The Vercel code exchange sends a code_verifier matching the S256 code_challenge of its authorization URL ([test](../../providers/catalog_test.go#L85))
    - [x] A Vercel app signs in through the browser under a custom base path whose callback reaches the token request ([test](../../providers/token_auth_test.go#L123))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The Vercel code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The other runtime's Vercel provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L37))
  - [ ] Usage
    - [x] Sign in with Vercel ([test](../../providers/catalog_test.go#L21))
      - [x] Vercel sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
      - [x] `provider` ([test](../../providers/catalog_test.go#L147))
        - [x] A sign-in/social body with provider set to "vercel" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))
  - [ ] Options
    - [x] The Vercel code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The Vercel token request uses form-body (not HTTP Basic) client authentication, as the catalog records ([test](../../providers/catalog_test.go#L59))
    - [x] Token endpoint authentication ([test](../../providers/token_auth_test.go#L123))
      - [x] A custom hook adds an OIDC workload token as the client assertion while the code, redirect URI and PKCE verifier stay unchanged ([test](../../providers/token_auth_test.go#L123))
      - [x] OIDC client authentication ([test](../../providers/token_auth_test.go#L123))
        - [x] A client assertion callback authenticates the Vercel code exchange without a secret, and the same with a secret is refused ([test](../../providers/token_auth_test.go#L123))
      - [x] Private key JWT client authentication ([test](../../providers/token_auth_test.go#L123))
        - [x] providers.PrivateKeyJWT signs the Vercel client assertion with the configured key ID, the client ID as issuer and subject, the token endpoint as audience and a one-minute lifetime, and the token endpoint verifies it ([test](../../providers/token_auth_test.go#L123))
    - [ ] Available Scopes
      - [x] sign-in/social for Vercel redirects to the catalog authorization endpoint with an empty scope value, since the catalog records no default scopes for Vercel ([test](../../providers/catalog_test.go#L162))
      - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [ ] `openid`
        - [x] The Vercel userinfo sub becomes the account subject, matching the other runtime's Vercel provider ([test](../../providers/catalog_test.go#L242))
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [ ] `email`
        - [x] After the Vercel callback, get-session returns the expected email and emailVerified from the Vercel userinfo ([test](../../providers/catalog_test.go#L203))
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [ ] `profile`
        - [x] After the Vercel callback, get-session returns the expected name and image from the Vercel userinfo ([test](../../providers/catalog_test.go#L203))
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
      - [ ] `offline_access`
        - [x] The refresh token returned by the browser code exchange is stored on the account and handed to the provider's refresh ([test](../../adapters/sqlstore/oauth_encryption_test.go#L37))
        - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))

## VK

- [ ] VK
  - [x] VK sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's VK provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L13))
  - [x] Get your VK ID credentials ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
    - [x] With BasePath /identity, the authorization and token requests carry redirect_uri BaseURL/identity/callback/<id> ([test](../../providers/profile_presets_test.go#L125))
  - [x] Configure the provider ([test](../../providers/catalog_test.go#L79))
    - [x] The VK code exchange carries the client ID and secret passed to New, with grant_type authorization_code and the callback code ([test](../../providers/catalog_test.go#L79))
    - [x] The other runtime's VK provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L13))
  - [x] Sign In with VK ([test](../../providers/catalog_test.go#L21))
    - [x] VK sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "vk" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))

## WeChat

- [ ] WeChat
  - [x] WeChat sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's WeChat provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L15))
  - [x] Get your WeChat Credentials ([test](../../providers/catalog_test.go#L171))
    - [x] The WeChat authorization URL carries the App ID passed to New as appid and has no client_id ([test](../../providers/catalog_test.go#L171))
    - [x] The WeChat code exchange is a GET carrying the App ID as appid and the App Secret as secret ([test](../../providers/catalog_test.go#L66))
    - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))
  - [ ] Configure the provider
    - [x] The WeChat authorization URL carries the App ID passed to New as appid and has no client_id ([test](../../providers/catalog_test.go#L171))
    - [x] The WeChat code exchange is a GET carrying the App ID as appid and the App Secret as secret ([test](../../providers/catalog_test.go#L66))
    - [x] The other runtime's WeChat provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L15))
    - [ ] Optional Configuration
      - [x] Each catalog provider's fixed authorization parameters, WeChat's lang=cn among them, appear in its authorization URL ([test](../../providers/catalog_test.go#L167))
      - [x] Replacing a provider's Config.Scopes and setting AuthorizationParams changes the scope and adds the parameter in the sign-in/social and link-social authorization URLs ([test](../../conformance/goapi/provider_contract_test.go#L67))
  - [x] Sign In with WeChat ([test](../../providers/catalog_test.go#L21))
    - [x] WeChat sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
    - [x] `provider` ([test](../../providers/catalog_test.go#L147))
      - [x] A sign-in/social body with provider set to "wechat" starts that provider's authorization redirect, and its callback signs the user in ([test](../../providers/catalog_test.go#L147))
  - [ ] Usage
    - [x] Platform Support ([test](../../providers/catalog_test.go#L162))
      - [x] sign-in/social for WeChat redirects to the open.weixin.qq.com/connect/qrconnect website-login endpoint with the wechat_redirect fragment and scope snsapi_login ([test](../../providers/catalog_test.go#L162))
    - [x] Development Notes ([test](../../conformance/goapi/oauth_test.go#L142))
      - [x] With a 127.0.0.1 BaseURL, the provider's redirect lands on BaseURL/api/auth/callback/<id> and that callback completes the sign-in ([test](../../conformance/goapi/oauth_test.go#L142))

## Zoom

- [ ] Zoom
  - [x] Zoom sign-in/social, callback code exchange and get-session complete against local fixtures with the expected user and account data ([test](../../providers/catalog_test.go#L21))
  - [x] The other runtime's Zoom provider, run on local fixtures, reproduces the checked-in catalog entry (endpoints, scopes, PKCE, client auth) and expected profile ([test](../../conformance/social-profiles.mjs#L38))
  - [ ] Create a Zoom App from Marketplace
  - [ ] Configure your Zoom App
    - [x] For every catalog provider, including zoom, the provider's return to /api/auth/callback/<name> with the code and state completes the sign-in ([test](../../providers/catalog_test.go#L180))
    - [x] With BasePath /identity, each profile preset sends https://app.example/identity/callback/<provider> as redirect_uri in the authorization URL and the code exchange ([test](../../providers/profile_presets_test.go#L67))
  - [ ] Configure the provider
    - [x] For every catalog provider, including zoom, the client ID and secret passed to New reach the token exchange in the form the provider requires ([test](../../providers/catalog_test.go#L79))
  - [ ] Sign In with Zoom
    - [x] For every catalog provider, including zoom, POST /sign-in/social with the provider name redirects to its authorization endpoint, and the callback creates a session with the mapped profile ([test](../../providers/catalog_test.go#L21))
