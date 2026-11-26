# CAPTCHA verification

Register a verification provider to challenge HTTP requests before they reach an auth endpoint. The built-in protected paths are `/sign-up/email`, `/sign-in/email`, and `/request-password-reset`. After the browser completes the provider's challenge, send its fresh token as the `X-Captcha-Response` header on the auth request.

```go
p, err := captcha.New(captcha.Options{
    Provider:         captcha.CloudflareTurnstile,
    SecretKey:        os.Getenv("TURNSTILE_SECRET"),
    ExpectedAction:   "signup",
    AllowedHostnames: []string{"app.example.com"},
    Endpoints:        []string{"/sign-up/email"},
})
if err != nil {
    return err
}
opts.Plugins = append(opts.Plugins, p)
```

Import `github.com/Plain-Org/plain-auth/plugins/captcha`. The application reads its provider secret from the server environment. Configure the browser widget with the matching site key and action.

| Provider | Verification options |
| --- | --- |
| `captcha.CloudflareTurnstile` | Optional exact `ExpectedAction` and `AllowedHostnames` |
| `captcha.GoogleRecaptcha` | Optional action and hostname checks. v3 scores must meet `MinScore` (default 0.5). Successful v2 responses can omit the score. |
| `captcha.HCaptcha` | Optional `SiteKey` for validating the intended widget |
| `captcha.CaptchaFox` | Optional `SiteKey` for validating the intended widget |
| `captcha.VercelBotID` | Application-provided `CheckBotID` and optional `ValidateRequest` |

For the four challenge-token protocols, the server sends the verification POST directly to the provider. `SiteVerifyURLOverride` selects an application-configured verification endpoint. The request keeps the selected provider's format: JSON for Cloudflare Turnstile and a form body for the others. `New` refuses an override that is not an absolute `http` or `https` URL with a host, or that includes credentials or a fragment, and verification does not follow redirects: a redirect answers 500 `UNKNOWN_ERROR`. `Transport` accepts an HTTP transport for local tests. The request uses the host's trusted proxy settings to obtain the client IP. With IP tracking disabled, the provider request omits it.

A nonempty `Endpoints` list replaces the defaults. Specify paths relative to the auth mount. For example, `/sign-in/*` matches one segment after `/sign-in/`, and `/sign-in/**` includes nested paths. Missing challenge tokens return HTTP 400 with `MISSING_RESPONSE`. Rejected challenges return 403 with `VERIFICATION_FAILED`. Provider failures return 500 with `UNKNOWN_ERROR`. Verification has a ten-second deadline. Server-side methods such as `Auth.SignUpEmail` called directly by trusted application code do not pass through HTTP request hooks.

For Vercel BotID, configure the browser integration for the same paths and methods as the server. Supply a `CheckBotID` callback that obtains a trusted verdict for the current request. The default accepts human verdicts. `ValidateRequest` can apply an application-specific policy to the request and verdict, including a deliberate exception for a named verified bot. Both callbacks receive the request context and deadline. The host supplies the Vercel SDK bridge. [Provider and BotID tests](../plugins/captcha/captcha_test.go)
