# Captcha

[Feature index](../README.md)

## Interfaces

- [ ] Captcha endpoints, types and options
  - [ ] `captcha`
  - [ ] `Provider`
  - [ ] `BaseCaptchaOptions`
    - [ ] `secretKey`
    - [ ] `endpoints`
    - [ ] `siteVerifyURLOverride`
  - [ ] `GoogleRecaptchaOptions`
    - [ ] `provider`
    - [ ] `minScore`
    - [ ] `expectedAction`
    - [ ] `allowedHostnames`
  - [ ] `CloudflareTurnstileOptions`
    - [ ] `provider`
    - [ ] `expectedAction`
    - [ ] `allowedHostnames`
  - [ ] `HCaptchaOptions`
    - [ ] `provider`
    - [ ] `siteKey`
  - [ ] `CaptchaFoxOptions`
    - [ ] `provider`
    - [ ] `siteKey`
  - [ ] `BotIdVerification`
  - [ ] `ValidateRequestContext`
  - [ ] `VercelBotIdOptions`
    - [ ] `provider`
    - [ ] `endpoints`
    - [ ] `checkBotId`
    - [ ] `validateRequest`
  - [ ] `CaptchaOptions`

## Captcha

- [ ] Captcha
  - [ ] Providers
    - [ ] Vercel BotID
  - [ ] How it works
  - [ ] Plugin Options
    - [ ] `provider` (required)
    - [ ] `secretKey` (required for all providers except `vercel-botid`)
    - [ ] `endpoints`
    - [ ] `minScore`
    - [ ] `siteKey`
    - [ ] `siteVerifyURLOverride`
    - [ ] `checkBotId`
    - [ ] `validateRequest`
