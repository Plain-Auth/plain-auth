# Username

[Feature index](../README.md)

## Interfaces

- [ ] Username endpoints, types and options
  - [ ] `UsernameClientOptions`
    - [ ] `displayUsername`
  - [ ] `usernameClient`
  - [ ] `POST /sign-in/username`
  - [ ] `POST /is-username-available`
  - [ ] `UsernameOptions`
    - [ ] `schema`
    - [ ] `minUsernameLength`
    - [ ] `maxUsernameLength`
    - [ ] `usernameValidator`
    - [ ] `displayUsernameValidator`
    - [ ] `usernameNormalization`
    - [ ] `displayUsernameNormalization`
    - [ ] `validationOrder`
    - [ ] `immutableUsername`
    - [ ] `displayUsername`
  - [ ] `UsernamePlugin`
  - [ ] `UsernamePluginWithoutDisplayUsername`
  - [ ] `username`
  - [ ] `username`
  - [ ] `username`

## Username

- [ ] Username
  - [ ] Usage
    - [ ] Sign up
      - [ ] `POST /sign-up/email`
        - [ ] Parameter `email`
        - [ ] Parameter `name`
        - [ ] Parameter `password`
        - [ ] Parameter `username` (optional)
        - [ ] Parameter `displayUsername` (optional)
    - [ ] Sign in
      - [ ] `POST /sign-in/username`
        - [ ] Parameter `username`
        - [ ] Parameter `password`
    - [ ] Update username
      - [ ] `POST /update-user`
        - [ ] Parameter `username` (optional)
    - [ ] Check if username is available
      - [ ] `POST /is-username-available`
        - [ ] Parameter `username`
  - [ ] Options
    - [ ] Min Username Length
    - [ ] Max Username Length
    - [ ] Username Validator
    - [ ] Display Username Validator
    - [ ] Username Normalization
    - [ ] Display Username Normalization
    - [ ] Validation Order
    - [ ] Disable Display Username
    - [ ] Immutable Username
    - [ ] Disable Is Username Available
  - [ ] Schema
    - [ ] `usernameUserTableFields.username`
    - [ ] `usernameUserTableFields.displayUsername`
