# Bearer

[Feature index](../README.md)

## Interfaces

- [ ] Bearer endpoints, types and options
  - [ ] `BearerOptions`
    - [x] `requireSignature` ([test](../../../plugins/bearer/bearer_test.go#L52))
      - [x] Accept valid signed credentials and reject raw or altered tokens when signatures are required ([test](../../../plugins/bearer/bearer_test.go#L52))
  - [ ] `bearer`

## Bearer Token Authentication

- [ ] Bearer Token Authentication
  - [ ] Installing the Bearer Plugin
  - [ ] How to Use Bearer Tokens
    - [x] 1. Obtain the Bearer Token ([test](../../../client/bearer_test.go#L42))
      - [x] Read the signed session credential from successful login response headers ([test](../../../client/bearer_test.go#L42))
    - [x] 2. Configure the Auth Client ([test](../../../client/bearer_test.go#L64))
      - [x] Authenticate a device with a signed credential while the browser uses its own account ([test](../../../client/bearer_test.go#L64))
    - [ ] 3. Make Authenticated Requests
      - [x] Use a bearer credential to retrieve an authenticated session ([test](../../../plugins/bearer/bearer_test.go#L16))
    - [x] 4. Per-Request Token (Optional) ([test](../../../client/bearer_test.go#L70))
      - [x] Use a credential for one client view without falling back to the browser on revocation ([test](../../../client/bearer_test.go#L70))
    - [ ] 5. Using Bearer Tokens Outside the Auth Client
  - [ ] Options
    - [ ] requireSignature
