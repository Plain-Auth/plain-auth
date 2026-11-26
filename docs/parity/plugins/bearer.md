# Bearer

[Feature index](../README.md)

## Interfaces

- [x] Bearer endpoints, types and options ([test](../../../conformance/core.test.mjs#L1221))
  - [x] Verify bearer session issuance, renewal, mixed credentials and revocation with both signature policies ([test](../../../conformance/core.test.mjs#L1221))
  - [x] `BearerOptions` ([test](../../../conformance/core.test.mjs#L1227))
    - [x] Configure the public signature policy and exercise each setting on both runtimes ([test](../../../conformance/core.test.mjs#L1227))
    - [x] `requireSignature` ([test](../../../plugins/bearer/bearer_test.go#L52))
      - [x] Accept valid signed credentials and reject raw or altered tokens when signatures are required ([test](../../../plugins/bearer/bearer_test.go#L52))
  - [x] `bearer` ([test](../../../conformance/bearer-contract.mjs#L5))
    - [x] Install the bearer hooks and exercise ordinary and signed-only sessions over HTTP ([test](../../../conformance/bearer-contract.mjs#L5))
    - [x] Retain the original opaque token when decoding the cookie signature for the response header ([test](../../../plugins/bearer/bearer_test.go#L65))

## Bearer Token Authentication

- [x] Bearer Token Authentication ([test](../../../conformance/bearer-contract.mjs#L5))
  - [x] Exercise bearer headers on sign-in, protected requests, session renewal and sign-out ([test](../../../conformance/bearer-contract.mjs#L5))
  - [x] Installing the Bearer Plugin ([test](../../../client/bearer_test.go#L16))
    - [x] Install the plugin on a Go host with signed-only credentials and exercise the client on TLS ([test](../../../client/bearer_test.go#L16))
  - [x] How to Use Bearer Tokens ([test](../../../client/bearer_test.go#L98))
    - [x] Read the signed login header, use it on the client, and authenticate a request at another application endpoint ([test](../../../client/bearer_test.go#L98))
    - [x] 1. Obtain the Bearer Token ([test](../../../client/bearer_test.go#L56))
      - [x] Read the signed session credential from successful login response headers ([test](../../../client/bearer_test.go#L56))
    - [x] 2. Configure the Auth Client ([test](../../../client/bearer_test.go#L78))
      - [x] Authenticate a device with a signed credential while the browser uses its own account ([test](../../../client/bearer_test.go#L78))
    - [x] 3. Make Authenticated Requests ([test](../../../conformance/bearer-contract.mjs#L62))
      - [x] Use a bearer credential to retrieve an authenticated session ([test](../../../plugins/bearer/bearer_test.go#L16))
      - [x] List only the device owner’s active sessions with the configured browser client ([test](../../../conformance/bearer-contract.mjs#L62))
    - [x] 4. Per-Request Token (Optional) ([test](../../../client/bearer_test.go#L103))
      - [x] Use a credential for one client view without falling back to the browser on revocation ([test](../../../client/bearer_test.go#L103))
    - [x] 5. Using Bearer Tokens Outside the Auth Client ([test](../../../client/bearer_test.go#L105))
      - [x] Authenticate a host-owned TLS route with a plain HTTP client and deny the same credential after sign-out ([test](../../../client/bearer_test.go#L105))
  - [x] Options ([test](../../../conformance/core.test.mjs#L1226))
    - [x] Test the default signature policy and signed-only mode with independent accounts ([test](../../../conformance/core.test.mjs#L1226))
    - [x] requireSignature ([test](../../../conformance/bearer-contract.mjs#L49))
      - [x] Accept the raw credential only under the default policy and always verify signed values ([test](../../../conformance/bearer-contract.mjs#L49))
