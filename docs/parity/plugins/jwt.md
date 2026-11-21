# JSON Web Tokens

[Feature index](../README.md)

## Interfaces

- [ ] JSON Web Tokens endpoints, types and options
  - [ ] `jwtClient`
  - [ ] `GET /jwks (configurable)`
  - [ ] `GET /token`
  - [ ] `signJWT (server API only)`
  - [ ] `verifyJWT (server API only)`
  - [ ] `jwt`
  - [ ] `JwtOptions`
    - [ ] `sessionCookieCache`
    - [ ] `jwks`
    - [ ] `jwt`
    - [ ] `disableSettingJwtHeader`
    - [ ] `schema`
    - [ ] `adapter`
  - [ ] `JWKOptions`
    - [ ] `alg`
    - [ ] `crv`
    - [ ] `alg`
    - [ ] `crv`
    - [ ] `alg`
    - [ ] `crv`
    - [ ] `alg`
    - [ ] `modulusLength`
    - [ ] `alg`
    - [ ] `modulusLength`
  - [ ] `JWSAlgorithms`
  - [ ] `Jwk`
  - [ ] `ResolvedSigningKey`

## JWT

- [ ] JWT
  - [ ] Usage
  - [ ] JWT
    - [ ] Retrieve the token
      - [ ] Using the client plugin (recommended)
      - [ ] Using your session token
      - [ ] From `set-auth-jwt` header
    - [ ] Verifying the token
      - [ ] Example using jose with remote JWKS
      - [ ] Example with local JWKS
    - [ ] OAuth Provider Mode
    - [ ] Remote JWKS Url
    - [ ] Custom JWKS Path
      - [ ] Server Configuration:
      - [ ] Client Configuration:
    - [ ] Custom Signing
      - [ ] Localized Signing
      - [ ] Remote Signing
  - [ ] Schema
    - [ ] JWKS
      - [ ] `jwksTableFields.id`
      - [ ] `jwksTableFields.publicKey`
      - [ ] `jwksTableFields.privateKey`
      - [ ] `jwksTableFields.alg`
      - [ ] `jwksTableFields.crv`
      - [ ] `jwksTableFields.createdAt`
      - [ ] `jwksTableFields.expiresAt`
  - [ ] Options
    - [ ] Session cookie cache
    - [ ] Algorithm of the Key Pair
      - [ ] EdDSA
        - [ ] Default Curve
        - [ ] Optional Property
      - [ ] ES256
      - [ ] RSA256
        - [ ] Optional Property
      - [ ] PS256
        - [ ] Optional Property
      - [ ] ECDH-ES
        - [ ] Optional Property
      - [ ] ES512
    - [ ] Disable private key encryption
    - [ ] Key Rotation
      - [ ] `rotationInterval`
      - [ ] `gracePeriod`
    - [ ] Modify JWT payload
    - [ ] Modify Issuer, Audience, Subject or Expiration time
    - [ ] Custom Adapter
