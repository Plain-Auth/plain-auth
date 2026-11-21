# Environment contract

The [configuration guide](../docs/environment.md) lists the server's five settings and their corresponding Go options. The native HTTP client reads `AUTH_URL` when its caller supplies an empty URL.

The [isolated-process test](env.test.mjs) starts the compiled Go fixture with a synthetic environment. It checks the mounted URL, callback trust decisions and the active key's signature against independently calculated values. It also captures the destination of an actual client request and verifies that unrelated host settings cannot supply a signing key or redirect either component.

The [server tests](../env_test.go) exercise explicit option precedence, rate limiting, key rotation and retirement. The [native client tests](../client/environment_test.go) cover the default and custom mounts.
