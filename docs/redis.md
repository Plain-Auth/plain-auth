# Redis secondary storage

Use the optional `github.com/Plain-Auth/plain-auth/adapters/redis` Go module to share rate limits across auth servers or store short-lived application values. It accepts a single-node `*redis.Client` from go-redis v9. The primary store continues to manage users, sessions and account data.

Install the adapter from your application's Go module. During private development, use the same GitHub credentials as for the main module.

```sh
GOPRIVATE=github.com/Plain-Auth/plain-auth go get \
  github.com/Plain-Auth/plain-auth@main \
  github.com/Plain-Auth/plain-auth/adapters/redis@main
```

## Share rate limits

Configure all replicas with the same Redis database, key prefix and rate-limit rules. The client belongs to the application and should be closed at shutdown.

```go
import (
    "context"
    "time"

    plainauth "github.com/Plain-Auth/plain-auth"
    redisstore "github.com/Plain-Auth/plain-auth/adapters/redis"
    "github.com/redis/go-redis/v9"
)

func configure(ctx context.Context, opts plainauth.Options, redisURL string) (*plainauth.Auth, *redis.Client, error) {
    connection, err := redis.ParseURL(redisURL)
    if err != nil {
        return nil, nil, err
    }
    connection.ContextTimeoutEnabled = true
    connection.MaxRetries = -1
    client := redis.NewClient(connection)
    if err := client.Ping(ctx).Err(); err != nil {
        client.Close()
        return nil, nil, err
    }
    limits, err := redisstore.New(client, "shop:production:limits:")
    if err != nil {
        client.Close()
        return nil, nil, err
    }
    on := true
    opts.RateLimit = &on
    opts.RateLimitStorage = limits
    opts.RateLimitDefault = &plainauth.RateLimitRule{Max: 100, Window: time.Minute}
    handler, err := plainauth.New(opts)
    if err != nil {
        client.Close()
        return nil, nil, err
    }
    return handler, client, nil
}
```

Redis opens a fixed window on the first request from a peer to a route. Every matching request across the replicas increments the same counter. Requests above the maximum receive HTTP 429 and `X-Retry-After` with the configured window in seconds. The counter expires on its original schedule. A Redis failure prevents the request from reaching its handler. The example disables automatic client retries because a lost reply can leave the outcome of an increment or consumption unknown. [Handler integration test](../adapters/redis/storage_test.go)

## Store and consume values

The default prefix is `plainauth:`. Choose separate, disjoint prefixes for environments, application-owned values and rate counters. Every operation accepts a Go context. `Set(ctx, key, value, ttl)` stores a string for a whole number of seconds. A zero or negative TTL stores it persistently. `Get` and `GetAndDelete` return the value, a presence flag and an error. The presence flag distinguishes a stored empty string from a missing key. `Delete` succeeds on an absent key.

`GetAndDelete` atomically consumes one value with `GETDEL`, falling back to a single-key Lua script when the server reports that the command is unknown. `Increment` returns the new signed 64-bit count. Supply a positive whole-second TTL. Redis assigns it only when it creates the key. An existing integer keeps its original expiry. [Redis GETDEL](https://redis.io/docs/latest/commands/getdel/)

`ListKeys` pages through the keyspace with `SCAN` and returns unique, prefix-stripped keys. `Clear` deletes only keys matching the literal configured prefix, in pages. A failed clear may have already removed earlier pages. Retry after the failure and stop concurrent writers when you need an empty namespace. The adapter targets one writable keyspace. Redis Cluster and sharded rings need cluster-wide scanning and slot-aware deletion. [Redis SCAN](https://redis.io/docs/latest/commands/scan/)

Run `make test-redis` with either a `valkey-server` or `redis-server` executable on the path. Tests start disposable processes listening on private Unix sockets. Alternatively, set `AUTH_TEST_REDIS_SERVER` to an executable or `AUTH_TEST_REDIS_URL` to a disposable Redis database. Hosted verification runs against Valkey.
