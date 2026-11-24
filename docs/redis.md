# Redis secondary storage

Use the optional `github.com/Plain-Org/plain-auth/adapters/redis` Go module to keep sessions in Redis, share rate limits across auth servers or store short-lived application values. It accepts a single-node `*redis.Client` from go-redis v9. The primary store continues to own users, sessions and account data.

Install the adapter and core from the same preview revision in your application's Go module.

```sh
go get \
  github.com/Plain-Org/plain-auth@main \
  github.com/Plain-Org/plain-auth/adapters/redis@main
```

## Keep sessions in Redis

Set `Options.SecondaryStorage` to a Redis store so session reads skip the database. Sessions also stay in the database, which `Options.StoreSessionInDatabase` must confirm; Redis holds a copy of each live session:

```go
sessions, err := redisstore.New(client, "shop:production:sessions:")
if err != nil {
    return err
}
opts.SecondaryStorage = sessions
opts.StoreSessionInDatabase = true
```

The SQL store writes a session's copy when it creates the session, under the session token, with the session's remaining lifetime as its TTL. A read that finds no copy, for example after a flush, reads the database and copies the session back. Every revocation, sign-out, refresh and change to the user's profile deletes the affected copies before it commits, and a copy that cannot be deleted fails the change, so Redis never serves a session the database has ended. This covers every path through Plain Auth, plugins such as SCIM included. A change made outside Plain Auth, such as SQL run by hand, shows only after the copy expires or Redis is flushed. Impersonated sessions are never copied, because they depend on the admin's own session.

A Redis failure on a read or when a session is created fails that request. A copy that fails to write after a database read is deleted instead, and every deletion runs again two seconds later, so a write whose reply was lost cannot leave a copy behind. If Redis stalls for longer than that while a copy is being written, the late copy can outlive its session until the session would have expired, or until someone signs out with its token; keep Redis client timeouts short and watch Redis for stalls.

The copies stay correct only while every change goes through a Store that has the storage attached:

- Attach the same storage, with the same prefix, to every Store handle in every process that writes users or sessions through Plain Auth. A process or handle without it changes the database without deleting the copies.
- Turn mirroring on in every process before any of them serves sessions from Redis.
- Flush the prefix whenever you turn mirroring on or back on. Copies left from an earlier run may describe sessions that changed while mirroring was off.

The copies hold live session tokens and the user's email, name, image and admin state: run Redis on a private network with TLS and authentication, give each environment its own prefix, and remember that Redis persistence writes the copies to disk. Evicting a copy is harmless. One store attaches one storage; a second, different storage is refused. The memory store does not mirror sessions. Sessions cannot live in Redis alone, and the copies use their own key layout, so share a Redis keyspace only with other Plain Auth instances. [Redis session test](../adapters/redis/sessions_test.go) · [Three-engine tests](../adapters/sqlstore/secondary_sessions_test.go)

## Share rate limits

Configure all replicas with the same Redis database, key prefix and rate-limit rules. The client belongs to the application and should be closed at shutdown.

```go
import (
    "context"
    "time"

    plainauth "github.com/Plain-Org/plain-auth"
    redisstore "github.com/Plain-Org/plain-auth/adapters/redis"
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
