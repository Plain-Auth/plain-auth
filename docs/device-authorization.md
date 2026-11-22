# Sign in a device

Use a browser to authorize a CLI, TV or other device that belongs to your application. The device receives its own revocable session. The signed-in browser keeps its existing session.

Generate the `device-authorization` SQL profile and register the plugin. Register the bearer plugin when the device will present its session in the HTTP Authorization header.

```go
device, err := deviceauthorization.New(deviceauthorization.Options{
    VerificationURI: "/activate",
    ValidateClient: func(ctx context.Context, id string) (bool, error) {
        return id == "tv" || id == "cli", nil
    },
})
if err != nil {
    return err
}
options.Plugins = append(options.Plugins, device, bearer.New(bearer.Options{}))
```

Serve a browser page at `/activate`. Show the code and the requesting client before asking the user to approve. The user should compare this code with the one displayed on their own device. A client ID identifies the requesting application. A public device embeds no client secret.

| Actor | Request relative to the auth mount | Result |
| --- | --- | --- |
| Device | `POST /device/code` with `client_id`, optional `scope` and optional `user_id` | Device code, display code, verification links, lifetime and polling interval |
| Browser | `GET /device?user_code=…` | Anonymous users see status. The first signed-in reviewer claims an unbound code and can see its client and scopes. A pre-bound code already has an owner. |
| Browser | `POST /device/approve` or `POST /device/deny` with JSON `{"userCode":"…"}` | Records the owner's decision |
| Device | `POST /device/token` with `client_id`, `device_code` and `grant_type=urn:ietf:params:oauth:grant-type:device_code` | Bearer session token, lifetime and requested scopes |

The code and token routes accept JSON and URL-encoded forms. Keep the device code on the device. Only the user code belongs on the activation screen. The default user code contains eight characters and accepts case and display separators. Custom user codes are matched exactly first. The default device code has 40 random alphanumeric characters. A grant expires after 30 minutes and its polling interval starts at five seconds.

**Polling.** Wait for the indicated interval before each token request. After `authorization_pending`, continue at the same interval. After `slow_down`, add five seconds for this and every subsequent attempt. Back off after connection timeouts. Stop on denial, expiry, an invalid grant or caller cancellation. Redemption and session creation occur in a single SQL transaction. The token inherits the server's session lifetime. The returned scope reports the original request. Applications enforce access to resources. [RFC 8628, section 3.5](https://www.rfc-editor.org/rfc/rfc8628#section-3.5)

**Go client.** Use separate clients and cookie jars for the device and browser. The device calls `RequestDeviceCode` and `PollDeviceToken`. The browser calls `VerifyDeviceCode`, then `ApproveDeviceCode` or `DenyDeviceCode`. `PollDeviceToken` makes one request. A returned `*plainauth.APIError` carries the HTTP status, OAuth error code and description. Send a successful token as `Authorization: Bearer <access_token>` to an instance with bearer authentication enabled.

**Configuration.** Set `ExpiresIn` and `Interval` as Go durations of at least one second. Set `DeviceCodeLength` and `UserCodeLength` to select lengths up to 191 characters. `GenerateDeviceCode` and `GenerateUserCode` may supply custom codes. The server retries collisions up to three times. `ValidateClient` runs during issuance and polling. The default accepts nonempty client IDs. `OnDeviceAuthRequest` receives the accepted client ID and scope during issuance. The browser verification route allows five lookups per peer per grant lifetime when rate limiting is enabled.

This plugin issues first-party sessions. An OAuth authorization server, third-party delegated grants, resource indicators and custom grant extensions remain separate roadmap items. The review and token routes refuse records bound to an OAuth client in a shared database. See the [feature checklist](parity/plugins/device-authorization.md) and [schema guide](schema.md).
