import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";

// The metadata contributor both runtimes register.
export function extensionMetadata({ type }) {
  return { credential_issuer: "https://wallet.example.test/" + type, issuer: "forged", token_endpoint: "forged" };
}

// An extension adds discovery fields to each served document and cannot
// replace the provider's own.
export async function compareExtensionMetadata(t, { reference, goFixture }) {
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", scopes: ["openid", "email", "reports", "extra"],
        extensions: [{ metadata: input => extensionMetadata({ type: input.type }) }],
      })], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_OAUTH_EXTENSIONS: "1",
      });
      const res = await server.send(new Request(server.baseURL + "/api/auth/.well-known/openid-configuration"));
      assert.equal(res.status, 200);
      const doc = await res.json();
      assert.equal(doc.credential_issuer, "https://wallet.example.test/openid-configuration");
      assert.equal(doc.issuer, server.baseURL + "/api/auth");
      assert.equal(doc.token_endpoint, server.baseURL + "/api/auth/oauth2/token");
    });
  }
}

// The extension grant both runtimes register: it authenticates the client
// for the requested scopes and issues a client token for them.
export const extensionGrant = "urn:conformance:client";

async function clientGrant({ ctx, provider }) {
  const scopes = ctx.body.scope ? ctx.body.scope.split(" ") : [];
  const { client } = await provider.authenticateClient({ scopes });
  return provider.issueTokens({ client, scopes, tokenResponse: { tenant: "handler" } });
}

// An extension grant authenticates its client through the provider and
// issues an opaque client token with the client credentials lifetime,
// which introspects like one; discovery lists the grant, and a wrong secret
// or a client not registered for the grant is refused.
export async function compareExtensionGrant(t, { reference, goFixture }) {
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", scopes: ["openid", "email", "reports", "extra"],
        m2mAccessTokenExpiresIn: 600, scopeExpirations: { reports: "90s" },
        prefix: { clientSecret: "fixture_", opaqueAccessToken: "access_" },
        extensions: [{ metadata: input => extensionMetadata({ type: input.type }), grants: { [extensionGrant]: clientGrant } }],
      })], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_OAUTH_EXTENSIONS: "1",
      });
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const raw = "local-grant-secret", secret = "fixture_" + raw;
      const stored = createHash("sha256").update(raw).digest("base64url");
      for (const [id, grants] of [["granted", [extensionGrant]], ["machine", ["client_credentials"]]]) {
        db.prepare("INSERT INTO oauthClient(id,clientId,clientSecret,tokenEndpointAuthMethod,grantTypes,redirectUris) VALUES (?,?,?,?,?,?)")
          .run(randomUUID(), id, stored, "client_secret_post", JSON.stringify(grants), "[]");
      }
      const mount = server.baseURL + "/api/auth";
      const post = (route, fields) => server.send(new Request(mount + "/oauth2/" + route, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields),
      }));
      const response = await post("token", { grant_type: extensionGrant, client_id: "granted", client_secret: secret, scope: "extra" });
      const token = await response.json();
      assert.equal(response.status, 200, JSON.stringify(token));
      assert.match(response.headers.get("cache-control"), /no-store/);
      assert.deepEqual(Object.keys(token).sort(), ["access_token", "expires_at", "expires_in", "scope", "tenant", "token_type"]);
      assert.equal(token.token_type, "Bearer");
      assert.equal(token.scope, "extra");
      assert.equal(token.expires_in, 600);
      assert.equal(token.tenant, "handler");
      assert.match(token.access_token, /^access_/);
      const info = await (await post("introspect", { client_id: "granted", client_secret: secret, token: token.access_token })).json();
      assert.equal(info.active, true, JSON.stringify(info));
      assert.equal(info.client_id, "granted");
      assert.equal(info.scope, "extra");
      assert.equal(info.sub, undefined);
      for (const [fields, error, description] of [
        [{ client_id: "granted", client_secret: "fixture_wrong" }, "invalid_client", "invalid client_secret"],
        [{ client_id: "machine", client_secret: secret }, "unauthorized_client", "client is not authorized to use grant type " + extensionGrant],
      ]) {
        const refused = await post("token", { grant_type: extensionGrant, scope: "extra", ...fields });
        const body = await refused.json();
        assert.equal(refused.status, 400, JSON.stringify(body));
        assert.equal(body.error, error);
        assert.equal(body.error_description, description);
      }
      const doc = await (await server.send(new Request(mount + "/.well-known/openid-configuration"))).json();
      assert.ok(doc.grant_types_supported.includes(extensionGrant), JSON.stringify(doc.grant_types_supported));
    });
  }
}
