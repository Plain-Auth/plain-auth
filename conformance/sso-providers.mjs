import assert from "node:assert/strict";
import {createServer} from "node:http";
import {once} from "node:events";
import { DatabaseSync } from "node:sqlite";
import { sso } from "@better-auth/sso";
import { ssoClient } from "@better-auth/sso/client";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

export async function providerCatalog(t, {goFixture, instrument}) {
  let issuer;
  let discoveries = 0;
  const idp = createServer((req, res) => {
    if (req.url !== "/tenant/.well-known/openid-configuration") { res.writeHead(404).end(); return; }
    discoveries++;
    res.writeHead(200, {"content-type":"application/json"}).end(JSON.stringify({
      issuer, authorization_endpoint:"/authorize", token_endpoint:"token", jwks_uri:"/keys",
      token_endpoint_auth_methods_supported:["client_secret_post"],
    }));
  });
  idp.listen(0, "127.0.0.1");
  await once(idp, "listening");
  t.after(() => new Promise(resolve => idp.close(resolve)));
  const origin = "http://127.0.0.1:" + idp.address().port;
  issuer = origin + "/tenant";
  const go = await goFixture(t, ["sso"], {CONFORMANCE_SSO_DISCOVERY_ORIGIN: origin});
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const options = {
    baseURL: "http://reference.localhost",
    secret: "local-conformance-0123456789-abcdefghijk",
    emailAndPassword: {enabled: true},
    trustedOrigins: [origin],
    database: {type: "sqlite", dialect: new NodeSqliteDialect({database: db}), transaction: true},
    plugins: [sso()],
    telemetry: {enabled: false},
  };
  await (await getMigrations(options)).runMigrations();
  const reference = betterAuth(options);
  const ts = {baseURL: options.baseURL, send: r => reference.handler(r)};
  // Observe the wire headers on the Go handler alongside the released SDK.
  const goWithCacheCheck = { ...go, send: async request => {
    const response = await go.send(request);
    if (new URL(request.url).pathname.endsWith("/sso/register")) {
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
    return response;
  } };
  const client = server => instrument(server === go ? goWithCacheCheck : server, [ssoClient()]).client;
  const success = res => {assert.equal(res.error, null, JSON.stringify(res.error));return res.data;};
  for (const [n, [creator, peer]] of [[go, ts], [ts, go]].entries()) {
    const credentials = {email: "sso-admin-" + n + "@example.test", password: "valid-long-password"};
    const first = client(creator), other = client(peer);
    success(await first.signUp.email({...credentials, name: "Enterprise owner"}));
    success(await other.signIn.email(credentials));
    const providerId = "enterprise-" + n;
    const oidcConfig = {
      clientId: "private-client-5678", clientSecret: "fixture-raw-oidc-secret",
      scopes: ["openid", "email"],
    };
    const body = {providerId, issuer, domain: "example.org", oidcConfig};
    const record = success(await first.sso.register(body));
    assert.equal(record.providerId, providerId);
    assert.equal(record.oidcConfig.pkce, true);
    assert.equal(record.oidcConfig.tokenEndpointAuthentication, "client_secret_post");
    assert.equal(record.oidcConfig.clientSecret, oidcConfig.clientSecret);
    assert.equal(record.redirectURI, creator.baseURL + "/api/auth/sso/callback/" + providerId);
    const fetched = success(await other.sso.getProvider({query: {providerId}}));
    assert.equal(fetched.providerId, providerId);
    assert.equal(fetched.domainVerified, false);
    assert.equal(fetched.organizationId, null);
    assert.equal(fetched.oidcConfig.clientIdLastFour, "****5678");
    assert.equal(fetched.oidcConfig.jwksEndpoint, issuer + "/keys");
    assert.deepEqual(fetched.oidcConfig.scopes, oidcConfig.scopes);
    assert.ok(!JSON.stringify(fetched).includes(oidcConfig.clientSecret));
    assert.ok(!JSON.stringify(fetched).includes(oidcConfig.clientId));
    const page = success(await other.sso.providers());
    assert.deepEqual(page.providers, [fetched]);
    assert.equal((await other.sso.register(body)).error.status, 422);
    const unauthenticated = client(peer);
    assert.equal((await unauthenticated.sso.providers()).error.status, 401);
    success(await unauthenticated.signUp.email({email: "sso-foreign-" + n + "@example.test",password:"valid-long-password",name:"Unrelated"}));
    assert.deepEqual(success(await unauthenticated.sso.providers()).providers, []);
    assert.equal((await unauthenticated.sso.getProvider({query:{providerId}})).error.status, 403);
    const manualId = providerId + "-manual";
    const manual = success(await first.sso.register({...body, providerId: manualId, oidcConfig: {
      ...oidcConfig, skipDiscovery:true, authorizationEndpoint: issuer + "/authorize",
      tokenEndpoint: issuer + "/token", jwksEndpoint: issuer + "/keys", pkce: false,
    }}));
    assert.equal(manual.oidcConfig.pkce, false);
    const manualRead = success(await other.sso.getProvider({query:{providerId:manualId}}));
    assert.equal(manualRead.oidcConfig.pkce, false);
  }
  assert.equal(discoveries, 2);
}
