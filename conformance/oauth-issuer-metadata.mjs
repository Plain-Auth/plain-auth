import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { createLocalJWKSet, jwtVerify } from "jose";

export async function compareIssuerMetadata(t, { reference, goFixture }) {
  const issuer = "https://discovery.example.test/tenant/acme";
  const keyPath = "/keys/public";
  const supported = ["private_key_jwt", "client_secret_post"];
  const referenceOptions = {
    loginPage: "/login", consentPage: "/consent", scopes: ["reports", "extra"],
    grantTypes: ["client_credentials"], allowDynamicClientRegistration: true,
    dpop: { signingAlgorithms: ["ES256"] },
    advertisedMetadata: { scopes_supported: ["reports"], token_endpoint_auth_methods_supported: supported },
    validateInitialAccessToken: ({ initialAccessToken }) => initialAccessToken === "initial" && { referenceId: "workspace" },
  };
  let expected;
  for (const runtime of ["reference", "Go"]) {
    await t.test(runtime, async t => {
      const server = runtime === "reference" ? await reference(t, [
        jwt({ jwt: { issuer }, jwks: { jwksPath: keyPath } }), oauthProvider(referenceOptions),
      ], { rateLimit: { enabled: false } }) : await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "protected", CONFORMANCE_DISCOVERY_ISSUER: issuer,
        CONFORMANCE_JWKS_PATH: keyPath, CONFORMANCE_ISSUER_METADATA: "1",
      });
      const fetch = (url, opts) => server.send(new Request(url, opts));
      const mount = server.baseURL + "/api/auth";
      const primary = "/.well-known/oauth-authorization-server/tenant/acme";
      const alternate = "/tenant/acme/.well-known/oauth-authorization-server";
      const first = await fetch(server.baseURL + primary + "?cache=1");
      assert.equal(first.status, 200);
      assert.equal(first.headers.get("content-type"), "application/json");
      assert.equal(first.headers.get("cache-control"), "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400");
      const doc = await first.json();
      for (const path of [primary, alternate]) {
        const r = await fetch(server.baseURL + path);
        assert.deepEqual(await r.json(), doc);
        const head = await fetch(server.baseURL + path, { method: "HEAD" });
        assert.equal(head.status, 200);
        assert.equal(head.headers.get("cache-control"), first.headers.get("cache-control"));
        assert.equal(await head.text(), "");
        for (const method of ["POST", "OPTIONS"]) {
          const denied = await fetch(server.baseURL + path, { method });
          assert.equal(denied.status, 405);
          assert.equal(denied.headers.get("allow"), "GET, HEAD");
          assert.equal(await denied.text(), "");
        }
      }
      assert.equal(doc.issuer, issuer);
      assert.deepEqual(doc.grant_types_supported, ["client_credentials"]);
      assert.deepEqual(doc.response_types_supported, []);
      assert.deepEqual(doc.scopes_supported, ["reports"]);
      assert.deepEqual(doc.token_endpoint_auth_methods_supported, supported);
      assert.deepEqual(doc.dpop_signing_alg_values_supported, ["ES256"]);
      for (const [key, path] of Object.entries({
        token_endpoint: "/oauth2/token", registration_endpoint: "/oauth2/register",
        introspection_endpoint: "/oauth2/introspect", revocation_endpoint: "/oauth2/revoke", jwks_uri: keyPath,
      })) assert.equal(doc[key], mount + path);
      const common = Object.fromEntries(Object.entries(doc).filter(([k]) =>
        k.includes("endpoint_auth_") || ["grant_types_supported", "response_types_supported", "scopes_supported", "dpop_signing_alg_values_supported"].includes(k)));
      if (runtime === "reference") expected = common;
      else {
        assert.deepEqual(common, expected);
        for (const key of ["authorization_endpoint", "code_challenge_methods_supported", "end_session_endpoint", "id_token_signing_alg_values_supported"]) {
          assert.equal(doc[key], undefined);
        }
      }
      assert.equal((await fetch(server.baseURL + "/tenant/acme/.well-known/openid-configuration")).status, 404);
      const registered = await fetch(doc.registration_endpoint, {
        method: "POST", headers: { "content-type": "application/json", authorization: "Bearer initial" },
        body: JSON.stringify({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" }),
      });
      const client = await registered.json();
      assert.equal(registered.status, 201, JSON.stringify(client));
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const api = "urn:reports";
      db.prepare("UPDATE oauthClient SET clientCredentialsScopes=? WHERE clientId=?").run('["reports"]', client.client_id);
      db.prepare("INSERT INTO oauthResource(id,identifier,name) VALUES(?,?,?)").run(randomUUID(), api, "Reports");
      db.prepare("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES(?,?,?)").run(randomUUID(), client.client_id, api);
      const post = (endpoint, params) => fetch(endpoint, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: client.client_id, client_secret: client.client_secret, ...params }),
      });
      const getToken = async params => {
        const r = await post(doc.token_endpoint, { grant_type: "client_credentials", scope: "reports", ...params });
        const obj = await r.json();
        assert.equal(r.status, 200, JSON.stringify(obj));
        return obj.access_token;
      };
      const signed = await getToken({ resource: api });
      const keys = createLocalJWKSet(await (await fetch(doc.jwks_uri)).json());
      const { payload } = await jwtVerify(signed, keys, { issuer: doc.issuer, audience: api, typ: "at+jwt" });
      assert.equal(payload.sub, client.client_id);
      const inspect = async token => (await post(doc.introspection_endpoint, { token })).json();
      assert.equal((await inspect(signed)).active, true);
      const opaque = await getToken({});
      assert.equal((await inspect(opaque)).active, true);
      assert.equal((await post(doc.revocation_endpoint, { token: opaque })).status, 200);
      assert.deepEqual(await inspect(opaque), { active: false });
    });
  }
}
