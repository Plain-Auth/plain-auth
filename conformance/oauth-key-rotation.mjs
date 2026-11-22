import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export async function exerciseClientKeyRotation({ server, issuer, keyed, signer, key }) {
  const mount = server.baseURL + "/api/auth";
  const path = "/oauth2/client/rotate-keys";
  const peer = "http://issuer.localhost/api/auth";
  const type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  const next = await generateKeyPair("ES256");
  const nextKey = { ...await exportJWK(next.publicKey), alg: "ES256", kid: "new-key" };
  const sign = (pair, kid, aud = mount + path) => new SignJWT({})
    .setIssuer(keyed.client_id).setSubject(keyed.client_id).setAudience(aud)
    .setProtectedHeader({ alg: "ES256", kid }).setIssuedAt().setExpirationTime("90s").setJti(randomUUID()).sign(pair.privateKey);
  function rotate(assertion, keys) {
    return server.send(new Request(mount + path, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_assertion: assertion, client_assertion_type: type, jwks: { keys, unknown_top_level_field: "omitted" } }) }));
  }
  async function reject(assertion, keys, status, error) {
    const res = await rotate(assertion, keys);
    const body = await res.json();
    assert.equal(res.status, status, JSON.stringify(body));
    assert.equal(body.error, error);
  }
  async function inspect(pair, kid, host, status) {
    const res = await host(new Request(peer + "/oauth2/introspect", { method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({
        token: "unknown", client_assertion_type: type, client_assertion: await sign(pair, kid, peer + "/oauth2/introspect"),
      }) }));
    assert.equal(res.status, status, await res.text());
  }
  for (const aud of [mount, mount + "/oauth2/token", [mount, mount + "/oauth2/introspect"]]) {
    await reject(await sign(signer, key.kid, aud), [nextKey], 401, "invalid_client");
  }
  const once = await sign(signer, key.kid, [mount, mount + path]);
  for (const invalid of [[], [{ kty: "oct", k: "abc" }], [{ ...key, d: "private" }]]) {
    await reject(once, invalid, 400, "invalid_client_metadata");
  }
  const overlap = await rotate(once, [key, nextKey]);
  const body = await overlap.json();
  assert.equal(overlap.status, 200, JSON.stringify(body));
  assert.match(overlap.headers.get("cache-control"), /no-store/);
  assert.deepEqual(body, { client_id: keyed.client_id, jwks: { keys: [key, nextKey] } });
  await reject(once, [key], 400, "invalid_client");
  await inspect(signer, key.kid, issuer.handler, 200);
  await inspect(next, nextKey.kid, issuer.handler, 200);
  const retired = await rotate(await sign(next, nextKey.kid), [nextKey]);
  assert.equal(retired.status, 200, await retired.text());
  await inspect(signer, key.kid, issuer.handler, 401);
  await inspect(next, nextKey.kid, issuer.handler, 200);
  await reject(await sign(signer, key.kid), [key], 401, "invalid_client");
}
