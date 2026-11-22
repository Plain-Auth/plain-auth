import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { generateKeyPair, SignJWT } from "jose";

export async function exerciseClientAssertions({ server, issuer, keyed, signer, key }) {
  const mount = server.baseURL + "/api/auth";
  const peer = "http://issuer.localhost/api/auth";
  const id = keyed.client_id;
  const type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  function sign(claims = {}, privateKey = signer.privateKey) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ sub: id, iss: id, aud: mount, exp: now + 90, iat: now, jti: randomUUID(), ...claims })
      .setProtectedHeader({ alg: "ES256", kid: key.kid }).sign(privateKey);
  }
  function send(endpoint, assertion, fields, toPeer = false) {
    const request = new Request((toPeer ? peer : mount) + "/oauth2/" + endpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_assertion: assertion, client_assertion_type: type, ...fields }),
    });
    return toPeer ? issuer.handler(request) : server.send(request);
  }
  async function problem(req, status, code) {
    const res = await req;
    const body = await res.json();
    assert.equal(res.status, status, JSON.stringify(body));
    assert.equal(body.error, code);
    if (status === 401) assert.match(res.headers.get("www-authenticate") ?? "", /^Basic\b/);
    return body;
  }
  const grant = { grant_type: "client_credentials" };
  const a = await sign({ aud: [mount + "/oauth2/token", peer + "/oauth2/introspect"] });
  const issued = await send("token", a, grant);
  const token = await issued.json();
  assert.equal(issued.status, 200, JSON.stringify(token));
  assert.equal(token.scope, "reports");
  const inspect = { token: token.access_token };
  const replay = await problem(send("introspect", a, inspect, true), 400, "invalid_client");
  assert.match(replay.error_description, /already been used/);
  const common = await sign({ aud: [mount, peer] });
  const active = await send("introspect", common, inspect, true);
  assert.equal((await active.json()).active, true);
  assert.match((await problem(send("revoke", common, inspect), 400, "invalid_client")).error_description, /already been used/);

  const valid = await send("introspect", await sign({ aud: mount + "/oauth2/introspect" }), { ...inspect, client_id: id });
  assert.equal((await valid.json()).client_id, id);
  await problem(send("revoke", await sign({ aud: mount + "/oauth2/token" }), inspect), 401, "invalid_client");
  assert.equal((await send("revoke", await sign(), inspect)).status, 200);
  assert.deepEqual(await (await send("introspect", await sign(), inspect)).json(), { active: false });

  const now = Math.floor(Date.now() / 1000);
  for (const claims of [{ exp: now - 5 }, { nbf: now + 60 }, { iss: "another-client" }, { sub: undefined }, { aud: "https://another.example" }]) {
    await problem(send("token", await sign(claims), grant), 401, "invalid_client");
  }
  for (const claims of [{ exp: undefined }, { exp: now + 900 }, { iat: now - 900 }, { jti: "" }]) {
    await problem(send("token", await sign(claims), grant), 400, "invalid_client");
  }
  const other = await generateKeyPair("ES256");
  await problem(send("token", await sign({}, other.privateKey), grant), 401, "invalid_client");
  await problem(send("token", await sign(), { ...grant, client_id: "mismatched" }), 400, "invalid_client");
  await problem(send("token", await sign(), { ...grant, client_secret: "mixed" }), 400, "invalid_request");
  await problem(send("token", "invalid", grant), 400, "invalid_client");
  const singleUse = await sign();
  await problem(send("token", singleUse, { ...grant, scope: "ungranted" }), 400, "invalid_scope");
  await problem(send("token", singleUse, grant), 400, "invalid_client");
}
