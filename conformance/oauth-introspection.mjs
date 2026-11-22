import assert from "node:assert/strict";

export async function exerciseIntrospection({ server, issuer, exchange, credentials, created, cookie, setMachineScopes }) {
  const auth = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const fields = { ...auth, token: "unknown" };
  const media = "application/x-www-form-urlencoded";
  async function inspect(form, headers = {}) {
    return server.send(new Request(server.baseURL + "/api/auth/oauth2/introspect", {
      method: "POST", headers: { "content-type": media, ...headers }, body: new URLSearchParams(form),
    }));
  }
  async function response(form, headers) {
    const res = await inspect(form, headers);
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.match(res.headers.get("cache-control"), /no-store/);
    assert.equal(res.headers.get("pragma"), "no-cache");
    return body;
  }
  async function problem(form, headers, status, code, challenge) {
    const res = await inspect(form, headers);
    const body = await res.json();
    assert.equal(res.status, status, JSON.stringify(body));
    assert.equal(body.error, code);
    assert.equal(res.headers.get("www-authenticate"), challenge ?? null);
  }

  const issued = await exchange(auth.client_secret);
  const token = await issued.json();
  assert.equal(issued.status, 200, JSON.stringify(token));
  const active = await response({ ...auth, token: token.access_token });
  assert.deepEqual(active, {
    active: true, iss: server.baseURL + "/api/auth", client_id: auth.client_id, azp: auth.client_id,
    exp: token.expires_at, iat: token.expires_at - 90, scope: "reports", token_type: "Bearer",
  });
  for (const [value, hint] of [
    [token.access_token, "access_token"], [" bEArer   " + token.access_token + " ", "unexpected"],
    ["DPoP\t" + token.access_token, ""],
  ]) {
    assert.deepEqual(await response({ ...auth, token: value, token_type_hint: hint }), active);
  }
  for (const form of [
    fields, { ...auth, token: token.access_token.slice("access_".length) },
    { ...auth, token: token.access_token, token_type_hint: "refresh_token" },
  ]) assert.deepEqual(await response(form), { active: false });
  const peer = await created({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_basic" }, { cookie });
  const authorization = "Basic " + Buffer.from(peer.client_id + ":" + peer.client_secret).toString("base64");
  assert.deepEqual(await response({ token: token.access_token }, { authorization }), { active: false });
  await setMachineScopes(peer.client_id, ["extra"]);
  const peerIssued = await server.send(new Request(server.baseURL + "/api/auth/oauth2/token", {
    method: "POST", headers: { "content-type": media, authorization },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
  }));
  const peerToken = await peerIssued.json();
  assert.equal(peerIssued.status, 200, JSON.stringify(peerToken));
  const own = await response({ token: peerToken.access_token }, { authorization });
  assert.equal(own.active, true);
  assert.equal(own.client_id, peer.client_id);
  assert.equal(own.scope, "extra");
  assert.equal(own.exp, peerToken.expires_at);
  assert.deepEqual(await response({ ...auth, token: peerToken.access_token }), { active: false });
  await problem({}, {}, 400, "invalid_request");
  await problem({ token: token.access_token }, { cookie, origin: server.baseURL }, 401, "invalid_client", "Basic");
  await problem({ client_id: auth.client_id, token: token.access_token }, {}, 401, "invalid_client", "Basic");
  await problem({ ...auth, token: "" }, {}, 400, "invalid_request");
  await problem({ ...fields, client_secret: "invalid" }, {}, 400, "invalid_client");
  await problem(fields, { authorization }, 400, "invalid_request");
  await problem({ token: "unknown" }, { authorization: "Basic invalid!" }, 401, "invalid_client", "Basic");
  const duplicate = new URLSearchParams(fields);
  duplicate.append("client_id", auth.client_id);
  await problem(duplicate, {}, 400, "invalid_request");
  const revoked = await issuer.handler(new Request("http://issuer.localhost/api/auth/oauth2/revoke", {
    method: "POST", headers: { "content-type": media },
    body: new URLSearchParams({ ...auth, token: token.access_token, token_type_hint: "access_token" }),
  }));
  assert.equal(revoked.status, 200);
  assert.deepEqual(await response({ ...auth, token: token.access_token }), { active: false });
}
