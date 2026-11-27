import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export async function exerciseMachineTokens({ server, issuer, db, credentials, cookie, created, setMachineScopes }) {
  const grant = { grant_type: "client_credentials" };
  const bodyClient = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const basicClient = await created({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_basic" }, { cookie });
  // A confidential registration without a method defaults to client_secret_basic.
  const defaulted = await created({ grant_types: ["client_credentials"] }, { cookie });
  assert.equal(defaulted.token_endpoint_auth_method, "client_secret_basic");
  await setMachineScopes(basicClient.client_id, ["extra", "reports"]);
  function basic(id, secret) {
    const encode = s => new URLSearchParams({ v: s }).toString().slice(2);
    return "bAsIc   " + Buffer.from(encode(id) + ":" + encode(secret)).toString("base64");
  }
  const authHeader = { authorization: basic(basicClient.client_id, basicClient.client_secret) };
  const formType = "application/x-www-form-urlencoded";
  async function request(fields, headers = {}, mediaType = formType) {
    const req = new Request(server.baseURL + "/api/auth/oauth2/token", {
      method: "POST", headers: { "content-type": mediaType, ...headers }, body: new URLSearchParams(fields),
    });
    return server.send(req);
  }
  async function error(fields, status, code, headers = {}, challenge, description) {
    const response = await request(fields, headers);
    const body = await response.json();
    assert.equal(response.status, status, JSON.stringify(body));
    assert.equal(body.error, code, JSON.stringify(body));
    if (description !== undefined) assert.equal(body.error_description, description);
    assert.equal(response.headers.get("www-authenticate"), challenge ?? null);
    if (challenge) assert.match(response.headers.get("access-control-expose-headers"), /WWW-Authenticate/i);
    // The reference validates the presence of grant_type before the token handler runs.
    if (fields.grant_type || fields instanceof URLSearchParams || server.databasePath) {
      assert.match(response.headers.get("cache-control"), /no-store/);
    }
  }
  async function introspect(token, client = bodyClient) {
    const url = "http://issuer.localhost/api/auth/oauth2/introspect";
    const response = await issuer.handler(new Request(url, {
      method: "POST", headers: { "content-type": formType },
      body: new URLSearchParams({ ...client, token, token_type_hint: "access_token" }),
    }));
    assert.equal(response.status, 200);
    return response.json();
  }
  const r = await request({ ...grant, ...bodyClient, scope: "reports" }, {}, formType + "; charset=UTF-8");
  const issued = await r.json();
  assert.equal(r.status, 200, JSON.stringify(issued));
  assert.match(r.headers.get("cache-control"), /no-store/);
  assert.equal(r.headers.get("pragma"), "no-cache");
  assert.deepEqual(Object.keys(issued).sort(), ["access_token", "expires_at", "expires_in", "scope", "token_type"]);
  assert.equal(issued.token_type, "Bearer");
  assert.equal(issued.scope, "reports");
  assert.equal(issued.expires_in, 90);
  assert.match(issued.access_token, /^access_[A-Za-z]{32}$/);
  const hash = createHash("sha256").update(issued.access_token.slice("access_".length)).digest("base64url");
  const row = db.prepare("SELECT token, clientId, userId, sessionId, refreshId, scopes, createdAt, expiresAt FROM oauthAccessToken WHERE token=?").get(hash);
  assert.equal(row.clientId, credentials.client_id);
  assert.equal(row.userId, null);
  assert.equal(row.sessionId, null);
  assert.equal(row.refreshId, null);
  assert.deepEqual(JSON.parse(row.scopes), ["reports"]);
  const info = await introspect(issued.access_token);
  assert.equal(info.active, true);
  assert.equal(info.client_id, credentials.client_id);
  assert.equal(info.scope, "reports");
  assert.equal(info.exp, issued.expires_at);
  assert.equal(info.exp - info.iat, 90);
  assert.equal(info.sub, undefined);
  assert.deepEqual(await introspect("access_missing"), { active: false });

  for (const [fields, scope, ttl] of [
    [grant, "extra reports", 90],
    [{ ...grant, scope: "extra" }, "extra", 600],
    [{ ...grant, client_id: "ignored", scope: "reports" }, "reports", 90],
  ]) {
    const response = await request(fields, authHeader);
    const token = await response.json();
    assert.equal(response.status, 200, JSON.stringify(token));
    assert.equal(token.scope, scope);
    assert.equal(token.expires_in, ttl);
  }
  // The defaulted client authenticates with a Basic header.
  await setMachineScopes(defaulted.client_id, ["reports"]);
  const defaultedToken = await request(grant, { authorization: basic(defaulted.client_id, defaulted.client_secret) });
  assert.equal(defaultedToken.status, 200);
  assert.equal((await defaultedToken.json()).scope, "reports");
  await error(grant, 401, "invalid_client", { authorization: basic(defaulted.client_id, "wrong") }, "Basic");
  await error({}, 400, "invalid_request", {}, undefined, "grant_type is required");
  await error({ grant_type: "unknown" }, 400, "unsupported_grant_type");
  await error(grant, 400, "invalid_request", {}, undefined, "Missing required client_id");
  await error({ ...grant, client_id: "absent", client_secret: "bad" }, 400, "invalid_client");
  await error({ ...grant, ...bodyClient, client_secret: "bad" }, 400, "invalid_client");
  await error({ ...grant, ...bodyClient, client_secret: credentials.client_secret.slice("fixture_".length) }, 400, "invalid_client");
  await error(grant, 401, "invalid_client", { authorization: basic(basicClient.client_id, "wrong") }, "Basic");
  await error(grant, 401, "invalid_client", { authorization: basic(credentials.client_id, credentials.client_secret) }, "Basic");
  await error(grant, 401, "invalid_client", { authorization: "Basic invalid!" }, "Basic");
  await error(grant, 401, "invalid_client", { authorization: "Bearer example" }, "Bearer");
  await error({ ...grant, ...bodyClient }, 400, "invalid_request", authHeader);
  await error({ ...grant, client_id: credentials.client_id, client_assertion: "value" }, 400, "invalid_client");
  // A secret and an assertion, in the body or with a Basic header, are two methods.
  const assertion = { client_assertion: "value", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" };
  await error({ ...grant, ...bodyClient, ...assertion }, 400, "invalid_request", {}, undefined, "A request must use only one client authentication method");
  await error({ ...grant, ...assertion }, 400, "invalid_request", authHeader, undefined, "A request must use only one client authentication method");
  for (const key of ["client_id", "client_secret", "client_assertion", "client_assertion_type"]) {
    const form = new URLSearchParams(grant);
    form.append(key, "one");
    form.append(key, "two");
    await error(form, 400, "invalid_request", {}, undefined, key + " must not be repeated");
  }
  const empties = new URLSearchParams({ ...grant, ...bodyClient });
  empties.append("client_id", "");
  empties.append("client_secret", "");
  assert.equal((await request(empties)).status, 200);
  for (const scope of ["", "openid", "extra", "reports  reports"]) {
    await error({ ...grant, ...bodyClient, scope }, 400, "invalid_scope");
  }
  const wrongType = await request(grant, {}, "application/json");
  assert.equal(wrongType.status, 415);
  assert.equal((await wrongType.json()).code, "UNSUPPORTED_MEDIA_TYPE");
  const prior = db.prepare("SELECT dpopBoundAccessTokens AS required FROM oauthClient WHERE clientId=?").get(credentials.client_id);
  const update = db.prepare("UPDATE oauthClient SET dpopBoundAccessTokens=? WHERE clientId=?");
  update.run(1, credentials.client_id);
  try {
    await error({ ...grant, ...bodyClient }, 400, "invalid_dpop_proof");
  } finally {
    update.run(prior.required, credentials.client_id);
  }
  await error({ ...grant, ...bodyClient }, 400, "invalid_dpop_proof", { dpop: "not-a-proof" });
  await error({ ...grant, ...bodyClient, resource: "urn:absent-resource" }, 400, "invalid_target");
  const revoke = await issuer.handler(new Request("http://issuer.localhost/api/auth/oauth2/revoke", {
    method: "POST", headers: { "content-type": formType },
    body: new URLSearchParams({ ...bodyClient, token: issued.access_token, token_type_hint: "access_token" }),
  }));
  assert.equal(revoke.status, 200);
  assert.deepEqual(await introspect(issued.access_token), { active: false });
}
