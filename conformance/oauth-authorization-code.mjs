import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { authorizationCodeClient } from "./oauth-refresh-introspection.mjs";

export async function exerciseAuthorizationCode({ server, issuer, db }) {
  const { peer, app, fields, user, authorizeCode } = await authorizationCodeClient(issuer, db, {
    name: "PKCE client owner", email: "code-redemption@issuer.test", scopes: ["reports"],
    callback: "https://reports.example.test/pkce",
  });
  const request = (mount, endpoint, values) => new Request(mount + "/oauth2/" + endpoint, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values),
  });
  const exchange = values => server.send(request(server.baseURL + "/api/auth", "token", values));
  async function inspect(token) {
    const res = await issuer.handler(request(peer, "introspect", { ...fields, token }));
    assert.equal(res.status, 200);
    return res.json();
  }
  async function redeem(values) {
    const res = await exchange(values);
    const token = await res.json();
    assert.equal(res.status, 200, JSON.stringify(token));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(token.scope, "reports");
    assert.equal(token.token_type, "Bearer");
    assert.equal(token.expires_in, 90);
    assert.ok(token.access_token.startsWith("access_"));
    assert.equal(token.refresh_token, undefined);
    assert.equal(token.id_token, undefined);
    return token.access_token;
  }
  const original = await authorizeCode();
  for (const [overrides, error] of [
    [{ code_verifier: "incorrect" }, "invalid_grant"], [{ redirect_uri: "https://reports.example.test/PKCE" }, "invalid_grant"],
    [{ redirect_uri: "" }, "invalid_request"], [{ code_verifier: "" }, "invalid_request"],
  ]) {
    const res = await exchange({ ...original, ...overrides });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, error);
  }
  const token = await redeem(original);
  const second = await redeem(await authorizeCode());
  const observed = await inspect(token);
  assert.equal(observed.active, true);
  assert.equal(observed.client_id, app.client_id);
  assert.equal(observed.scope, "reports");
  assert.ok(observed.sid);
  const digest = createHash("sha256").update(original.code).digest("base64url");
  const row = db.prepare("SELECT token,userId,sessionId FROM oauthAccessToken WHERE authorizationCodeId=?").get(digest);
  assert.equal(row.userId, user);
  assert.equal(row.sessionId, observed.sid);
  assert.equal(row.token, createHash("sha256").update(token.slice("access_".length)).digest("base64url"));
  const replay = await exchange(original);
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "invalid_grant");
  assert.deepEqual(await inspect(token), { active: false });
  assert.equal((await inspect(second)).active, true);
}
