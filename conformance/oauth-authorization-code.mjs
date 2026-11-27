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

export async function exerciseOfflineCode({ server, issuer, db }) {
  const { peer, app, fields, user, authorizeCode } = await authorizationCodeClient(issuer, db, {
    name: "Offline owner", email: "offline-issuance@issuer.test", scopes: ["reports", "offline_access"],
    callback: "https://reports.example.test/offline",
  });
  const post = (base, route, values) => new Request(base + "/oauth2/" + route, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values),
  });
  const code = await authorizeCode();
  const mount = server.baseURL + "/api/auth";
  const res = await server.send(post(mount, "token", code));
  const pair = await res.json();
  assert.equal(res.status, 200, JSON.stringify(pair));
  assert.equal(pair.scope, "reports offline_access");
  assert.equal(pair.expires_in, 90);
  assert.match(pair.refresh_token, /^[a-zA-Z]{32}$/);
  // The response carries exactly these fields, and expires_at agrees with expires_in.
  assert.deepEqual(Object.keys(pair).sort(), ["access_token", "expires_at", "expires_in", "refresh_token", "scope", "token_type"]);
  assert.ok(Math.abs(pair.expires_at - Math.floor(Date.now() / 1000) - pair.expires_in) <= 5, JSON.stringify(pair));
  const digest = s => createHash("sha256").update(s).digest("base64url");
  const refresh = db.prepare("SELECT * FROM oauthRefreshToken WHERE token=?").get(digest(pair.refresh_token));
  const access = db.prepare("SELECT * FROM oauthAccessToken WHERE refreshId=?").get(refresh.id);
  const browser = db.prepare("SELECT * FROM session WHERE id=?").get(refresh.sessionId);
  assert.equal(refresh.userId, user);
  assert.equal(refresh.clientId, app.client_id);
  assert.equal(access.authorizationCodeId, digest(code.code));
  assert.equal(refresh.authorizationCodeId, access.authorizationCodeId);
  assert.equal(access.sessionId, browser.id);
  assert.equal(Date.parse(refresh.expiresAt) - Date.parse(refresh.createdAt), 30 * 24 * 3600 * 1000);
  assert.equal(Date.parse(refresh.authTime), Date.parse(browser.createdAt));
  const inspect = async raw => {
    const r = await issuer.handler(post(peer, "introspect", { ...fields, token: raw }));
    assert.equal(r.status, 200);
    return r.json();
  };
  assert.equal((await inspect(pair.refresh_token)).sid, browser.id);
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00.000Z", browser.id);
  assert.equal((await inspect(pair.access_token)).active, false);
  assert.equal((await inspect(pair.refresh_token)).active, true);
  const rotation = await issuer.handler(post(peer, "token", { ...fields, grant_type: "refresh_token", refresh_token: pair.refresh_token }));
  const rotated = await rotation.json();
  assert.equal(rotation.status, 200, JSON.stringify(rotated));
  assert.ok(rotated.refresh_token && rotated.refresh_token !== pair.refresh_token);
  assert.equal((await inspect(rotated.refresh_token)).active, true);
  const replay = await server.send(post(mount, "token", code));
  assert.equal(replay.status, 400);
  assert.equal((await replay.json()).error, "invalid_grant");
  assert.deepEqual(await inspect(rotated.refresh_token), { active: false });
  assert.deepEqual(await inspect(rotated.access_token), { active: false });
}
