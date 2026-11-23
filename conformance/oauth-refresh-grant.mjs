import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { authorizationCodeClient } from "./oauth-refresh-introspection.mjs";

export async function exerciseRefreshGrant({ server, issuer, db }) {
  const { peer, app, fields, user, authorizeCode } = await authorizationCodeClient(issuer, db, {
    name: "Refresh exchange owner", email: "refresh-exchange@issuer.test",
    scopes: ["reports", "offline_access"], callback: "https://reports.example.test/refresh",
  });
  const mount = server.baseURL + "/api/auth";
  const request = (base, path, form) => new Request(base + "/oauth2/" + path, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form),
  });
  const code = await authorizeCode();
  const issued = await issuer.handler(request(peer, "token", code));
  assert.equal(issued.status, 200);
  const parent = (await issued.json()).refresh_token;
  const hash = raw => createHash("sha256").update(raw).digest("base64url");
  const lookup = raw => db.prepare("SELECT * FROM oauthRefreshToken WHERE token=?").get(hash(raw));
  const row = lookup(parent);
  const exchange = (raw, extra = {}) => server.send(request(mount, "token", {
    ...fields, grant_type: "refresh_token", refresh_token: raw, ...extra,
  }));
  async function expectError(raw, extra, status, error) {
    const res = await exchange(raw, extra);
    assert.equal(res.status, status);
    assert.equal((await res.json()).error, error);
  }
  async function accept(raw, extra) {
    const res = await exchange(raw, extra);
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(body.token_type, "Bearer");
    return body;
  }
  async function inspect(token) {
    const res = await issuer.handler(request(peer, "introspect", { ...fields, token }));
    assert.equal(res.status, 200);
    return res.json();
  }
  await expectError(parent, { scope: "outside" }, 400, "invalid_scope");
  assert.equal((await inspect(parent)).active, true);
  const narrowed = await accept(parent, { scope: "reports" });
  assert.equal(narrowed.scope, "reports");
  assert.ok(narrowed.refresh_token && narrowed.refresh_token !== parent);
  assert.equal((await inspect(parent)).active, false);
  assert.equal((await inspect(narrowed.refresh_token)).sid, row.sessionId);
  const online = await accept(narrowed.refresh_token, {});
  assert.equal(online.scope, "reports");
  assert.equal(online.refresh_token, undefined);
  assert.equal((await inspect(narrowed.refresh_token)).active, true);
  const secondCode = await authorizeCode();
  const second = await issuer.handler(request(peer, "token", secondCode));
  assert.equal(second.status, 200);
  const offline = (await second.json()).refresh_token;
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run("2000-01-01T00:00:00.000Z", row.sessionId);
  await expectError(narrowed.refresh_token, {}, 400, "invalid_grant");
  await expectError(offline, { scope: "reports" }, 400, "invalid_grant");
  assert.equal((await inspect(offline)).active, true);
  const detached = await accept(offline, {});
  assert.equal(detached.scope, "reports offline_access");
  const child = lookup(detached.refresh_token);
  assert.equal(child.sessionId, row.sessionId);
  assert.equal(child.userId, user);
  assert.equal(child.clientId, app.client_id);
  assert.equal(child.authorizationCodeId, hash(secondCode.code));
  assert.equal(Date.parse(child.authTime), Date.parse(row.authTime));
  assert.equal(Date.parse(child.expiresAt) - Date.parse(child.createdAt), 30 * 86400 * 1000);
  for (const credential of [detached.refresh_token, detached.access_token]) {
    const info = await inspect(credential);
    assert.equal(info.active, true);
    assert.equal(info.sid, undefined);
  }
  const again = await issuer.handler(request(peer, "token", { ...fields, grant_type: "refresh_token", refresh_token: detached.refresh_token }));
  assert.equal(again.status, 200);
  const latest = await again.json();
  await expectError(offline, {}, 400, "invalid_grant");
  assert.equal((await inspect(latest.refresh_token)).active, false);
  assert.equal((await inspect(latest.access_token)).active, false);
}
