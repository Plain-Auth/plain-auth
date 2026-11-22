import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

// The authorization-code exchange comes from an independent issuer. The two
// resource registrations exercise the resource server's own client credentials.
export async function exerciseOpaqueGrant({ inspect, issued, db, app, credentials, expected, mount }) {
  const token = issued.access_token;
  const row = db.prepare("SELECT * FROM oauthAccessToken WHERE clientId=? AND refreshId IS NOT NULL").get(app.client_id);
  assert.ok(row, "expected a stored delegated access token");
  const details = { ...expected, azp: app.client_id, iat: Math.floor(Date.parse(row.createdAt) / 1000),
    exp: Math.floor(Date.parse(row.expiresAt) / 1000) };
  const resourceCredentials = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const check = (extra = {}) => inspect({ token, token_type_hint: "access_token", ...extra });
  assert.deepEqual(await check(), details);
  assert.deepEqual(await check(resourceCredentials), { active: false });

  const one = "urn:opaque:first", two = "urn:opaque:second";
  const resource = db.prepare("INSERT INTO oauthResource(id,identifier,name,customClaims,disabled) VALUES(?,?,?,?,?)");
  resource.run(randomUUID(), one, "First", JSON.stringify({ tier: "first", first: true }), 0);
  resource.run(randomUUID(), two, "Second", JSON.stringify({ tier: "second", iss: "reserved", sub: "reserved", cnf: { jkt: "reserved" } }), 1);
  db.prepare("INSERT INTO oauthClientResource(id,clientId,resourceId) VALUES(?,?,?)").run(randomUUID(), credentials.client_id, two);
  const update = db.prepare("UPDATE oauthAccessToken SET resources=?,scopes=?,confirmation=?,requestedUserInfoClaims=? WHERE id=?");
  update.run(JSON.stringify([one,two]), '["openid","reports"]', '{"jkt":"proof"}', '["email"]', row.id);
  const bound = { ...details, aud: [one,two,mount + "/oauth2/userinfo"], scope: "openid reports", token_type: "DPoP",
    cnf: { jkt: "proof" }, first: true, tier: "second" };
  assert.deepEqual(await check(resourceCredentials), bound);
  assert.deepEqual(await check(), bound);
  db.prepare("DELETE FROM oauthResource WHERE identifier=?").run(one);
  assert.deepEqual(await check(resourceCredentials), { active: false });
  assert.deepEqual(await check(), { active: false });
  update.run(JSON.stringify([two]), '["reports"]', null, null, row.id);
  assert.deepEqual(await check(resourceCredentials), { ...details, scope: "reports", aud: two, tier: "second" });
  db.prepare("DELETE FROM oauthClientResource WHERE clientId=? AND resourceId=?").run(credentials.client_id, two);
  assert.deepEqual(await check(resourceCredentials), { active: false });
  update.run(JSON.stringify([mount + "/oauth2/userinfo"]), '["openid"]', null, null, row.id);
  assert.deepEqual(await check(resourceCredentials), { active: false });
  assert.deepEqual(await check(), { ...details, scope: "openid", aud: mount + "/oauth2/userinfo" });
  update.run(row.resources, row.scopes, row.confirmation, row.requestedUserInfoClaims, row.id);
  return check;
}
