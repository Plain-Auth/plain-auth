import assert from "node:assert/strict";
import { createHash, createHmac, randomUUID } from "node:crypto";

export async function exerciseRefreshIntrospection({ server, issuer, db, credentials }) {
  const mount = server.baseURL + "/api/auth";
  const peer = "http://issuer.localhost/api/auth";
  const callback = "https://reports.example.test:8443/return";
  const scopes = ["reports", "offline_access"];
  const account = await issuer.api.signUpEmail({ body: { name: "Refresh user", email: "refresh-grant@issuer.test", password: "refresh fixture password" }, asResponse: true });
  assert.equal(account.status, 200);
  const user = (await account.json()).user.id;
  const login = account.headers.getSetCookie().map(line => line.split(";")[0]).join("; ");
  const registration = await issuer.handler(new Request(peer + "/oauth2/register", {
    method: "POST", headers: { cookie: login, origin: "http://issuer.localhost", "content-type": "application/json" },
    body: JSON.stringify({ grant_types: ["authorization_code", "refresh_token"], redirect_uris: [callback],
      token_endpoint_auth_method: "client_secret_post", subject_type: "pairwise", scope: scopes.join(" ") }),
  }));
  const app = await registration.json();
  assert.equal(registration.status, 201, JSON.stringify(app));
  const fields = { client_id: app.client_id, client_secret: app.client_secret };
  const now = new Date().toISOString();
  db.prepare("INSERT INTO oauthConsent(id,clientId,userId,scopes,createdAt,updatedAt) VALUES(?,?,?,?,?,?)")
    .run(randomUUID(), app.client_id, user, JSON.stringify(scopes), now, now);
  const verifier = randomUUID() + randomUUID();
  const query = new URLSearchParams({ response_type: "code", client_id: app.client_id, redirect_uri: callback,
    state: randomUUID(), scope: scopes.join(" "), code_challenge_method: "S256",
    code_challenge: createHash("sha256").update(verifier).digest("base64url") });
  const authorize = await issuer.handler(new Request(peer + "/oauth2/authorize?" + query, { headers: { cookie: login } }));
  const location = authorize.headers.get("location");
  assert.ok(location, "expected an authorization redirect, HTTP " + authorize.status);
  const redirected = new URL(location);
  assert.equal(redirected.origin + redirected.pathname, callback);
  const code = redirected.searchParams.get("code");
  assert.ok(code, redirected.searchParams.get("error_description") ?? "missing authorization code");
  function post(base, path, form) {
    return new Request(base + "/oauth2/" + path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form) });
  }
  const exchange = await issuer.handler(post(peer, "token", { ...fields, grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: callback }));
  const issued = await exchange.json();
  assert.equal(exchange.status, 200, JSON.stringify(issued));
  assert.ok(issued.refresh_token, "the independent issuer returned a refresh token");
  const row = db.prepare("SELECT * FROM oauthRefreshToken WHERE clientId=?").get(app.client_id);
  assert.equal(row.userId, user);
  assert.ok(row.sessionId);
  async function inspect(extra = {}, remote = false) {
    const request = post(remote ? peer : mount, "introspect", { ...fields, token: issued.refresh_token, ...extra });
    const res = remote ? await issuer.handler(request) : await server.send(request);
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    return body;
  }
  const expected = { active: true, client_id: app.client_id, iss: mount, iat: Math.floor(Date.parse(row.createdAt) / 1000),
    exp: Math.floor(Date.parse(row.expiresAt) / 1000), scope: scopes.join(" "), token_type: "Bearer", sid: row.sessionId,
    sub: createHmac("sha256", "p".repeat(32)).update("reports.example.test:8443." + user).digest("base64") };
  for (const hint of [{ token_type_hint: "refresh_token" }, {}, { token_type_hint: "unknown" }]) {
    assert.deepEqual(await inspect(hint), expected);
  }
  assert.deepEqual(await inspect({}, true), { ...expected, iss: peer });
  assert.deepEqual(await inspect({ token_type_hint: "access_token" }), { active: false });
  assert.deepEqual(await inspect({ client_id: credentials.client_id, client_secret: credentials.client_secret }), { active: false });
  for (const [cnf, token_type] of [[{ jkt: "thumbprint" }, "DPoP"], [{ "x5t#S256": "certificate" }, "Bearer"]]) {
    db.prepare("UPDATE oauthRefreshToken SET confirmation=? WHERE id=?").run(JSON.stringify(cnf), row.id);
    assert.deepEqual(await inspect(), { ...expected, token_type, cnf });
    assert.deepEqual(await inspect({}, true), { ...expected, iss: peer, token_type, cnf });
  }
  db.prepare("UPDATE oauthRefreshToken SET confirmation=NULL WHERE id=?").run(row.id);
  const browser = db.prepare("SELECT token,expiresAt FROM session WHERE id=?").get(row.sessionId);
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00.000Z", row.sessionId);
  const detached = { ...expected };
  delete detached.sid;
  assert.deepEqual(await inspect(), detached);
  db.prepare("UPDATE oauthRefreshToken SET scopes=? WHERE id=?").run('["reports"]', row.id);
  assert.deepEqual(await inspect(), { active: false });
  db.prepare("UPDATE oauthRefreshToken SET scopes=? WHERE id=?").run(JSON.stringify(scopes), row.id);
  db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run(browser.expiresAt, row.sessionId);
  const narrowed = randomUUID();
  db.prepare("INSERT INTO oauthRefreshToken(id,token,userId,sessionId,clientId,scopes,createdAt,expiresAt) VALUES(?,?,?,?,?,?,?,?)")
    .run(narrowed, randomUUID(), user, row.sessionId, app.client_id, '["reports"]', now, row.expiresAt);
  const access = randomUUID();
  db.prepare("INSERT INTO oauthAccessToken(id,token,userId,sessionId,clientId,scopes,createdAt,expiresAt) VALUES(?,?,?,?,?,?,?,?)")
    .run(access, randomUUID(), user, row.sessionId, app.client_id, '["reports"]', now, row.expiresAt);
  const headers = { "content-type": "application/json", origin: server.baseURL };
  const signIn = await server.send(new Request(mount + "/sign-in/email", { method: "POST", headers,
    body: JSON.stringify({ email: "refresh-grant@issuer.test", password: "refresh fixture password" }) }));
  assert.equal(signIn.status, 200);
  const cookie = signIn.headers.getSetCookie().map(line => line.split(";")[0]).join("; ");
  const endSession = await server.send(new Request(mount + "/revoke-session", { method: "POST", headers: { ...headers, cookie },
    body: JSON.stringify({ token: browser.token }) }));
  assert.equal(endSession.status, 200);
  assert.equal(db.prepare("SELECT id FROM session WHERE id=?").get(row.sessionId), undefined);
  assert.ok(db.prepare("SELECT revoked FROM oauthRefreshToken WHERE id=?").get(narrowed).revoked);
  assert.ok(db.prepare("SELECT revoked FROM oauthAccessToken WHERE id=?").get(access).revoked);
  assert.deepEqual(await inspect(), detached);
  const revoke = await issuer.handler(post(peer, "revoke", { ...fields, token: issued.refresh_token, token_type_hint: "refresh_token" }));
  assert.equal(revoke.status, 200);
  assert.deepEqual(await inspect(), { active: false });
}
