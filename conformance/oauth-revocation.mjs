import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export async function exerciseRevocation({ runtime, server, issuer, db, credentials, created, cookie, exchange }) {
  const native = runtime === "Go";
  const owner = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const media = "application/x-www-form-urlencoded";
  const root = server.baseURL + "/api/auth";
  async function revoke(fields, headers = {}) {
    return server.send(new Request(root + "/oauth2/revoke", {
      method: "POST", headers: { "content-type": media, ...headers }, body: new URLSearchParams(fields),
    }));
  }
  async function success(fields, headers) {
    const res = await revoke(fields, headers);
    const body = await res.text();
    assert.equal(res.status, 200, body);
    if (native) {
      assert.equal(body, "");
      assert.match(res.headers.get("cache-control"), /no-store/);
    }
  }
  async function problem(fields, headers, status, code, challenge) {
    const res = await revoke(fields, headers);
    const body = await res.json();
    assert.equal(res.status, status, JSON.stringify(body));
    assert.equal(body.error, code);
    assert.equal(res.headers.get("www-authenticate"), challenge ?? null);
  }
  const issued = await exchange(owner.client_secret);
  const { access_token: token } = await issued.json();
  assert.equal(issued.status, 200);
  async function active() {
    const res = await issuer.handler(new Request("http://issuer.localhost/api/auth/oauth2/introspect", {
      method: "POST", headers: { "content-type": media }, body: new URLSearchParams({ ...owner, token }),
    }));
    assert.equal(res.status, 200);
    return (await res.json()).active;
  }
  const other = await created({ redirect_uris: ["https://web.example.test/cb"], token_endpoint_auth_method: "none" }, { cookie });
  await success({ client_id: other.client_id, token });
  assert.equal(await active(), true);
  await problem({}, {}, 400, "invalid_request");
  await problem({ token }, {}, 401, "invalid_client", "Basic");
  await problem({ ...owner, token: "" }, {}, 400, "invalid_request");
  await problem({ ...owner, client_secret: "wrong", token }, {}, 400, "invalid_client");
  await problem({ token }, { authorization: "Basic !" }, 401, "invalid_client", "Basic");
  await success({ ...owner, token: " bEaReR  " + token + " ", token_type_hint: native ? "refresh_token" : "unknown" });
  assert.equal(await active(), false);
  if (native) {
    await success({ ...owner, token });
    await success({ ...owner, token: "does-not-exist", token_type_hint: "access_token" });
  }

  const user = db.prepare("SELECT id FROM user LIMIT 1").get().id;
  const now = new Date();
  const expires = new Date(now.getTime() + 600_000).toISOString();
  const raw = randomUUID();
  const family = randomUUID();
  const hash = v => createHash("sha256").update(v).digest("base64url");
  const refresh = db.prepare("INSERT INTO oauthRefreshToken (id,token,clientId,userId,expiresAt,createdAt,scopes) VALUES (?,?,?,?,?,?,?)");
  const access = db.prepare("INSERT INTO oauthAccessToken (id,token,clientId,userId,refreshId,expiresAt,createdAt,scopes) VALUES (?,?,?,?,?,?,?,?)");
  for (const [id, value] of [[family, raw], [family + "-next", raw + "-next"]]) {
    refresh.run(id, hash(value), owner.client_id, user, expires, now.toISOString(), '["reports"]');
    access.run(id, hash("access-" + value), owner.client_id, user, id, expires, now.toISOString(), '["reports"]');
  }
  await success({ ...owner, token: raw, token_type_hint: "refresh_token" });
  assert.ok(db.prepare("SELECT revoked FROM oauthRefreshToken WHERE id=?").get(family).revoked);
  assert.equal(db.prepare("SELECT id FROM oauthAccessToken WHERE id=?").get(family), undefined);
  const foreignReplay = await revoke({ client_id: other.client_id, token: raw, token_type_hint: "refresh_token" });
  assert.equal(foreignReplay.status, native ? 200 : 400);
  assert.ok(db.prepare("SELECT id FROM oauthAccessToken WHERE id=?").get(family + "-next"));
  // Some issuers return an error on replay even after invalidating the family.
  const replay = await revoke({ ...owner, token: raw, token_type_hint: "refresh_token" });
  assert.equal(replay.status, native ? 200 : 400);
  assert.equal(db.prepare("SELECT id FROM oauthRefreshToken WHERE id=?").get(family + "-next"), undefined);
  assert.equal(db.prepare("SELECT id FROM oauthAccessToken WHERE id=?").get(family + "-next"), undefined);

  const kid = randomUUID();
  const audience = "urn:revocation:" + kid;
  const pair = await generateKeyPair("EdDSA");
  db.prepare("INSERT INTO jwks (id,publicKey,privateKey,createdAt,alg,crv) VALUES (?,?,?,?,?,?)")
    .run(kid, JSON.stringify(await exportJWK(pair.publicKey)), "unused", now.toISOString(), "EdDSA", "Ed25519");
  async function sign(claims, header = { alg: "EdDSA", kid }) {
    return new SignJWT({ iss: root, azp: owner.client_id, exp: Math.floor(Date.now() / 1000) + 300, ...claims })
      .setProtectedHeader(header).sign(pair.privateKey);
  }
  db.prepare("INSERT INTO oauthResource (id,identifier,name,disabled) VALUES (?,?,?,1)").run(kid, audience, "Disabled API");
  try {
    const noKeyID = await sign({}, { alg: "EdDSA" });
    await problem({ ...owner, token: noKeyID, token_type_hint: "access_token" }, {}, 400, "unsupported_token_type");
    for (const claims of [{}, { aud: root + "/oauth2/userinfo" }, { aud: [audience, root + "/oauth2/userinfo"] }]) {
      await problem({ ...owner, token: await sign(claims), token_type_hint: "access_token" }, {}, 400, "unsupported_token_type");
    }
    db.prepare("DELETE FROM oauthResource WHERE id=?").run(kid);
    for (const claims of [{ exp: 1 }, { azp: undefined }, { aud: [root + "/oauth2/userinfo", audience] }, { aud: Array(65).fill(root + "/oauth2/userinfo") }]) {
      await success({ ...owner, token: await sign(claims), token_type_hint: "access_token" });
    }
    if (native) {
      db.prepare("INSERT INTO jwks (id,publicKey,privateKey,createdAt,alg,crv) SELECT ?,publicKey,privateKey,createdAt,alg,crv FROM jwks WHERE id=?").run(kid + "-other", kid);
      assert.equal((await revoke({ ...owner, token: noKeyID })).status, 500);
    }
  } finally {
    db.prepare("DELETE FROM oauthResource WHERE id=?").run(kid);
    db.prepare("DELETE FROM jwks WHERE id=?").run(kid);
    db.prepare("DELETE FROM jwks WHERE id=?").run(kid + "-other");
  }
}
