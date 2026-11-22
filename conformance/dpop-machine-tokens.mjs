import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { createDpopReplayStore, deriveDpopAth, enforceDpopBinding, verifyDpopProof } from "@better-auth/core/oauth2";

export async function exerciseBoundMachineTokens({ server, issuer, db, credentials }) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const creds = { client_id: credentials.client_id, client_secret: credentials.client_secret };
  const url = server.baseURL + "/api/auth/oauth2/token";
  const sign = (method, target, extra = {}) => new SignJWT({ htm: method, htu: target, ...extra })
    .setJti(randomUUID()).setIssuedAt().setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk }).sign(privateKey);
  const post = (url, fields, proof) => new Request(url, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(proof && { dpop: proof }) },
    body: new URLSearchParams(fields),
  });
  const issue = proof => server.send(post(url, { ...creds, grant_type: "client_credentials" }, proof));
  const introspect = async token => {
    const r = await issuer.handler(post("http://issuer.localhost/api/auth/oauth2/introspect", { ...creds, token }));
    assert.equal(r.status, 200);
    return r.json();
  };
  const replayStore = createDpopReplayStore(await issuer.$context);
  const previous = db.prepare("SELECT dpopBoundAccessTokens AS required FROM oauthClient WHERE clientId=?").get(creds.client_id);
  const update = db.prepare("UPDATE oauthClient SET dpopBoundAccessTokens=? WHERE clientId=?");
  try {
    for (const required of [false, true]) {
      update.run(Number(required), creds.client_id);
      if (required) {
        const missing = await issue();
        assert.equal(missing.status, 400);
        assert.equal((await missing.json()).error, "invalid_dpop_proof");
      }
      const proof = await sign("POST", url);
      const r = await issue(proof);
      const body = await r.json();
      assert.equal(r.status, 200, JSON.stringify(body));
      assert.equal(body.token_type, "DPoP");
      const info = await introspect(body.access_token);
      assert.equal(info.active, true);
      assert.equal(info.token_type, "DPoP");
      assert.deepEqual(info.cnf, { jkt });
      const authorization = { scheme: "DPoP", token: body.access_token };
      const target = "https://api.example.test/reports";
      await enforceDpopBinding({
        payload: info, authorization, method: "GET", url: target,
        proofJwt: await sign("GET", target, { ath: await deriveDpopAth(body.access_token) }),
      });
      await assert.rejects(enforceDpopBinding({
        payload: info, authorization: { ...authorization, scheme: "Bearer" }, method: "GET", url: target,
      }), { code: "invalid_token" });
      await assert.rejects(verifyDpopProof({ proofJwt: proof, method: "POST", url, replayStore }), { code: "invalid_dpop_proof" });
      const repeated = await issue(proof);
      assert.equal(repeated.status, 400);
      assert.equal((await repeated.json()).error, "invalid_dpop_proof");
      const revoked = await issuer.handler(post("http://issuer.localhost/api/auth/oauth2/revoke", { ...creds, token: body.access_token }));
      assert.equal(revoked.status, 200);
      assert.deepEqual(await introspect(body.access_token), { active: false });
    }
  } finally {
    update.run(previous.required, creds.client_id);
  }
}
