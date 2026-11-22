import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { createDpopReplayStore, deriveDpopAth, enforceDpopBinding, verifyDpopProof } from "@better-auth/core/oauth2";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";

export async function compareDPoPProofs(t, goFixture) {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const go = await goFixture(t, [], { CONFORMANCE_DPOP_JKT: jkt });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const host = betterAuth({
    database, baseURL: go.baseURL, secret: "local-conformance-0123456789-abcdefghijk",
    telemetry: { enabled: false },
  });
  const replayStore = createDpopReplayStore(await host.$context);
  const method = "POST";
  const url = go.baseURL + "/__fixture/proof";
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims) => new SignJWT({ iat: now, ...claims })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk }).sign(privateKey);
  const submit = (proof) => go.send(url + "?source=go", { method, headers: { DPoP: proof } });
  const verify = (proofJwt, store) => verifyDpopProof({ method, url, proofJwt, replayStore: store });
  const first = { jti: "issued-for-go", htm: "post", htu: url + "?source=client" };
  const proof = await sign(first);
  const reference = await verify(proof);
  const accepted = await submit(proof);
  assert.equal(accepted.status, 200);
  const record = await accepted.json();
  assert.deepEqual({
    jwk: record.PublicKey, jkt: record.Thumbprint, jti: record.ID, htm: record.Method, htu: record.URL,
    iat: Date.parse(record.IssuedAt) / 1000, replayKey: record.ReplayKey, expires: Date.parse(record.ExpiresAt),
  }, {
    jwk: reference.jwk, jkt, jti: first.jti, htm: first.htm, htu: url,
    iat: reference.iat, replayKey: reference.replayKey, expires: reference.expiresAt.getTime(),
  });
  await assert.rejects(verify(proof, replayStore), { code: "invalid_dpop_proof" });
  const second = { ...first, jti: "issued-for-reference" };
  await verify(await sign(second), replayStore);
  const replay = await submit(await sign({ ...second, htm: "POST", htu: url }));
  assert.equal(replay.status, 400);
  assert.equal((await replay.text()).trim(), "invalid_dpop_proof");

  const target = go.baseURL + "/__fixture/reports";
  const ath = await deriveDpopAth("bound-token");
  for (const [id, scheme, token, claims, expected] of [
    ["bearer", "Bearer", "bearer-token", null, null],
    ["unbound-dpop", "DPoP", "bearer-token", null, "invalid_token"],
    ["bound-bearer", "Bearer", "bound-token", null, "invalid_token"],
    ["missing", "DPoP", "bound-token", null, "invalid_dpop_proof"],
    ["wrong-hash", "DPoP", "bound-token", { ath: "different" }, "invalid_dpop_proof"],
    ["wrong-method", "DPoP", "bound-token", { ath, htm: "POST" }, "invalid_dpop_proof"],
    ["wrong-target", "DPoP", "bound-token", { ath, htu: url }, "invalid_dpop_proof"],
    ["bound", "DPoP", "bound-token", { ath }, null],
  ]) {
    const proofJwt = claims && await sign({ jti: id, htm: "GET", htu: target, ...claims });
    const check = enforceDpopBinding({
      payload: token === "bound-token" ? { cnf: { jkt } } : {},
      authorization: { scheme, token }, method: "GET", url: target, proofJwt,
    });
    if (expected) await assert.rejects(check, { code: expected });
    else await check;
    const headers = { Authorization: scheme + " " + token };
    if (proofJwt) headers.DPoP = proofJwt;
    const response = await go.send(target, { headers });
    assert.equal(response.status, expected ? 401 : 204, id);
    if (expected) assert.equal((await response.text()).trim(), expected);
    if (id === "bound") {
      await assert.rejects(enforceDpopBinding({
        payload: { cnf: { jkt } }, authorization: { scheme, token },
        method: "GET", url: target, proofJwt, replayStore,
      }), { code: "invalid_dpop_proof" });
    }
  }
}
