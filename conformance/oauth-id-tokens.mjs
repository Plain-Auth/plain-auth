import assert from "node:assert/strict";
import {createHash, randomUUID} from "node:crypto";
import {DatabaseSync} from "node:sqlite";
import {createLocalJWKSet, jwtVerify} from "jose";
import {jwt} from "better-auth/plugins";
import {oauthProvider} from "@better-auth/oauth-provider";
import {issuerBrowser} from "./oauth-social-authorization.mjs";

export async function compareIDTokens(t, reference, goFixture) {
  const scopes = ["openid", "email", "profile", "offline_access"];
  for (const alg of ["EdDSA", "RS256", "ES256", "ES512", "PS256"]) {
    for (const runtime of ["reference", "Go"]) await t.test(runtime + " " + alg, async t => {
      const pairwise = alg === "RS256";
      const server = runtime === "Go"
        ? await goFixture(t, ["oauth-provider", "jwt"], {CONFORMANCE_CLIENT_REGISTRATION: "oidc", CONFORMANCE_JWT_ALGORITHM: alg})
        : await reference(t, [jwt({jwks: {keyPairConfig: {alg}}}), oauthProvider({
          loginPage: "/login", consentPage: "/consent", scopes, pairwiseSecret: "p".repeat(32),
          allowDynamicClientRegistration: true, clientRegistrationAllowedScopes: scopes,
          prefix: {opaqueAccessToken: "at_"}, ...(pairwise && {idTokenExpiresIn: 120}),
        })], {rateLimit: {enabled: false}});
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const {base, post, send, destination, json} = issuerBrowser(runtime, server);
      const email = "person@oidc.test";
      await json(await post("/sign-up/email", {name:"Test Person", email, password:"local OpenID credential"}));
      const {user, session} = await json(await send(base + "/get-session"));
      const callback = "https://reader.example.test/signin";
      const app = await json(await post("/oauth2/register", {redirect_uris: [callback], grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "none", scope: scopes.join(" "), application_type: "native", subject_type: pairwise ? "pairwise" : "public"}), 201);
      db.prepare("UPDATE oauthClient SET enableEndSession=? WHERE clientId=?").run(Number(pairwise), app.client_id);
      const verifier = randomUUID() + randomUUID(), nonce = randomUUID(), state = randomUUID();
      const query = {response_type:"code",client_id:app.client_id,redirect_uri:callback,scope:"openid offline_access",state, nonce,
        code_challenge_method:"S256",code_challenge:createHash("sha256").update(verifier).digest("base64url")};
      const authorize = async extra => destination(await send(base + "/oauth2/authorize?" + new URLSearchParams({...query, ...extra}), {headers:{accept:"application/json"}}));
      const oauth = async fields => json(await server.send(new Request(base + "/oauth2/token", {method:"POST", body:new URLSearchParams({client_id:app.client_id, ...fields})})));
      const info = async access => json(await server.send(new Request(base + "/oauth2/userinfo", {headers:{authorization:"Bearer " + access}})));
      const verify = async (tokens, {fresh, live, explicitEmail = true}) => {
        assert.ok(tokens.access_token.startsWith("at_"));
        const jwks = await json(await send(base + "/jwks"));
        const {payload, protectedHeader} = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {issuer:base, audience:app.client_id, algorithms:[alg]});
        assert.ok(protectedHeader.kid);
        assert.equal(payload.aud, app.client_id);
        assert.equal(payload.exp - payload.iat, pairwise ? 120 : 36000);
        assert.equal(payload.acr, "0");
        assert.equal(payload.auth_time, Math.floor(new Date(session.createdAt).getTime() / 1000));
        assert.equal(payload.nonce, fresh ? nonce : undefined);
        assert.equal(payload.sid, pairwise && live ? session.id : undefined);
        const digest = createHash(["EdDSA", "ES512"].includes(alg) ? "sha512" : "sha256").update(tokens.access_token).digest();
        assert.equal(payload.at_hash, digest.subarray(0, digest.length / 2).toString("base64url"));
        for (const name of ["name", "email", "email_verified", "picture", "scope", "azp"]) assert.equal(payload[name], undefined);
        assert.equal(payload.sub === user.id, !pairwise);
        const profile = await info(tokens.access_token);
        assert.deepEqual(profile, explicitEmail ? {sub:payload.sub, email} : {sub:payload.sub});
        return payload;
      };
      for (const [claims, error] of [
        ['{"id_token":{"acr":{"essential":"true"}}}', "invalid_request"],
        ['{"userinfo":null}', "invalid_request"],
        ['{"id_token":{"acr":{"essential":true,"values":["1"]}}}', "access_denied"],
      ]) {
        const rejected = await authorize({claims});
        assert.equal(rejected.searchParams.get("error"), error);
        assert.equal(rejected.searchParams.has("code"), false);
      }
      const claims = JSON.stringify({id_token:{acr:{values:["1"]},email:{essential:true}},userinfo:{email:null,name:null}});
      const consent = await authorize({claims, acr_values:"1",prompt:"consent"});
      assert.equal(consent.pathname, "/consent");
      const elevated = await post("/oauth2/consent", {oauth_query:consent.search.slice(1),accept:true,claims:{userinfo:{picture:null}}});
      assert.equal(elevated.status,400);
      const approved = await destination(await post("/oauth2/consent", {oauth_query:consent.search.slice(1),accept:true,claims:{userinfo:{email:null}}}));
      assert.equal(approved.origin + approved.pathname,callback);
      assert.equal(approved.searchParams.get("state"),state);
      const redeem = location => oauth({grant_type:"authorization_code",code:location.searchParams.get("code"),code_verifier:verifier,redirect_uri:callback});
      const issued = await redeem(approved);
      const original = await verify(issued,{fresh:true, live:true});
      const more = await authorize({claims,prompt:"none"});
      assert.equal(more.searchParams.get("error"),"consent_required");
      const bare = await authorize({scope:"openid",prompt:"none"});
      const bareTokens = await redeem(bare);
      assert.equal(bareTokens.refresh_token,undefined);
      await verify(bareTokens,{fresh:true,live:true,explicitEmail:false});
      const refresh = (token, scope) => oauth({grant_type:"refresh_token",refresh_token:token,...(scope && {scope})});
      const renewed = await refresh(issued.refresh_token);
      assert.notEqual(renewed.refresh_token, issued.refresh_token);
      const rotated = await verify(renewed,{fresh:false,live:true});
      assert.equal(rotated.sub, original.sub);
      assert.notEqual(rotated.at_hash, original.at_hash);
      // Offline credentials survive the interactive session's natural expiry.
      db.prepare("UPDATE session SET expiresAt=? WHERE id=?").run(new Date(Date.now()-60000).toISOString(),session.id);
      const offline = await refresh(renewed.refresh_token);
      await verify(offline,{fresh:false,live:false});
      const reduced = await refresh(offline.refresh_token,"offline_access");
      assert.equal(reduced.id_token,undefined);
      assert.equal(reduced.scope,"offline_access");
    });
  }
}
