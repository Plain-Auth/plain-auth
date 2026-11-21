import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { sso } from "@better-auth/sso";
import { ssoClient } from "@better-auth/sso/client";
import { NodeSqliteDialect } from "@better-auth/kysely-adapter/node-sqlite-dialect";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export async function compareEnterpriseBrowser(t, {goFixture,instrument}) {
  const {publicKey, privateKey} = await generateKeyPair("RS256");
  const jwk = {...await exportJWK(publicKey), kid:"enterprise", use:"sig", alg:"RS256"};
  const grants = new Map();
  let issuer;
  const idp = createServer(async (req,res) => {
    const json = (status, data) => res.writeHead(status, {"content-type":"application/json"}).end(JSON.stringify(data));
    if (req.url === "/keys") return json(200,{keys:[jwk]});
    if (req.url !== "/token" || req.method !== "POST") return json(404,{});
    let raw = "";
    for await (const part of req) raw += part;
    const fields = new URLSearchParams(raw);
    const grant = grants.get(fields.get("code"));
    grants.delete(fields.get("code"));
    if (!grant || fields.get("redirect_uri") !== grant.redirect ||
        fields.get("client_id") !== "catalog-client" || fields.get("client_secret") !== "catalog-secret" ||
        createHash("sha256").update(fields.get("code_verifier") ?? "").digest("base64url") !== grant.challenge)
      return json(400,{error:"invalid_grant"});
    const token = await new SignJWT({email:grant.email, name:"Enterprise employee", email_verified:true,...grant.nonce && {nonce:grant.nonce}})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid}).setSubject(grant.subject)
      .setIssuedAt().setExpirationTime("5m").setIssuer(issuer).setAudience("catalog-client").sign(privateKey);
    return json(200,{access_token:"opaque-access",token_type:"Bearer",id_token:token});
  });
  idp.listen(0,"127.0.0.1");
  await once(idp,"listening");
  t.after(() => new Promise(resolve => idp.close(resolve)));
  issuer = "http://127.0.0.1:" + idp.address().port;
  for (const shared of [false,true]) {
    const go = await goFixture(t,["sso"],{CONFORMANCE_SSO_DISCOVERY_ORIGIN:issuer,CONFORMANCE_SSO_SHARED_CALLBACK:shared ? "1":"0"});
    const db = new DatabaseSync(go.databasePath);
    t.after(() => db.close());
    const options = {baseURL:"http://reference.localhost",secret:"local-conformance-0123456789-abcdefghijk",
      emailAndPassword:{enabled:true},trustedOrigins:[issuer],
      database:{type:"sqlite",dialect:new NodeSqliteDialect({database:db}),transaction:true},
      telemetry:{enabled:false},plugins:[sso(shared ? {redirectURI:"/sso/callback"}:{})]};
    await (await getMigrations(options)).runMigrations();
    const reference = betterAuth(options);
    const ts = {baseURL:options.baseURL,send:r=>reference.handler(r)};
    const ok = r => {assert.equal(r.error,null,JSON.stringify(r.error));return r.data;};
    const admin = instrument(ts,[ssoClient()]).client;
    ok(await admin.signUp.email({email:"registry@example.test",password:"valid-long-password",name:"Issuer owner"}));
    const registration = ok(await admin.sso.register({providerId:"company",domain:"enterprise.example",issuer,
      oidcConfig:{skipDiscovery:true,authorizationEndpoint:issuer+"/authorize",tokenEndpoint:issuer+"/token",
        jwksEndpoint:issuer+"/keys",clientId:"catalog-client",clientSecret:"catalog-secret",tokenEndpointAuthentication:"client_secret_post"}}));
    assert.equal(registration.redirectURI,ts.baseURL+"/api/auth/sso/callback"+(shared?"":"/company"));
    for (const [i,server] of [go,ts,go].entries()){
      // Capture cookies from both the SDK's JSON request and the browser's manual 302.
      const jar = new Map();
      async function browser(request) {
        const headers = new Headers(request.headers);
        headers.set("cookie",[...jar].map(([k,v]) => k+"="+v).join("; "));
        const response = await server.send(new Request(request,{headers,redirect:"manual"}));
        for (const value of response.headers.getSetCookie()) {
          const pair=value.split(";",1)[0], pos=pair.indexOf("=");
          jar.set(pair.slice(0,pos),pair.slice(pos+1));
        }
        return response;
      }
      const {client} = instrument({baseURL:server.baseURL,send:browser},[ssoClient()]);
      const relative = server.baseURL;
      const request = ok(await client.signIn.sso({email:"employee@enterprise.example",callbackURL:relative+"/home",newUserCallbackURL:relative+"/welcome",errorCallbackURL:relative+"/retry",loginHint:"employee",additionalParams:{prompt:"login"}}));
      assert.equal(request.redirect,true);
      const authz = new URL(request.url);
      assert.equal(authz.origin,issuer);
      const query=authz.searchParams;
      assert.equal(query.get("client_id"),"catalog-client");
      assert.equal(query.get("response_type"),"code");
      assert.equal(query.get("login_hint"),"employee");
      assert.equal(query.get("prompt"),"login");
      assert.equal(query.get("code_challenge_method"),"S256");
      assert.ok(query.get("scope").split(" ").includes("openid"));
      const target = new URL(query.get("redirect_uri"));
      assert.equal(target.href,relative+"/api/auth/sso/callback"+(shared?"":"/company"));
      const code=randomUUID();
      grants.set(code,{redirect:target.href,challenge:query.get("code_challenge"),nonce:query.get("nonce"),subject:"employee-id",email:"enterprise-sso@example.test"});
      target.search = new URLSearchParams({state:query.get("state"),code}).toString();
      const callback=await browser(new Request(target));
      assert.equal(callback.status,302);
      assert.equal(callback.headers.get("location"),relative+(i===0?"/welcome":"/home"));
      const session=ok(await client.getSession());
      assert.equal(session.user.email,"enterprise-sso@example.test");
      assert.equal(session.user.emailVerified,false);
      assert.equal(db.prepare('select count(*) as n from account where providerId=? and accountId=?').get("company","employee-id").n,1);
    }
    // A state created before deletion cannot authorize a replacement with the same public provider ID.
    let stateCookie;
    const browser = instrument({...go,send:async request => {
      const response = await go.send(request);
      if (new URL(request.url).pathname.endsWith("/sign-in/sso"))
        stateCookie = response.headers.getSetCookie().map(h=>h.split(";",1)[0]).join("; ");
      return response;
    }},[ssoClient()]).client;
    const stale = ok(await browser.signIn.sso({providerId:"company",callbackURL:go.baseURL+"/home",errorCallbackURL:go.baseURL+"/retry"}));
    const authorization = new URL(stale.url).searchParams;
    const target = new URL(authorization.get("redirect_uri"));
    const code = randomUUID();
    grants.set(code,{redirect:target.href,challenge:authorization.get("code_challenge"),nonce:authorization.get("nonce"),subject:"old-id",email:"stale@example.test"});
    target.search = new URLSearchParams({state:authorization.get("state"),code}).toString();
    ok(await admin.sso.deleteProvider({providerId:"company"}));
    const replacement=ok(await admin.sso.register({providerId:"company",domain:"enterprise.example",issuer,
      oidcConfig:{skipDiscovery:true,authorizationEndpoint:issuer+"/authorize",tokenEndpoint:issuer+"/token",jwksEndpoint:issuer+"/keys",clientId:"catalog-client",clientSecret:"catalog-secret",tokenEndpointAuthentication:"client_secret_post"}}));
    assert.notEqual(replacement.id,registration.id);
    const response=await go.send(new Request(target,{headers:{cookie:stateCookie},redirect:"manual"}));
    assert.equal(response.status,302);
    assert.equal(response.headers.get("location"),go.baseURL+"/retry?error=invalid_state");
    assert.ok(grants.delete(code),"a deleted provider's replacement reached the token endpoint");
    assert.equal(db.prepare("select count(*) as n from account where providerId='company'").get().n,0);
  }
}
