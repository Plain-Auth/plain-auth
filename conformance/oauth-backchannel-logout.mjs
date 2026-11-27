import assert from "node:assert/strict";
import {createHash, randomUUID} from "node:crypto";
import {createServer} from "node:http";
import {createLocalJWKSet, jwtVerify} from "jose";
import {jwt} from "better-auth/plugins";
import {oauthProvider} from "@better-auth/oauth-provider";
import {issuerBrowser} from "./oauth-social-authorization.mjs";

const logoutURI = "https://rp.example.test/logout";
const scopes = ["openid", "email", "profile", "offline_access"];

// A client registers a back-channel logout URI, obtains tokens for a
// browser session through a code flow, and receives one signed logout
// token when that session signs out. Both runtimes send the same form and
// the same header and claim set.
export async function compareBackchannelLogout(t, {reference, goFixture}) {
  const shapes = {};
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const received = [];
    let server;
    if (runtime === "Go") {
      const receiver = createServer((req, res) => {
        let body = "";
        req.on("data", chunk => { body += chunk; });
        req.on("end", () => {
          received.push({path: req.url, contentType: req.headers["content-type"], accept: req.headers.accept, body});
          res.writeHead(200);
          res.end();
        });
      });
      await new Promise(resolve => receiver.listen(0, "127.0.0.1", resolve));
      t.after(() => new Promise(resolve => receiver.close(resolve)));
      server = await goFixture(t, ["oauth-provider", "jwt"], {
        CONFORMANCE_CLIENT_REGISTRATION: "oidc", CONFORMANCE_BACKCHANNEL_TARGET: "http://127.0.0.1:" + receiver.address().port,
      });
    } else {
      const original = globalThis.fetch;
      globalThis.fetch = async (input, init = {}) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        if (url !== logoutURI) return original(input, init);
        const headers = new Headers(init.headers);
        received.push({path: new URL(url).pathname, contentType: headers.get("content-type"), accept: headers.get("accept"), body: String(init.body)});
        return new Response(null, {status: 200});
      };
      t.after(() => { globalThis.fetch = original; });
      server = await reference(t, [jwt(), oauthProvider({
        loginPage: "/login", consentPage: "/consent", scopes, allowDynamicClientRegistration: true,
        clientRegistrationAllowedScopes: scopes, prefix: {opaqueAccessToken: "at_"},
      })], {rateLimit: {enabled: false}});
    }
    const {base, post, send, destination, json} = issuerBrowser(runtime, server);
    const metadata = await json(await server.send(new Request(server.baseURL + "/api/auth/.well-known/openid-configuration")));
    assert.equal(metadata.backchannel_logout_supported, true);
    assert.equal(metadata.backchannel_logout_session_supported, true);
    await json(await post("/sign-up/email", {name: "Logout Person", email: "logout@oidc.test", password: "local logout credential"}));
    const {user, session} = await json(await send(base + "/get-session"));
    const callback = "https://reader.example.test/signin";
    const app = await json(await post("/oauth2/register", {redirect_uris: [callback], grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none", scope: "openid offline_access", application_type: "native", backchannel_logout_uri: logoutURI}), 201);
    assert.equal(app.backchannel_logout_uri, logoutURI);
    const verifier = randomUUID() + randomUUID();
    const query = {response_type: "code", client_id: app.client_id, redirect_uri: callback, scope: "openid offline_access", state: randomUUID(),
      code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url")};
    const consent = await destination(await send(metadata.authorization_endpoint + "?" + new URLSearchParams(query), {headers: {accept: "application/json"}}));
    assert.equal(consent.pathname, "/consent");
    const approved = await destination(await post("/oauth2/consent", {oauth_query: consent.search.slice(1), accept: true}));
    const tokens = await json(await server.send(new Request(metadata.token_endpoint, {method: "POST", body: new URLSearchParams({
      client_id: app.client_id, grant_type: "authorization_code", code: approved.searchParams.get("code"), code_verifier: verifier, redirect_uri: callback,
    })})));
    assert.ok(tokens.id_token && tokens.refresh_token);
    assert.equal(received.length, 0);
    await json(await post("/sign-out", {}));
    assert.equal(received.length, 1);
    const [delivery] = received;
    assert.equal(delivery.path, "/logout");
    assert.equal(delivery.contentType, "application/x-www-form-urlencoded");
    assert.equal(delivery.accept, "application/json");
    const form = new URLSearchParams(delivery.body);
    assert.deepEqual([...form.keys()], ["logout_token"]);
    const jwks = await json(await send(metadata.jwks_uri));
    const {payload, protectedHeader} = await jwtVerify(form.get("logout_token"), createLocalJWKSet(jwks), {issuer: base, audience: app.client_id, typ: "logout+jwt"});
    assert.equal(payload.sub, user.id);
    assert.equal(payload.sid, session.id);
    assert.deepEqual(payload.events, {"http://schemas.openid.net/event/backchannel-logout": {}});
    assert.equal(payload.exp - payload.iat, 120);
    assert.match(payload.jti, /^[A-Za-z0-9]{32}$/);
    assert.equal(payload.nonce, undefined);
    // The access token died with the session.
    const userInfo = await server.send(new Request(metadata.userinfo_endpoint, {headers: {authorization: "Bearer " + tokens.access_token}}));
    assert.equal(userInfo.status, 401);
    shapes[runtime] = {header: Object.keys(protectedHeader).sort(), claims: Object.keys(payload).sort()};
  });
  assert.deepEqual(shapes.Go, shapes.reference);
}
