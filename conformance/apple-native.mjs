import assert from "node:assert/strict";
import {generateKeyPair, exportJWK, SignJWT} from "jose";

async function localAppleKeys(t) {
  const {privateKey, publicKey} = await generateKeyPair("RS256", {extractable: true});
  const kid = "apple-test-key";
  const keys = {keys: [{...await exportJWK(publicKey), use:"sig", alg:"RS256", kid}]};
  const realFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (resource, init) => {
    const url = new URL(resource instanceof Request ? resource.url : resource);
    if (url.href === "https://appleid.apple.com/auth/keys") return Promise.resolve(Response.json(keys));
    assert.equal(url.hostname, "127.0.0.1", "provider fixture must stay local");
    return realFetch(resource, init);
  });
  return {keys, privateKey, kid};
}

export async function compareAppleNative(t, {reference, goFixture, instrument}) {
  const {keys, privateKey, kid} = await localAppleKeys(t);
  const web = "org.example.web", mobile = "org.example.mobile", watch = "org.example.watch";
  for (const explicit of [false, true]) {
    const apple = {clientId: web, clientSecret: "local-client-assertion", appBundleIdentifier: mobile};
    if (explicit) apple.audience = [web, watch];
    const servers = [
      await reference(t, [], {socialProviders: {apple}}),
      await goFixture(t, [], {CONFORMANCE_APPLE_JWKS: JSON.stringify(keys), CONFORMANCE_APPLE_AUDIENCES: explicit ? [web, watch].join(",") : ""}),
    ];
    for (const server of servers) {
      for (const audience of [web, mobile, watch, "org.example.unrelated"]) {
        const {client} = instrument(server);
        const nonce = crypto.randomUUID();
        const email = audience + "@example.test";
        const token = await new SignJWT({email, email_verified: true, name: "Apple user", nonce})
          .setProtectedHeader({alg: "RS256", kid}).setSubject(audience)
          .setIssuer("https://appleid.apple.com").setAudience(audience).setIssuedAt().setExpirationTime("5m").sign(privateKey);
        const result = await client.signIn.social({provider:"apple", idToken:{token,nonce}});
        if (explicit ? [web,watch].includes(audience) : audience === mobile) {
          assert.equal(result.error, null);
          assert.ok(result.data.token);
          assert.equal((await client.getSession()).data.user.email, email);
        } else {
          assert.equal(result.error?.status, 401);
          assert.equal((await client.getSession()).data, null);
        }
      }
    }
  }
}

export async function compareDisabledIDTokenSignIn(t, {reference, goFixture, instrument}) {
  const {keys, privateKey, kid} = await localAppleKeys(t);
  const mobile = "org.example.mobile";
  const apple = {clientId: "org.example.web", clientSecret: "local-client-assertion", appBundleIdentifier: mobile, disableIdTokenSignIn: true};
  const ref = await reference(t, [], {socialProviders: {apple}});
  const go = await goFixture(t, [], {CONFORMANCE_APPLE_JWKS: JSON.stringify(keys), CONFORMANCE_DISABLE_DIRECT_ID_TOKEN: "apple"});
  for (const server of [ref, go]) {
    const {client} = instrument(server);
    const email = "browser-owner@example.test", nonce = crypto.randomUUID();
    const token = await new SignJWT({email, email_verified: true, nonce})
      .setProtectedHeader({alg: "RS256", kid}).setSubject("browser-owner")
      .setIssuer("https://appleid.apple.com").setAudience(mobile).setIssuedAt().setExpirationTime("5m").sign(privateKey);
    const direct = {provider: "apple", idToken: {token, nonce}};
    const rejected = await client.signIn.social(direct);
    assert.equal(rejected.error?.status, 404);
    assert.equal(rejected.error.code, "ID_TOKEN_NOT_SUPPORTED");
    assert.equal((await client.getSession()).data, null);
    const created = await client.signUp.email({email, name: "Browser owner", password: "local-test-password"});
    assert.equal(created.error, null);
    const link = await client.linkSocial(direct);
    assert.equal(link.error?.status, 404);
    assert.equal(link.error.code, "ID_TOKEN_NOT_SUPPORTED");
    assert.deepEqual((await client.listAccounts()).data.map(a => a.providerId), ["credential"]);
    assert.equal((await client.getSession()).data.user.id, created.data.user.id);
    for (const start of [body => client.signIn.social(body), body => client.linkSocial(body)]) {
      const browser = await start({provider: "apple", callbackURL: "/done", disableRedirect: true});
      assert.equal(browser.error, null);
      const target = new URL(browser.data.url);
      assert.equal(target.origin, "https://appleid.apple.com");
      assert.equal(target.searchParams.get("response_type"), "code id_token");
      assert.equal(target.searchParams.get("response_mode"), "form_post");
      assert.ok(target.searchParams.get("state"));
    }
  }
}
