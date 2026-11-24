import assert from "node:assert/strict";
import { genericOAuth } from "better-auth/plugins/generic-oauth";

// A provider callback whose state cannot be used sends the browser to the
// error page with the same code on both runtimes, for each state strategy.
async function scenario(t, {reference, goFixture, instrument}, strategy, damage) {
  const provider = genericOAuth({config:[{
    providerId:"work", scopes:["profile"], clientId:"fixture-client", clientSecret:"fixture-secret",
    authorizationUrl:"https://id.example/authorize", tokenUrl:"https://id.example/token",
    getToken:async () => ({accessToken:"local-test", tokenType:"Bearer"}),
    getUserInfo:async () => ({id:"sample-user", email:"jo@example.org", name:"Jo", emailVerified:true}),
    accountSubject:({profile})=>profile.id,
  }]});
  const ref = await reference(t, [provider], {account:{storeStateStrategy:strategy}});
  const go = await goFixture(t, [], {CONFORMANCE_PROVIDER:"1", CONFORMANCE_LINK_POLICY:"default", CONFORMANCE_OAUTH_STATE:strategy});
  const outcomes = [];
  for (const target of [ref, go]) {
    const jar = new Map();
    const transport = {...target, send:async r => {
      if (jar.size) r.headers.set("cookie", [...jar].map(([key, value]) => key + "=" + value).join("; "));
      const res = await target.send(r);
      for (const header of res.headers.getSetCookie()) {
        const pair = header.split(";")[0], split = pair.indexOf("=");
        if (/;\s*max-age=0(?:;|$)/i.test(header)) jar.delete(pair.slice(0, split));
        else jar.set(pair.slice(0, split), pair.slice(split + 1));
      }
      return res;
    }};
    const stateCookie = () => [...jar.keys()].find(key => /(^|\.)(oauth_)?state$/.test(key));
    const {client} = instrument(transport);
    const start = async () => {
      const started = await client.signIn.social({provider:"work", callbackURL:"/complete", disableRedirect:true});
      assert.equal(started.error, null);
      const authURL = new URL(started.data.url);
      const callback = new URL(authURL.searchParams.get("redirect_uri"));
      callback.searchParams.set("state", authURL.searchParams.get("state"));
      callback.searchParams.set("code", "fixture-approval");
      return callback;
    };
    let callback = await start();
    if (damage === "no-state") callback.searchParams.delete("state");
    if (damage === "unknown-state") callback.searchParams.set("state", "unknown" + "0".repeat(25));
    if (damage === "no-cookie") jar.delete(stateCookie());
    if (damage === "altered-cookie") {
      // Alter a character well inside the value, whatever its encoding.
      const name = stateCookie(), value = jar.get(name), at = Math.floor(value.length / 2);
      jar.set(name, value.slice(0, at) + (value[at] === "a" ? "b" : "a") + value.slice(at + 1));
    }
    if (damage === "other-flow") {
      const name = stateCookie(), first = jar.get(name);
      callback = await start();
      jar.set(name, first);
    }
    const res = await transport.send(new Request(callback, {redirect:"manual", headers:{"user-agent":"authn-conformance"}}));
    const landing = res.status === 302 ? new URL(res.headers.get("Location"), target.baseURL) : null;
    outcomes.push({
      status: res.status,
      landing: landing && landing.pathname + "?error=" + landing.searchParams.get("error"),
      session: res.headers.getSetCookie().some(c => /session_token=[^;]/.test(c)),
    });
  }
  assert.deepEqual(outcomes[1], outcomes[0]);
  return outcomes[0];
}

export async function compareCallbackState(t, harness) {
  for (const [strategy, damage, code] of [
    ["database", "no-state", "state_not_found"],
    ["database", "unknown-state", "state_mismatch"],
    ["database", "no-cookie", "state_mismatch"],
    ["database", "altered-cookie", "state_mismatch"],
    ["cookie", "no-state", "state_not_found"],
    ["cookie", "no-cookie", "state_mismatch"],
    ["cookie", "altered-cookie", "state_invalid"],
    ["cookie", "other-flow", "state_mismatch"],
  ]) {
    const got = await scenario(t, harness, strategy, damage);
    assert.equal(got.status, 302, `${strategy} ${damage}`);
    assert.equal(got.landing, "/api/auth/error?error=" + code, `${strategy} ${damage}`);
    assert.equal(got.session, false, `${strategy} ${damage}`);
  }
}
