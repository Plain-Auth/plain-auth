import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { oAuthProxy } from "better-auth/plugins";
import { genericOAuth } from "better-auth/plugins/generic-oauth";
import { chromeBinary, openChromePage, waitForDocument } from "./browser-debug.mjs";

const mount = "/identity";
const cookieHeader = (res) => res.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");

async function referencePair(t, reference) {
  const preview = "http://review.localhost";
  const production = "http://login.localhost";
  const servers = new Map();
  for (const origin of [preview, production]) {
    const provider = genericOAuth({ config: [{
      providerId: "work", clientId: "work", clientSecret: "local fixture",
      authorizationUrl: "https://identity.fixture.invalid/authorize", tokenUrl: "https://identity.fixture.invalid/token",
      pkce: true, scopes: ["profile"],
      getToken: async () => {
        assert.equal(origin, production);
        return { accessToken: "private provider fixture token", tokenType: "Bearer" };
      },
      getUserInfo: async () => ({id:"employee", email:"employee@example.test", name:"Employee", emailVerified:true}),
      accountSubject: ({profile}) => profile.id,
    }]});
    const proxy = oAuthProxy({currentURL:origin, productionURL:production, secret:"shared only across local oauth proxy fixtures"});
    const host = await reference(t, [provider,proxy], {baseURL:origin,basePath:mount,trustedOrigins:[preview],secret:"local environment session fixture key "+origin});
    servers.set(origin, host);
  }
  return { baseURL:preview, database:servers.get(preview).database, productionDatabase:servers.get(production).database,
    send: request => servers.get(new URL(request.url).origin).send(request) };
}

export async function compareProxyDeployments(t, { reference, goFixture, instrument }) {
  const go = await goFixture(t, [], { CONFORMANCE_OAUTH_PROXY:"1" });
  const database = new DatabaseSync(go.databasePath);
  const productionDatabase = new DatabaseSync(go.databasePath + ".production");
  t.after(() => { database.close(); productionDatabase.close(); });
  for (const host of [await referencePair(t,reference), {...go,database,productionDatabase}]) {
    for (const [completion, expectedPage] of [["provider","welcome"], ["alias","done"]]) {
      let binding;
      const { client } = instrument({...host,basePath:mount,send: async request => {
        const res = await host.send(request);
        binding = cookieHeader(res);
        return res;
      }});
      const started = await client.signIn.social({provider:"work", disableRedirect:true, callbackURL:host.baseURL+"/done", newUserCallbackURL:host.baseURL+"/welcome"});
      assert.equal(started.error,null);
      assert.ok(binding);
      const authorization = new URL(started.data.url);
      const callback = new URL(authorization.searchParams.get("redirect_uri"));
      assert.notEqual(callback.origin,host.baseURL);
      assert.equal(callback.pathname,mount+"/callback/work");
      callback.searchParams.set("state",authorization.searchParams.get("state"));
      callback.searchParams.set("code","approved");
      const exchange = await host.send(new Request(callback,{redirect:"manual"}));
      assert.equal(exchange.status,302);
      assert.equal(cookieHeader(exchange),"");
      const target = new URL(exchange.headers.get("location"));
      assert.equal(target.origin,host.baseURL);
      assert.equal(target.pathname,mount+"/callback/work/oauth-proxy");
      assert.ok(target.searchParams.get("profile"));
      assert.equal(target.href.includes("private provider fixture token"),false);
      if (completion==="alias") target.pathname = mount+"/oauth-proxy-callback";
      const returned = await host.send(new Request(target,{redirect:"manual",headers:{Cookie:binding}}));
      assert.equal(returned.status,302);
      assert.equal(returned.headers.get("location"),host.baseURL+"/"+expectedPage);
      const session = await host.send(new Request(host.baseURL+mount+"/get-session",{headers:{Cookie:cookieHeader(returned)}}));
      assert.equal(session.status,200);
      assert.equal((await session.json()).user.email,"employee@example.test");
    }
    assert.equal(host.database.prepare('SELECT count(*) AS n FROM "user"').get().n,1);
    for (const table of ["user","session","account"]) {
      assert.equal(host.productionDatabase.prepare('SELECT count(*) AS n FROM "'+table+'"').get().n,0);
    }
  }
}

async function openPreview(t, goFixture) {
  const binary = chromeBinary();
  if (!binary) {
    t.skip("requires a local Chrome or Chromium");
    return;
  }
  const {baseURL} = await goFixture(t, [], {CONFORMANCE_OAUTH_PROXY:"1"});
  const landing = baseURL + "/welcome?start";
  const call = await openChromePage(t, landing, binary);
  return {baseURL, call};
}

export async function browserProxySignIn(t, goFixture) {
  const page = await openPreview(t, goFixture);
  if (!page) return;
  const {baseURL, call} = page;
  async function evaluate(expression) {
    const response = await call("Runtime.evaluate", {expression, awaitPromise:true, returnByValue:true});
    assert.equal(response.exceptionDetails, undefined);
    return response.result.value;
  }
  const authorization = await evaluate(`fetch("/identity/sign-in/social", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({provider:"work", disableRedirect:true, callbackURL:"/done", newUserCallbackURL:"/welcome"})
  }).then(r => r.json()).then(r => r.url)`);
  const registered = new URL(new URL(authorization).searchParams.get("redirect_uri"));
  assert.notEqual(registered.hostname, new URL(baseURL).hostname);
  await call("Page.navigate", {url:authorization});
  await waitForDocument(call, baseURL + "/welcome");
  const session = await evaluate('fetch("/identity/get-session").then(r => r.json())');
  assert.equal(session.user.email, "employee@example.test");
  const {cookies} = await call("Network.getCookies", {urls:[baseURL, registered.origin]});
  const sessions = cookies.filter(c => c.name.endsWith(".session_token"));
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].domain, new URL(baseURL).hostname);
  assert.equal(sessions[0].httpOnly, true);
}

export async function browserProxyPopup(t, goFixture) {
  const page = await openPreview(t, goFixture);
  if (!page) return;
  const {call} = page;
  const response = await call("Runtime.evaluate", {awaitPromise:true, returnByValue:true, userGesture:true, expression:`
    new Promise((resolve, reject) => {
      const params = new URLSearchParams({provider:"work", popupOrigin:location.origin,
        popupNonce:"browser-roundtrip", callbackURL:"/done", newUserCallbackURL:"/welcome",
        additionalData:JSON.stringify({source:"popup"})});
      const timeout = setTimeout(() => reject(Error("Popup did not return")), 15000);
      const popup = window.open("/identity/oauth-popup/start?" + params, "oauth");
      addEventListener("message", async event => {
        if (event.source !== popup || event.origin !== location.origin) return;
        clearTimeout(timeout);
        const session = await (await fetch("/identity/get-session")).json();
        resolve({nonce:event.data.nonce, redirect:event.data.redirectTo, name:session.user.name});
      });
    })`});
  assert.equal(response.exceptionDetails, undefined);
  assert.deepEqual(response.result.value, {nonce:"browser-roundtrip", redirect:"/welcome", name:"Popup Employee"});
}
