import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const moduleURL = new URL("../plugins/onetap/browser.mjs", import.meta.url);

test("One Tap binds the prompt and optional button to the server nonce and checks same-origin redirects", async (t) => {
  const { startOneTap } = await import(moduleURL);
  let config, notification, rendered, resultURL;
  const posted = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(options.mode, "same-origin");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.redirect, "error");
    assert.equal(new URL(url).origin, "https://app.test");
    posted.push(JSON.parse(options.body));
    return Response.json(url.endsWith("/nonce") ? { nonce: "browser-nonce", clientId: "audience" } : { user: { name: "Owner" } });
  });
  globalThis.window = { location: { origin: "https://app.test", href: "https://app.test/start", assign: (u) => { resultURL = u; } } };
  globalThis.google = { accounts: { id: {
    initialize: (opts) => { config = opts; }, prompt: (cb) => { notification = cb; },
    renderButton: (element, opts) => { rendered = [element, opts]; }, cancel() {},
  } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  await assert.rejects(startOneTap({ authPath: "https://other.test" }), /same-origin/);
  await assert.rejects(startOneTap({ callbackURL: "javascript:alert(1)" }), /same-origin/);
  assert.equal(posted.length, 0);
  const element = {}, cb = () => {};
  const flow = await startOneTap({ authPath: "/id", callbackURL: "/ready", button: { element, options: { size: "large" } },
    showPrompt: true, autoSelect: true, cancelOnTapOutside: false, context: "signup", onPromptNotification: cb });
  assert.deepEqual(rendered, [element, { size: "large" }]);
  notification({isSkippedMoment: () => true});
  assert.equal(typeof notification, "function");
  assert.deepEqual([config.client_id, config.nonce, config.ux_mode, config.context, config.auto_select, config.cancel_on_tap_outside],
    ["audience", "browser-nonce", "popup", "signup", true, false]);
  assert.equal(config.itp_support, true);
  await assert.rejects(startOneTap(), /already started/);
  await config.callback({ credential: "signed-credential" });
  await config.callback({ credential: "second-credential" });
  assert.deepEqual(posted, [{}, { idToken: "signed-credential", callbackURL: "https://app.test/ready" }]);
  assert.equal((await flow.result).user.name, "Owner");
  assert.equal(resultURL, "https://app.test/ready");
});

test("canceling One Tap ignores delayed Google credentials", async (t) => {
  const { startOneTap } = await import(moduleURL.href + "?cancel");
  let config, count = 0, canceled = false;
  globalThis.window = { location: { href: "https://app.test/", origin: "https://app.test" } };
  globalThis.google = { accounts: { id: { initialize(opts) { config = opts; }, prompt() {}, cancel() { canceled = true; } } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  t.mock.method(globalThis, "fetch", async () => { count++; return Response.json({ nonce: "n", clientId: "id" }); });
  const flow = await startOneTap();
  flow.cancel();
  await assert.rejects(flow.result, { name: "AbortError" });
  await config.callback({ credential: "late" });
  assert.equal(count, 1);
  assert.equal(canceled, true);
});

test("Chrome posts a stubbed Google credential with its HttpOnly browser cookie", {
  skip: !process.env.CHROME_BIN, timeout: 45_000,
}, async (t) => {
  const calls = [];
  const module = await readFile(moduleURL);
  const server = createServer(async (req, res) => {
    if (req.url === "/one-tap.mjs") {
      res.setHeader("Content-Type", "text/javascript"); res.end(module); return;
    }
    if (req.url === "/api/auth/one-tap/nonce" || req.url === "/api/auth/one-tap/callback") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      calls.push({ path: req.url, body: JSON.parse(raw), cookie: req.headers.cookie });
      res.setHeader("Content-Type", "application/json");
      if (req.url.endsWith("/nonce")) {
        res.setHeader("Set-Cookie", "browser_proof=bound; Path=/; HttpOnly; SameSite=Strict");
        res.end(JSON.stringify({ nonce: "local-nonce", clientId: "local-audience" }));
      } else res.end(JSON.stringify({ user: { name: "Signed in" } }));
      return;
    }
    res.setHeader("Content-Type", "text/html");
    res.end(`<!doctype html><body><output>Starting</output><script type="module">
      import {startOneTap} from "/one-tap.mjs";
      let user;
      window.google = { accounts: { id: {
        initialize(cfg) { user=cfg; },
        prompt() { if(user.nonce === "local-nonce" && user.client_id === "local-audience") user.callback({credential:"local-token"}); }
      } } };
      const flow = await startOneTap();
      const login = await flow.result;
      document.querySelector("output").textContent=login.user.name;
    </script></body>`);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const dir = await mkdtemp(join(tmpdir(), "authn-browser-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 3 }));
  const { stdout } = await promisify(execFile)(process.env.CHROME_BIN, [
    "--headless=new", "--disable-gpu", "--no-first-run", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
    "--user-data-dir=" + dir, "--virtual-time-budget=4000", "--dump-dom", "http://127.0.0.1:" + server.address().port,
  ], { timeout: 35_000 });
  assert.match(stdout, /<output>Signed in<\/output>/);
  assert.equal(calls[1].cookie, "browser_proof=bound");
  assert.deepEqual(calls[1].body, { idToken: "local-token" });
});

test("One Tap retries dismissed prompts and stops on a FedCM skip or cancellation", async (t) => {
  const { startOneTap } = await import(moduleURL.href + "?retry");
  let count = 0, finalReason;
  globalThis.window = {location: {href:"https://app.test/",origin:"https://app.test"}};
  globalThis.google = {accounts: {id: {
    initialize() {}, prompt(notify) {
      count++;
      if (count === 1) notify({isDismissedMoment:()=>true,getDismissedReason:()=>"flow_restarted"});
      else notify({isSkippedMoment:()=>true});
    },
  } } };
  t.after(()=>{delete globalThis.window;delete globalThis.google;});
  const flow = await startOneTap({getChallenge:async()=>({nonce:"bound",clientId:"id"}), promptOptions:{baseDelay:1,maxAttempts:2},
    onPromptNotification(note){finalReason = note.isSkippedMoment?.();}});
  assert.equal(await flow.result, null);
  assert.equal(count, 2);
  assert.equal(finalReason, true);
});

test("redirect buttons pin the same-origin receiver and preserve the host-issued nonce", async (t)=>{
  const { startOneTap } = await import(moduleURL.href+"?redirect-button");
  const element = {}, nonce = "application-issued-nonce";
  let cfg, button;
  globalThis.window={location:{href:"https://app.test/",origin:"https://app.test"}};
  globalThis.document={querySelector:(s)=>s==="#sign-in"?element:null};
  globalThis.google={accounts:{id:{initialize(x){cfg=x;},renderButton(el,style){button={el,style};},prompt(){assert.fail("button-only mode prompted")},cancel(){}}}};
  t.after(()=>{delete globalThis.window;delete globalThis.document;delete globalThis.google;});
  await assert.rejects(startOneTap({uxMode:"redirect",redirectURI:"https://other.example/cb",button:{container:element}}),/same-origin/);
  await assert.rejects(startOneTap({additionalOptions:{login_uri:"https://other.example"}}),/controls the Google/);
  await assert.rejects(startOneTap({additionalOptions:{nonce:"foreign"}}),/controls the Google/);
  const flow=await startOneTap({clientId:"audience",nonce,uxMode:"redirect",redirectURI:"/google/return",
    button:{container:"#sign-in",config:{theme:"outline"}},additionalOptions:{use_fedcm_for_button:true,button_auto_select:false,itp_support:true}});
  assert.deepEqual([cfg.nonce,cfg.client_id,cfg.ux_mode,cfg.login_uri,cfg.use_fedcm_for_button,cfg.button_auto_select],
    [nonce,"audience","redirect","https://app.test/google/return",true,false]);
  assert.deepEqual(button,{el:element,style:{theme:"outline"}});
  flow.cancel();await assert.rejects(flow.result,{name:"AbortError"});
});

test("sign-out clears supported FedCM selection only after the server revokes the session", async(t)=>{
  const {signOutOneTap}=await import(moduleURL.href+"?logout");
  globalThis.window={location:{href:"https://app.test/",origin:"https://app.test"},IdentityCredential:function(){}};
  let clears=0,disables=0,successful=true;
  const own=Object.getOwnPropertyDescriptor(globalThis.navigator,"credentials");
  Object.defineProperty(globalThis.navigator,"credentials",{value:{async preventSilentAccess(){clears++;}},configurable:true});
  globalThis.google={accounts:{id:{disableAutoSelect(){disables++;}}}};
  t.after(()=>{delete globalThis.google;delete globalThis.window;if(own)Object.defineProperty(globalThis.navigator,"credentials",own);else delete globalThis.navigator.credentials;});
  t.mock.method(globalThis,"fetch",async (url,options)=>{assert.equal(url,"https://app.test/api/auth/sign-out");assert.equal(options.credentials,"same-origin");return Response.json({success:successful},{status:successful?200:401});});
  await signOutOneTap();await signOutOneTap({promptOptions:{fedCM:false}});
  successful=false;await assert.rejects(signOutOneTap(),/401/);
  assert.deepEqual([clears,disables],[1,2]);
});

test("an expired host nonce cannot start a new Google prompt", async(t)=>{
  const {startOneTap}=await import(moduleURL.href+"?expired");
  globalThis.window={location:{href:"https://app.test/",origin:"https://app.test"}};
  globalThis.google={accounts:{id:{initialize(){assert.fail("expired challenge initialized Google");}}}};
  t.after(()=>{delete globalThis.window;delete globalThis.google;});
  await assert.rejects(startOneTap({clientId:"client",nonce:"host-challenge",nonceExpiresAt:Date.now()-100}),/expired/);
});

test("One Tap passes other Google options through and refuses to override its audience, nonce or receiver", async (t) => {
  const { startOneTap } = await import(moduleURL.href + "?sdk-options");
  let cfg, challenges = 0;
  globalThis.window = { location: { href: "https://app.test/", origin: "https://app.test" } };
  globalThis.google = { accounts: { id: { initialize(x) { cfg = x; }, prompt() {}, cancel() {} } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  const getChallenge = async () => { challenges++; return { nonce: "bound", clientId: "audience" }; };
  for (const key of ["client_id", "nonce", "callback", "login_uri", "ux_mode"]) {
    await assert.rejects(startOneTap({ getChallenge, additionalOptions: { [key]: "foreign" } }), /controls the Google/);
  }
  assert.deepEqual([challenges, cfg], [0, undefined]);
  const close = () => {};
  const flow = await startOneTap({ getChallenge, context: "signup", additionalOptions: { state_cookie_domain: "app.test", allowed_parent_origin: ["https://app.test"],
    intermediate_iframe_close_callback: close, use_fedcm_for_prompt: true, itp_support: false, auto_select: true, context: "use", cancel_on_tap_outside: false } });
  assert.deepEqual({ ...cfg, callback: typeof cfg.callback }, { client_id: "audience", nonce: "bound", ux_mode: "popup", callback: "function", cancel_on_tap_outside: false,
    state_cookie_domain: "app.test", allowed_parent_origin: ["https://app.test"], intermediate_iframe_close_callback: close, use_fedcm_for_prompt: true,
    itp_support: false, auto_select: true, context: "use" });
  flow.cancel();
  await assert.rejects(flow.result, { name: "AbortError" });
});

test("One Tap sends fetchOptions headers to both auth requests and runs onSuccess before navigating", async (t) => {
  const { startOneTap } = await import(moduleURL.href + "?fetch-options");
  let config;
  const events = [], requests = [];
  globalThis.window = { location: { href: "https://app.test/", origin: "https://app.test", assign: (u) => events.push("navigate " + u) } };
  globalThis.google = { accounts: { id: { initialize(o) { config = o; }, prompt() {}, cancel() {} } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  t.mock.method(globalThis, "fetch", async (url, options) => {
    requests.push({ url, options, body: JSON.parse(options.body) });
    return url.endsWith("/nonce") ? Response.json({ nonce: "n", clientId: "id" }) : Response.json({ user: { name: "Owner" } }, { headers: { "X-Session-Note": "issued" } });
  });
  await assert.rejects(startOneTap({ fetchOptions: { signal: AbortSignal.abort() } }), { name: "AbortError" });
  assert.equal(requests.length, 0);
  const flow = await startOneTap({ callbackURL: "/home", fetchOptions: { headers: { "X-Tenant": "blue", "Content-Type": "text/plain" }, credentials: "include", mode: "cors",
    onSuccess: (ctx) => events.push(["success", ctx.data.user.name, ctx.response.headers.get("x-session-note")]) } });
  await config.callback({ credential: "signed" });
  assert.deepEqual(requests.map((r) => [new URL(r.url).pathname, r.options.headers.get("x-tenant"), r.options.headers.get("content-type"), r.options.credentials, r.options.mode]),
    [["/api/auth/one-tap/nonce", "blue", "application/json", "same-origin", "same-origin"], ["/api/auth/one-tap/callback", "blue", "application/json", "same-origin", "same-origin"]]);
  assert.deepEqual(requests[1].body, { idToken: "signed", callbackURL: "https://app.test/home" });
  assert.deepEqual(events, [["success", "Owner", "issued"], "navigate https://app.test/home"]);
  assert.equal((await flow.result).user.name, "Owner");
});

test("aborting the fetchOptions signal ends One Tap without posting a later credential", async (t) => {
  const { startOneTap } = await import(moduleURL.href + "?fetch-abort");
  let config, nonceSignal, canceled = 0, succeeded = 0;
  const paths = [], navigations = [];
  globalThis.window = { location: { href: "https://app.test/", origin: "https://app.test", assign: (u) => navigations.push(u) } };
  globalThis.google = { accounts: { id: { initialize(o) { config = o; }, prompt() {}, cancel() { canceled++; } } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  t.mock.method(globalThis, "fetch", async (url, options) => {
    paths.push(new URL(url).pathname);
    nonceSignal = options.signal;
    assert.equal(options.signal.aborted, false);
    return Response.json({ nonce: "n", clientId: "id" });
  });
  const host = new AbortController();
  const flow = await startOneTap({ callbackURL: "/home", fetchOptions: { signal: host.signal, onSuccess: () => { succeeded++; } } });
  host.abort();
  await assert.rejects(flow.result, { name: "AbortError" });
  assert.equal(nonceSignal.aborted, true);
  await config.callback({ credential: "late" });
  assert.deepEqual([paths, navigations, canceled, succeeded], [["/api/auth/one-tap/nonce"], [], 1, 0]);
});

test("One Tap backs off from 1, 2, 4, 8 and 16 seconds by default and honours a caller's retry settings", async (t) => {
  const prompts = [], notes = [];
  globalThis.window = { location: { href: "https://app.test/", origin: "https://app.test" } };
  globalThis.google = { accounts: { id: { initialize() {}, prompt(notify) { prompts.push(notify); }, cancel() {} } } };
  t.after(() => { delete globalThis.window; delete globalThis.google; });
  let challenges = 0;
  const getChallenge = async () => { challenges++; return { nonce: "bound", clientId: "id" }; };
  const dismissed = () => ({ isDismissedMoment: () => true, getDismissedReason: () => "flow_restarted" });
  const { startOneTap } = await import(moduleURL.href + "?backoff");
  for (const promptOptions of [{ baseDelay: -1 }, { baseDelay: 60_001 }, { baseDelay: 1.5 }, { maxAttempts: 11 }, { maxAttempts: 1.5 }]) {
    await assert.rejects(startOneTap({ getChallenge, promptOptions }), /retry settings/);
  }
  assert.equal(challenges, 0);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const backOff = async (start, delays) => {
    prompts.length = 0; notes.length = 0;
    const flow = await start();
    assert.equal(prompts.length, 1);
    for (const delay of delays) {
      prompts.at(-1)(dismissed());
      const count = prompts.length;
      t.mock.timers.tick(delay - 1);
      assert.equal(prompts.length, count);
      t.mock.timers.tick(1);
      assert.equal(prompts.length, count + 1);
    }
    assert.equal(notes.length, 0);
    const last = dismissed();
    prompts.at(-1)(last);
    assert.deepEqual([notes.length, notes[0]], [1, last]);
    assert.equal(await flow.result, null);
    t.mock.timers.tick(60_000);
    assert.equal(prompts.length, delays.length + 1);
  };
  await backOff(() => startOneTap({ getChallenge, onPromptNotification: (n) => notes.push(n) }), [1000, 2000, 4000, 8000, 16000]);
  const custom = await import(moduleURL.href + "?backoff-custom");
  await backOff(() => custom.startOneTap({ getChallenge, promptOptions: { baseDelay: 250, maxAttempts: 2 }, onPromptNotification: (n) => notes.push(n) }), [250, 500]);
});
