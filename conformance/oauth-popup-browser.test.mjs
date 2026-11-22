import assert from "node:assert/strict";
import test from "node:test";
import { createPopupClient, POPUP_MESSAGE_TYPE } from "../plugins/oauthpopup/browser.mjs";

function browser(t, embedded = false, options = {}) {
  const win = new EventTarget();
  win.self = win;
  win.top = embedded
    ? {
        get location() {
          throw Error("cross origin");
        }
      }
    : win;
  win.location = new URL("https://app.example/entry");
  win.screenX = 10;
  win.screenY = 5;
  win.outerWidth = 1000;
  win.outerHeight = 800;
  const storage = new Map();
  win.localStorage = {
    getItem: (k) => storage.get(k) ?? null,
    setItem: (k, v) => storage.set(k, v),
    removeItem: (k) => storage.delete(k)
  };
  let opened;
  win.open = (url, name, features) =>
    (opened = {
      url,
      name,
      features,
      closed: false,
      focused: 0,
      focus() {
        this.focused++;
      },
      close() {
        this.closed = true;
      }
    });
  globalThis.window = win;
  t.after(() => delete globalThis.window);
  const calls = [],
    notifications = [];
  let response = () => Response.json({ session: { id: "session" } });
  const client = createPopupClient({
    ...options,
    baseURL: "https://identity.example/login",
    onSession: (s) => notifications.push(s),
    fetch: async (url, options) => {
      calls.push({ url, options });
      return response();
    }
  });
  function deliver(data = {}, origin = "https://identity.example", source = opened) {
    const event = new Event("message");
    Object.assign(event, {
      origin,
      source,
      data: {
        type: POPUP_MESSAGE_TYPE,
        nonce: opened.url.searchParams.get("popupNonce"),
        token: "returned-token",
        ...data
      }
    });
    win.dispatchEvent(event);
  }
  return {
    win,
    client,
    calls,
    notifications,
    storage,
    deliver,
    get opened() {
      return opened;
    },
    reply(cb) {
      response = cb;
    }
  };
}

test("popup messages require exact origin, window, wire type and nonce while preserving host listeners", async (t) => {
  const b = browser(t);
  let heard = 0;
  b.win.addEventListener("message", () => heard++);
  const result = b.client.signIn.popup({
    providerId: "custom",
    provider: "built-in",
    callbackURL: "/ok",
    errorCallbackURL: "/error",
    newUserCallbackURL: "/welcome",
    requestSignUp: true,
    scopes: ["read", "email"],
    additionalData: { label: "local" },
    windowFeatures: "width=320",
    timeoutMs: 2000
  });
  const u = b.opened.url;
  assert.equal(u.pathname, "/login/oauth-popup/start");
  assert.equal(b.opened.features, "width=320");
  assert.equal(u.searchParams.get("provider"), "built-in");
  assert.match(u.searchParams.get("popupNonce"), /^[a-f0-9]{32}$/);
  assert.deepEqual(
    [
      "popupOrigin",
      "callbackURL",
      "errorCallbackURL",
      "newUserCallbackURL",
      "requestSignUp",
      "scopes",
      "additionalData"
    ].map((k) => u.searchParams.get(k)),
    ["https://app.example", "/ok", "/error", "/welcome", "true", "read,email", '{"label":"local"}']
  );
  const second = await b.client.signIn.popup({ provider: "other" });
  assert.equal(second.error.code, "POPUP_SIGN_IN_FAILED");
  assert.equal(b.opened.focused, 1);
  b.deliver({}, "https://wrong.example");
  b.deliver({}, undefined, {});
  b.deliver({ nonce: "other" });
  b.deliver({ type: "bogus" });
  b.deliver({ token: "" });
  await Promise.resolve();
  assert.equal(b.calls.length, 0);
  b.deliver();
  assert.deepEqual(await result, { data: { success: true }, error: null });
  assert.equal(b.opened.closed, true);
  assert.equal(b.client.getStoredPopupToken(), null);
  assert.equal(b.calls[0].options.headers.has("Authorization"), false);
  b.deliver();
  assert.equal(heard, 7);
  assert.equal(b.notifications.length, 1);
});

test("blocked, closed, aborted, timed-out and rejected popups release their listener and window", async (t) => {
  const b = browser(t);
  assert.equal((await b.client.signIn.popup({})).error.code, "POPUP_SIGN_IN_FAILED");
  const open = b.win.open;
  b.win.open = () => null;
  assert.equal((await b.client.signIn.popup({ provider: "x" })).error.code, "POPUP_BLOCKED");
  b.win.open = open;
  const closed = b.client.signIn.popup({ provider: "x", timeoutMs: 2000 });
  b.opened.closed = true;
  assert.equal((await closed).error.code, "POPUP_CLOSED");
  const ac = new AbortController();
  const aborted = b.client.signIn.popup({ provider: "x", signal: ac.signal });
  assert.equal(b.opened.features, "width=500,height=600,left=260,top=105,menubar=no,toolbar=no");
  ac.abort();
  assert.equal((await aborted).error.code, "POPUP_CLOSED");
  assert.equal(b.opened.closed, true);
  assert.equal(
    (await b.client.signIn.popup({ provider: "x", timeoutMs: 1 })).error.code,
    "POPUP_TIMEOUT"
  );
  const rejected = b.client.signIn.popup({ provider: "x" });
  b.deliver({ error: { code: "declined", description: "Not approved" } });
  assert.deepEqual(await rejected, {
    data: null,
    error: { code: "declined", message: "Not approved" }
  });
  assert.equal(b.calls.length, 0);
});

test("embedded bearers are confined to the auth mount and cleared after confirmed termination or failed handoff", async (t) => {
  const b = browser(t, true);
  const signIn = async () => {
    const login = b.client.signIn.popup({ providerId: "custom" });
    assert.equal(b.opened.url.searchParams.get("provider"), "custom");
    b.deliver();
    return await login;
  };
  for (const path of [
    "/sign-out",
    "/revoke-session",
    "/revoke-sessions",
    "/revoke-other-sessions",
    "/delete-user"
  ]) {
    const login = await signIn();
    assert.equal(login.error, null);
    assert.equal(b.client.getStoredPopupToken(), "returned-token");
    assert.equal(b.calls.at(-1).options.headers.get("Authorization"), "Bearer returned-token");
    assert.equal(b.calls.at(-1).options.credentials, "omit");
    assert.equal(b.calls.at(-1).options.redirect, "error");
    for (const invalid of [
      "https://evil.test/",
      "//evil.test",
      "/../resource",
      "/%2e%2e/resource",
      "/x%2f..",
      "/\\evil"
    ]) {
      await assert.rejects(b.client.fetch(invalid), TypeError);
    }
    await b.client.fetch("/get-session", { headers: { authorization: "Bearer chosen" } });
    assert.equal(b.calls.at(-1).options.headers.get("Authorization"), "Bearer chosen");
    b.reply(() => new Response(null, { status: 401 }));
    await b.client.fetch(path);
    assert.equal(b.client.getStoredPopupToken(), "returned-token");
    b.reply(() => Response.json({ done: true }));
    await b.client.fetch(path);
    assert.equal(b.client.getStoredPopupToken(), null);
  }
  b.reply(() => Response.json(null));
  assert.equal((await signIn()).error.code, "POPUP_SIGN_IN_FAILED");
  assert.equal(b.client.getStoredPopupToken(), null);
  b.reply(() => {
    throw Error("offline");
  });
  assert.equal((await signIn()).error.code, "POPUP_SIGN_IN_FAILED");
  assert.equal(b.client.getStoredPopupToken(), null);
  b.win.localStorage.setItem = () => {
    throw Error("disabled");
  };
  const calls = b.calls.length;
  assert.equal((await signIn()).error.code, "POPUP_SIGN_IN_FAILED");
  assert.equal(b.calls.length, calls);
});

test("different auth mounts isolate their embedded session credentials", async (t) => {
  const b = browser(t, true);
  const handoff = b.client.signIn.popup({ provider: "work" });
  b.deliver();
  assert.equal((await handoff).error, null);
  for (const baseURL of ["https://identity.example/other", "https://other.example/login"]) {
    const another = createPopupClient({ baseURL });
    assert.equal(another.getStoredPopupToken(), null);
  }
  b.reply(() => new Response(null, { status: 401 }));
  const again = b.client.signIn.popup({ provider: "work" });
  b.deliver();
  const denied = await again;
  assert.equal(denied.error.status, 401);
  assert.equal(b.client.getStoredPopupToken(), null);
});

test("a host-selected message protocol retains origin, window and nonce binding", async (t) => {
  const kind = "work.auth:oauth.popup",
    b = browser(t, false, { messageType: kind });
  for (const messageType of ["*", "oauth", "a:b:c", "a:b\n", "x".repeat(65) + ":popup", null]) {
    assert.throws(() => createPopupClient({ messageType }), TypeError);
  }
  const login = b.client.signIn.popup({ provider: "work", messageType: "untrusted:protocol" });
  assert.equal(b.opened.url.searchParams.has("messageType"), false);
  b.deliver();
  b.deliver({ type: "untrusted:protocol" });
  b.deliver({ type: kind }, "https://wrong.example");
  b.deliver({ type: kind }, undefined, {});
  b.deliver({ type: kind, nonce: "other" });
  await Promise.resolve();
  assert.equal(b.calls.length, 0);
  b.deliver({ type: kind });
  assert.equal((await login).error, null);
  assert.equal(b.notifications.length, 1);
});
