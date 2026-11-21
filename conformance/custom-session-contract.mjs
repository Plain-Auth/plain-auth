import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { customSession } from "better-auth/plugins";

const applicationCookies = [["fixture_first", 11], ["fixture_second", 22]];

function projection(data, ctx) {
  ctx.setHeader("cache-control", "public, max-age=3600");
  ctx.setHeader("pragma", "cache");
  ctx.setHeader("x-application-view", "active");
  for (const [name, maxAge] of applicationCookies) {
    ctx.setCookie(name, "view", { path: "/", secure: true, httpOnly: true, sameSite: "none", partitioned: true, maxAge });
  }
  if (ctx.headers.get("x-fail-projection") === "yes") {
    throw new Error("private projection backend detail");
  }
  const view = { viewer: data.user.email };
  if ("needsRefresh" in data) view.needsRefresh = data.needsRefresh;
  return view;
}

function getCookie(response, name) {
  return response.headers.getSetCookie().find(line => line.startsWith(name + "="));
}

function sessionRequests(server) {
  return (path, method = "GET", headers = {}, body) => {
    const init = { method, headers: { origin: server.baseURL, ...headers } };
    if (body) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return server.send(new Request(server.baseURL + "/api/auth/" + path, init));
  };
}

async function signUp(request) {
  const signup = await request("sign-up/email", "POST", {}, {
    email: "view@example.test", name: "Viewer", password: "valid-fixture-password",
  });
  assert.equal(signup.status, 200);
  return getCookie(signup, "authn.session_token").split(";")[0];
}

export async function compareCustomSession(t, { reference, goFixture }) {
  for (const deferred of [false, true]) {
    const settings = { session: { deferSessionRefresh: deferred, updateAge: 0 }, logger: { disabled: true } };
    const ref = await reference(t, [customSession(projection)], settings);
    const go = await goFixture(t, [], { CONFORMANCE_SESSION_VIEW: "contract", CONFORMANCE_DEFER_SESSION_REFRESH: deferred ? "1" : "0" });
    for (const server of [ref, go]) {
      const db = server.database ?? new DatabaseSync(server.databasePath);
      if (!server.database) t.after(() => db.close());
      const request = sessionRequests(server);
      const credential = await signUp(request);
      assert.equal(await (await request("get-session")).json(), null);
      assert.equal((await request("get-session", "POST", { cookie: credential })).status, 404);

      const cases = [
        ["", true], ["?disableRefresh=", true], ["?disableRefresh=false", false],
        ["?disableRefresh=true", false], ["?disableCookieCache=true", true],
      ];
      for (const [query, refresh] of cases) {
        const response = await request("get-session" + query, "GET", { cookie: credential });
        const expected = { viewer: "view@example.test" };
        if (deferred && refresh) expected.needsRefresh = true;
        assert.deepEqual(await response.json(), expected);
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.equal(response.headers.get("pragma"), "no-cache");
        assert.equal(response.headers.get("x-application-view"), "active");
        for (const [name, age] of applicationCookies) {
          const header = getCookie(response, name);
          assert.ok(header && !header.includes(", "));
          assert.match(header, /; Partitioned/i);
          assert.match(header, new RegExp("Max-Age=" + age + "(?:;|$)", "i"));
        }
        const renewed = getCookie(response, "authn.session_token");
        assert.equal(renewed?.split(";")[0], !deferred && refresh ? credential : undefined);
      }

      const stale = await request("get-session?disableRefresh=true", "GET", {
        cookie: credential + "; authn.session_data.0=old; authn.session_data.1=old; authn.session_data.invalid=keep",
      });
      for (const name of ["authn.session_data.0", "authn.session_data.1"]) {
        assert.match(getCookie(stale, name), /max-age=0/i);
      }
      assert.equal(getCookie(stale, "authn.session_data.invalid"), undefined);

      const failed = await request("get-session", "GET", { cookie: credential, "x-fail-projection": "yes" });
      assert.equal(failed.status, 500);
      assert.ok(!(await failed.text()).includes("private projection backend detail"));
      assert.equal(failed.headers.get("x-application-view"), null);
      assert.deepEqual(failed.headers.getSetCookie(), []);

      db.exec('ALTER TABLE "session" RENAME TO "offline_session"');
      try {
        const unavailable = await request("get-session", "GET", { cookie: credential });
        assert.equal(unavailable.status, 500);
        assert.equal((await unavailable.json()).code, "FAILED_TO_GET_SESSION");
        assert.equal(unavailable.headers.get("x-application-view"), null);
      } finally {
        db.exec('ALTER TABLE "offline_session" RENAME TO "session"');
      }

      db.exec('DELETE FROM "session"');
      const revoked = await request("get-session", "GET", { cookie: credential });
      assert.equal(await revoked.json(), null);
      assert.match(getCookie(revoked, "authn.session_token"), /max-age=0/i);
      assert.equal(revoked.headers.get("x-application-view"), null);
    }
  }
}

export async function compareOrdinarySession(t, { reference, goFixture }) {
  for (const deferred of [false, true]) {
    const ref = await reference(t, [], { session: { deferSessionRefresh: deferred } });
    const go = await goFixture(t, [], { CONFORMANCE_DEFER_SESSION_REFRESH: deferred ? "1" : "0" });
    for (const server of [ref, go]) {
      const request = sessionRequests(server);
      const cookie = await signUp(request);
      const get = await request("get-session", "GET", { cookie });
      assert.equal(get.headers.get("cache-control"), "no-store");
      const body = await get.json();
      assert.equal(body.user.email, "view@example.test");
      assert.equal(body.needsRefresh, deferred ? false : undefined);
      const post = await request("get-session", "POST", { cookie });
      assert.equal(post.status, deferred ? 200 : 405);
      if (deferred) assert.equal((await post.json()).user.email, body.user.email);
    }
  }
}

export async function pinnedCookieCacheContract(t, reference) {
  const server = await reference(t, [customSession(({ user }) => ({ display: user.name }))], {
    session: { expiresIn: 86400, updateAge: 0, cookieCache: { enabled: true, maxAge: 300 } },
    advanced: {
      cookiePrefix: "authn",
      defaultCookieAttributes: { httpOnly: true, secure: true, sameSite: "none", partitioned: true },
    },
  });
  const request = sessionRequests(server);
  const signup = await request("sign-up/email", "POST", {}, {
    email: "cache@example.test", name: "Initial", password: "valid-fixture-password",
  });
  assert.equal(signup.status, 200);
  const cookie = signup.headers.getSetCookie().map(line => line.split(";")[0]).join("; ");
  const read = query => request("get-session" + query, "GET", { cookie });
  server.database.prepare("UPDATE user SET name=? WHERE email=?").run("Updated", "cache@example.test");
  assert.deepEqual(await (await read("")).json(), { display: "Initial" });
  assert.deepEqual(await (await read("?disableCookieCache=")).json(), { display: "Initial" });
  for (const flag of ["false", "true"]) {
    const fresh = await read("?disableCookieCache=" + flag);
    assert.deepEqual(await fresh.json(), { display: "Updated" });
    for (const [suffix, maxAge] of [["session_token", 86400], ["session_data", 300]]) {
      const record = fresh.headers.getSetCookie().find(line => line.split("=")[0].endsWith("." + suffix));
      assert.ok(record, "pinned runtime should renew " + suffix);
      assert.match(record, /; Partitioned/i);
      assert.match(record, new RegExp("Max-Age=" + maxAge + "(?:;|$)", "i"));
    }
  }
}
