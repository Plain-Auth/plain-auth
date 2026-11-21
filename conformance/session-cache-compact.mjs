import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { customSession } from "better-auth/plugins";

const name = "authn.session_data";
const tokenName = "authn.session_token";

function pairs(response) {
  return Object.fromEntries(response.headers.getSetCookie().map(line => {
    const pair = line.split(";")[0];
    const eq = pair.indexOf("=");
    return [pair.slice(0, eq), pair.slice(eq + 1)];
  }));
}

function header(cookies) {
  return Object.entries(cookies).map(([k, v]) => k + "=" + v).join("; ");
}

function request(runtime, path, cookies = {}, body) {
  return runtime.send(new Request(runtime.baseURL + "/api/auth/" + path, {
    method: body ? "POST" : "GET",
    headers: { cookie: header(cookies), origin: runtime.baseURL, ...(body && { "content-type": "application/json" }) },
    ...(body && { body: JSON.stringify(body) }),
  }));
}

export async function compareCompactSessionCache(t, { reference, goFixture }) {
  const go = await goFixture(t, [], { CONFORMANCE_COMPACT_CACHE: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const ref = await reference(t, [], { database, session: { cookieCache: { enabled: true, version: "release-test" } } });
  for (const [issuer, reader, prefix] of [[go, ref, "go"], [ref, go, "reference"]]) {
    const email = prefix + "@example.test";
    const password = "cache-fixture-password";
    // Literal separators and an escaped backslash exercise JavaScript signing bytes across runtimes.
    const original = prefix + " <&> \u2028 \u2029 \\u2028";
    const signup = await request(issuer, "sign-up/email", {}, { name: original, email, password });
    assert.equal(signup.status, 200);
    const signed = pairs(signup);
    assert.ok(signed[name] && signed[tokenName]);
    const issued = JSON.parse(Buffer.from(signed[name], "base64url").toString()).session;
    for (const timestamp of [issued.user.createdAt, issued.user.updatedAt, issued.session.createdAt, issued.session.updatedAt, issued.session.expiresAt]) {
      assert.equal(timestamp, new Date(timestamp).toISOString());
    }
    database.prepare('UPDATE "user" SET name=? WHERE email=?').run("Updated", email);
    const cached = await request(reader, "get-session", signed);
    assert.equal((await cached.json()).user.name, original, "the other runtime consumed the signed cookie");
    const fresh = await request(reader, "get-session?disableCookieCache=false", signed);
    assert.equal((await fresh.json()).user.name, "Updated");
    assert.ok(pairs(fresh)[name]);

    // Fractional trailing zeros must survive JSON date revival on the verifying peer.
    database.prepare('UPDATE "user" SET image=?, createdAt=?, updatedAt=? WHERE email=?').run(
      "https://example.test/" + "x".repeat(9000), "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.120Z", email,
    );
    const login = await request(issuer, "sign-in/email", {}, { email, password, rememberMe: false });
    assert.equal(login.status, 200);
    const chunks = pairs(login);
    assert.ok(chunks[name + ".0"] && chunks[name + ".1"] && !chunks[name]);
    const cacheLines = login.headers.getSetCookie().filter(line => line.startsWith(name + "."));
    assert.ok(cacheLines.every(line => !/max-age=/i.test(line) && line.length <= 4050));
    const raw = Object.entries(chunks).filter(([k]) => k.startsWith(name + ".")).sort((a,b) => Number(a[0].split(".").pop()) - Number(b[0].split(".").pop())).map(([,v]) => v).join("");
    const envelope = JSON.parse(Buffer.from(raw, "base64url").toString());
    assert.ok(Math.abs(envelope.expiresAt - envelope.session.updatedAt - 60000) < 1000);
    database.prepare('UPDATE "user" SET name=? WHERE email=?').run("Latest", email);
    assert.equal((await (await request(reader, "get-session", chunks)).json()).user.name, "Updated");
    const mixed = { ...chunks, [tokenName]: signed[tokenName] };
    const rebound = await (await request(reader, "get-session", mixed)).json();
    assert.equal(rebound.user.name, "Latest", "a different valid session token forces a live read");
    assert.notEqual(rebound.session.token, envelope.session.session.token);
    const otherEmail = "other-" + email;
    const other = await request(issuer, "sign-up/email", {}, { email: otherEmail, name: "Other", password });
    assert.equal(other.status, 200);
    const otherOwner = await request(reader, "get-session", { ...chunks, [tokenName]: pairs(other)[tokenName] });
    assert.equal((await otherOwner.json()).user.email, otherEmail);
    const loggedOut = await request(reader, "sign-out", chunks, {});
    assert.equal(loggedOut.status, 200);
    for (const key of Object.keys(chunks).filter(k => k === tokenName || k.startsWith(name + "."))) {
      assert.ok(loggedOut.headers.getSetCookie().some(line => line.startsWith(key + "=;") && /max-age=0/i.test(line)));
    }
    const retained = await request(reader, "get-session", chunks);
    assert.equal((await retained.json()).user.email, email, "another browser may display its retained snapshot until expiry");
    assert.equal(await (await request(reader, "get-session?disableCookieCache=true", chunks)).json(), null);
  }
}

export async function compareCompactProjection(t, { reference, goFixture }) {
  const go = await goFixture(t, [], { CONFORMANCE_COMPACT_CACHE: "1", CONFORMANCE_SESSION_VIEW: "contract", CONFORMANCE_DEFER_SESSION_REFRESH: "1" });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const project = customSession((data, ctx) => {
    ctx.setHeader("cache-control", "public");
    const view = { viewer: data.user.email };
    if ("needsRefresh" in data) view.needsRefresh = data.needsRefresh;
    return view;
  });
  const ref = await reference(t, [project], { database, session: { deferSessionRefresh: true, updateAge: 0, cookieCache: { enabled: true, version: "release-test" } } });
  for (const [issuer, reader, prefix] of [[go, ref, "g"], [ref, go, "r"]]) {
    const email = prefix + "@example.test";
    const freshEmail = prefix + "-fresh@example.test";
    const created = await request(issuer, "sign-up/email", {}, { name: "Cache", email, password: "fixture-password" });
    assert.equal(created.status, 200);
    const cookies = pairs(created);
    database.prepare('UPDATE "user" SET email=? WHERE email=?').run(freshEmail, email);
    const cached = await request(reader, "get-session", cookies);
    assert.equal(cached.headers.get("cache-control"), "no-store");
    assert.deepEqual(await cached.json(), { viewer: email });
    const projectedPost = await sessionPost(reader, "", cookies);
    assert.equal(projectedPost.status, 404);
    const fresh = await request(reader, "get-session?disableCookieCache=true", cookies);
    assert.deepEqual(await fresh.json(), { viewer: freshEmail, needsRefresh: true });
    assert.ok(pairs(fresh)[name]);
  }
}

function sessionPost(runtime, query, cookies) {
  return runtime.send(new Request(runtime.baseURL + "/api/auth/get-session" + query, {
    method: "POST", headers: { cookie: header(cookies), origin: runtime.baseURL },
  }));
}

export async function compareDeferredCompactSession(t, { reference, goFixture }) {
  const go = await goFixture(t, [], {
    CONFORMANCE_COMPACT_CACHE: "1", CONFORMANCE_DEFER_SESSION_REFRESH: "1", CONFORMANCE_IMMEDIATE_SESSION_REFRESH: "1",
  });
  const ref = await reference(t, [], { session: { updateAge: 0, deferSessionRefresh: true, cookieCache: { enabled: true, version: "release-test" } } });
  for (const runtime of [ref, go]) {
    const database = runtime.database ?? new DatabaseSync(go.databasePath);
    if (!runtime.database) t.after(() => database.close());
    const created = await request(runtime, "sign-up/email", {}, { email: "post@example.test", name: "Old", password: "fixture-password" });
    assert.equal(created.status, 200);
    const cookies = pairs(created);
    database.prepare('UPDATE "user" SET name=? WHERE email=?').run("New", "post@example.test");
    for (const method of ["GET", "POST"]) {
      const read = (query, input = cookies) => method === "GET" ? request(runtime, "get-session" + query, input) : sessionPost(runtime, query, input);
      for (const signedToken of [null, "invalid-signature"]) {
        const orphan = { [name]: cookies[name], [name + ".0"]: "stale" };
        if (signedToken !== null) orphan[tokenName] = signedToken;
        const result = await read("", orphan);
        assert.equal(result.status, 200);
        assert.equal(await result.json(), null);
        assert.deepEqual(result.headers.getSetCookie(), [], "enabled cache ignores orphan cookies without changing browser state");
      }
      for (const query of ["", "?disableRefresh=true", "?disableCookieCache="]) {
        const cached = await read(query);
        assert.equal(cached.status, 200);
        const body = await cached.json();
        assert.equal(body.user.name, "Old");
        assert.equal(body.needsRefresh, undefined);
        assert.deepEqual(cached.headers.getSetCookie(), []);
      }
      for (const query of ["?disableCookieCache=true&disableRefresh=true", "?disableCookieCache=false&disableRefresh=false"]) {
        const suspended = await read(query);
        assert.equal(suspended.status, 200);
        const body = await suspended.json();
        assert.equal(body.user.name, "New");
        assert.equal(body.needsRefresh, undefined);
        assert.equal(pairs(suspended)[tokenName], undefined);
      }
      const authoritative = await read("?disableCookieCache=true");
      assert.equal(authoritative.status, 200);
      const body = await authoritative.json();
      assert.equal(body.user.name, "New");
      assert.equal(body.needsRefresh, method === "GET" ? true : undefined);
      assert.equal(pairs(authoritative)[tokenName] !== undefined, method === "POST");
      assert.ok(pairs(authoritative)[name]);
    }
  }
}
