import assert from "node:assert/strict";

export async function checkCacheCleanup({baseURL, send}) {
  const prefix = "authn.session_data";
  const sendRequest = (path, cookie, body) => send(new Request(baseURL + "/api/auth" + path, {
    method: body ? "POST" : "GET",
    headers: { origin: baseURL, cookie, ...(body && {"content-type": "application/json"}) },
    body: body && JSON.stringify(body),
  }));
  const signup = await sendRequest("/sign-up/email", "", {
    email: "cache@example.test", name: "Cache fixture", password: "local-cache-cleanup",
  });
  const account = (await signup.json()).user;
  const login = signup.headers.getSetCookie().map(c => c.split(";")[0]).find(c => c.startsWith("authn.session_token="));
  assert.ok(login);
  const foreign = ["foreign.session_data=keep", prefix + ".01=keep", prefix + ".label=keep", prefix + ".9007199254740992=keep"];
  const valid = [prefix, prefix + ".0", prefix + ".17", prefix + ".9007199254740991"];
  for (const [sessionCookie, names] of [["", valid], [login, [prefix]], [login, valid.slice(1)], [login, []]]) {
    const header = [...foreign, ...(sessionCookie ? [sessionCookie] : []), ...names.map(name => name + "=stale")].join("; ");
    const res = await sendRequest("/get-session", header);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data?.user.id ?? null, sessionCookie ? account.id : null);
    const expired = res.headers.getSetCookie().map(cookie => {
      assert.match(cookie.toLowerCase(), /; max-age=0(?:;|$)/);
      return cookie.split("=")[0];
    });
    assert.deepEqual(expired.sort(), [...names].sort());
  }
  const logout = await sendRequest("/sign-out", [login, ...foreign, ...valid.map(n => n + "=stale")].join("; "), {});
  const expiredNames = logout.headers.getSetCookie().map(v => v.split("=")[0]);
  assert.ok(valid.every(n => expiredNames.includes(n)));
  assert.ok(foreign.every(v => !expiredNames.includes(v.split("=")[0])));
}
