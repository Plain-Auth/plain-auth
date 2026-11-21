import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

const rules = [
  "https://*.shop.example.test",
  "*.regional.example.test",
  "https://preview-?.example.test:84??",
  "https://192.168.*.*",
  "https://media.example.test:*",
  "*://common.example.test",
];
const email = "origins@example.test";
const password = "local-example-password";

async function referenceServer(t) {
  const database = new DatabaseSync(":memory:");
  t.after(() => database.close());
  const baseURL = "http://reference.localhost";
  const options = {
    database, baseURL, trustedOrigins: rules,
    secret: "local-comparison-secret-for-origin-rules-1234",
    emailAndPassword: { enabled: true }, logger: { disabled: true },
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return { baseURL, send: (request) => auth.handler(request) };
}

export async function compareWildcardOrigins(t, goFixture) {
  const cases = [
    ["https://web.shop.example.test", true],
    ["https://web.eu.shop.example.test", true],
    ["https://web.shop.example.test:443", true],
    ["https://shop.example.test", false],
    ["https://web.shop.example.test:8443", false],
    ["http://web.shop.example.test", false],
    ["https://web.shop.example.test.other.test", false],
    ["http://one.regional.example.test", true],
    ["https://one.regional.example.test", true],
    ["https://preview-a.example.test:8443", true],
    ["https://preview-ab.example.test:8443", false],
    ["https://192.168.2.3", true],
    ["https://192.168.office.example", false],
    ["https://media.example.test:8765", true],
    ["https://media.example.test", false],
    ["https://common.example.test", true],
    ["http://common.example.test", true],
  ];
  for (const [label, setup] of [
    ["published", () => referenceServer(t)],
    ["go", () => goFixture(t, [], { AUTH_TRUSTED_ORIGINS: rules.join(",") })],
  ]) {
    const { baseURL, send } = await setup();
    function post(path, origin, body, cookie) {
      const headers = new Headers({ "content-type": "application/json", origin });
      if (cookie) headers.set("cookie", cookie);
      return send(new Request(baseURL + "/api/auth" + path, {
        method: "POST", headers, body: JSON.stringify(body), redirect: "manual",
      }));
    }
    const signup = await post("/sign-up/email", baseURL, { name: "Initial", email, password });
    assert.equal(signup.status, 200);
    const cookie = signup.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
    assert.ok(cookie);
    let expectedName = "Initial";
    for (const [index, [origin, allowed]] of cases.entries()) {
      const name = "Browser " + index;
      const res = await post("/update-user", origin, { name }, cookie);
      const data = await res.json();
      assert.equal(res.status, allowed ? 200 : 403, label + " cookie update from " + origin);
      if (allowed) expectedName = name;
      else assert.equal(data.code, "INVALID_ORIGIN");
      const session = await send(new Request(baseURL + "/api/auth/get-session", { headers: { cookie } }));
      assert.equal((await session.json()).user.name, expectedName, "only authorized updates change the account");
      const callbackURL = origin + "/orders?view=recent#today";
      const login = await post("/sign-in/email", baseURL, { email, password, callbackURL });
      const result = await login.json();
      assert.equal(login.status, allowed ? 200 : 403, label + " login callback to " + origin);
      if (allowed) assert.equal(result.url, callbackURL);
      else assert.equal(result.code, "INVALID_CALLBACK_URL");
    }
  }
}
