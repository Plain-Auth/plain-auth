import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

export async function compareSessionCacheVersions(t, { reference, goFixture, instrument }, strategy) {
  const dir = await mkdtemp(join(tmpdir(), "session-version-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "revision");
  const changeVersion = value => writeFile(path, value);
  await changeVersion("initial");
  const go = await goFixture(t, [], {
    CONFORMANCE_CACHE_STRATEGY: strategy, CONFORMANCE_SESSION_VERSION_FILE: path,
    CONFORMANCE_DEFER_SESSION_REFRESH: "1",
  });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  const version = async (session, user) => {
    const revision = await readFile(path, "utf8");
    if (revision === "error") throw new Error("fixture version lookup failed");
    if (revision === "reject-replacement" && user.name === "Live") throw new Error("fixture replacement failed");
    if (revision === "empty") return "";
    return [revision, session.id, user.id, user.name].join("|");
  };
  const ref = await reference(t, [], {
    database, logger: { disabled: true }, session: { deferSessionRefresh: true, cookieCache: { enabled: true, strategy, version } },
  });
  // Preserve one browser jar while selecting which replica handles the next request.
  for (const [label, issuer, reader] of [["go", go, ref], ["reference", ref, go]]) {
    let target = issuer;
    const { client, requests } = instrument({
      baseURL: "http://browser.localhost",
      send: request => {
        const url = new URL(request.url);
        const forwarded = new Request(target.baseURL + url.pathname + url.search, request);
        forwarded.headers.set("Origin", target.baseURL);
        return target.send(forwarded);
      },
    });
    const email = label + "@cache.example.test";
    const account = { name: "Before", email, password: "local-cache-version-test" };
    const setName = name => database.prepare('UPDATE "user" SET name=? WHERE email=?').run(name, email);
    const session = async (query, method = "GET") => client.getSession({ query, fetchOptions: { method } });
    const cacheWasWritten = () => requests.at(-1).cookies.some(c => c.name === "authn.session_data" && !c.attributes.includes("max-age=0"));

    await changeVersion("error");
    const rejectedSignup = await client.signUp.email(account);
    assert.equal(rejectedSignup.error.status, 500);
    assert.deepEqual(requests.at(-1).cookies, []);
    assert.equal(database.prepare('SELECT count(*) AS n FROM "user" WHERE email=?').get(email).n, 0);
    await changeVersion("initial");
    assert.equal((await client.signUp.email(account)).error, null);
    assert.ok(cacheWasWritten());
    setName("Live");
    target = reader;
    assert.equal((await session()).data.user.name, "Before", "the callback reads authenticated snapshot fields");
    assert.equal(requests.at(-1).cookies.length, 0);
    await changeVersion("reject-replacement");
    const failed = await session();
    assert.equal(failed.error.code, "FAILED_TO_GET_SESSION");
    assert.ok(requests.at(-1).cookies.some(c => c.name === "authn.session_data" && c.attributes.includes("max-age=0")),
      "retire the mismatched snapshot when replacement version lookup fails");
    // Recreate the old view to exercise the successful two-replica invalidation separately.
    setName("Before");
    await changeVersion("initial");
    assert.equal((await session()).data.user.name, "Before");
    setName("Live");
    await changeVersion("next");
    assert.equal((await session()).data.user.name, "Live", "a shared revision invalidates another replica's cache");
    assert.ok(cacheWasWritten());
    setName("Newest");
    target = issuer;
    assert.equal((await session()).data.user.name, "Live", "the replacement uses the live session and user");
    await changeVersion("error");
    for (const method of ["GET", "POST"]) {
      for (const query of [undefined, { disableCookieCache: true }]) {
        const result = await session(query, method);
        assert.equal(requests.at(-1).method, method);
        assert.equal(result.error.status, 500);
        assert.equal(result.error.code, "FAILED_TO_GET_SESSION");
        assert.equal(result.error.message, "Failed to get session");
        assert.equal(cacheWasWritten(), false);
      }
      assert.equal((await session({disableCookieCache: true, disableRefresh: true}, method)).data.user.name, "Newest");
    }
    const duplicate = await client.signUp.email(account);
    assert.equal(duplicate.error.code, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
    const rejectedLogin = await client.signIn.email({ email, password: account.password });
    assert.equal(rejectedLogin.error.status, 500);
    assert.deepEqual(requests.at(-1).cookies, []);
    // A stored empty version is read as "1". An empty expected version misses on every read.
    await changeVersion("empty");
    assert.equal((await session()).data.user.name, "Newest");
    assert.ok(cacheWasWritten());
    setName("After empty");
    assert.equal((await session()).data.user.name, "After empty");
    assert.ok(cacheWasWritten());
  }
}
