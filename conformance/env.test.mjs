import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("server and client use the application's AUTH settings in an isolated process", async (t) => {
  const tmp = await mkdtemp(join(tmpdir(), "auth-env-"));
  t.after(() => rm(tmp, { recursive: true, force: true }));
  const binary = join(tmp, "auth-env");
  execFileSync("go", ["build", "-o", binary, "./fixture/env"], {
    cwd: fileURLToPath(new URL(".", import.meta.url)), timeout: 180000,
  });
  const run = (env, args = []) => spawnSync(binary, args, { env, encoding: "utf8", timeout: 10000 });
  const output = (env, args) => {
    const result = run(env, args);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };
  const key = "fixture-signing-key-with-at-least-32-bytes";
  const active = "fixture-second-signing-key-with-at-least-32-bytes";
  const other = {
    BETTER_AUTH_SECRET: key, BETTER_AUTH_SECRETS: "99:" + key,
    BETTER_AUTH_URL: "https://external.example.org",
    BETTER_AUTH_TRUSTED_ORIGINS: "https://other.example.test",
    NEXT_PUBLIC_AUTH_URL: "https://client.example.org",
    NEXTAUTH_URL: "https://legacy.example.org", VERCEL_URL: "deploy.example.org",
    NODE_ENV: "production",
  };
  const own = {
    AUTH_URL: "https://issuer.example.test/auth",
    AUTH_SECRET: key, AUTH_SECRETS: "2:" + active + ",1:" + key,
    AUTH_TRUSTED_ORIGINS: "https://client.example.test",
  };
  const signature = createHmac("sha256", active).update("fixture").digest("base64");
  const expected = { mount: own.AUTH_URL, cookie: "fixture." + signature, trusted: true, unknown: false };
  assert.deepEqual(output(own), expected);
  assert.deepEqual(output({ ...own, ...other }), expected);
  assert.notEqual(run(other).status, 0);
  assert.notEqual(run({ ...other, AUTH_URL: own.AUTH_URL }).status, 0);
  assert.notEqual(run({ ...other, AUTH_SECRET: key }).status, 0);
  assert.notEqual(run(other, ["client", ""]).status, 0);
  assert.equal(output({ ...own, ...other }, ["client", ""]), own.AUTH_URL + "/get-session");
  assert.equal(output({ ...own, ...other }, ["client", "https://explicit.example.org"]),
    "https://explicit.example.org/api/auth/get-session");
});
