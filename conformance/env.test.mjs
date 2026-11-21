import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { makeSignature } from "better-auth/crypto";

test("host environment selects the same mount, trusted origins and active signing key", async (t) => {
  const tmp = await mkdtemp(join(tmpdir(), "auth-env-"));
  t.after(() => rm(tmp, { recursive: true, force: true }));
  const binary = join(tmp, "auth-env");
  execFileSync("go", ["build", "-o", binary, "./fixture/env"], {
    cwd: fileURLToPath(new URL(".", import.meta.url)), timeout: 180000,
  });
  const keyA = "development-fixture-key-a-0123456789";
  const keyB = "development-fixture-key-b-0123456789";
  const envNames = ["AUTH_ENV", "NODE_ENV", "AUTH_SECRETS", "BETTER_AUTH_SECRETS", "AUTH_SECRET",
    "BETTER_AUTH_SECRET", "AUTH_URL", "BETTER_AUTH_URL", "NEXT_PUBLIC_BETTER_AUTH_URL",
    "PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_BETTER_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL",
    "AUTH_TRUSTED_ORIGINS", "BETTER_AUTH_TRUSTED_ORIGINS",
    "NEXT_PUBLIC_AUTH_URL", "NEXTAUTH_URL", "VERCEL_URL"];
  const initial = Object.fromEntries(envNames.map((k) => [k, process.env[k]]));
  const reset = (values) => {
    for (const k of envNames) {
      if (values[k] === undefined) delete process.env[k];
      else process.env[k] = values[k];
    }
  };
  t.after(() => reset(initial));
  const publicURL = "https://issuer.example.test/auth";
  for (const vars of [
    { BETTER_AUTH_SECRET: keyA, AUTH_SECRET: keyB, BETTER_AUTH_URL: publicURL,
      BETTER_AUTH_TRUSTED_ORIGINS: "https://client.example.test,https://ui.example.test" },
    { AUTH_SECRET: keyB, PUBLIC_BETTER_AUTH_URL: publicURL },
    { BETTER_AUTH_SECRETS: "2:" + keyB + ",1:" + keyA, BETTER_AUTH_SECRET: keyA, BASE_URL: publicURL },
  ]) {
    reset(vars);
    const db = new DatabaseSync(":memory:");
    try {
      const ctx = await betterAuth({ database: db, telemetry: { enabled: false }, logger: { disabled: true } }).$context;
      const expected = {
        mount: ctx.baseURL,
        cookie: "fixture." + await makeSignature("fixture", ctx.secret),
        trusted: ctx.isTrustedOrigin("https://client.example.test/return"),
        unknown: ctx.isTrustedOrigin("https://other.example.test/return"),
      };
      assert.deepEqual(JSON.parse(execFileSync(binary, { encoding: "utf8", timeout: 10000 })), expected);
    } finally {
      db.close();
    }
  }
  await t.test("native client and pinned client issue the same session request", async () => {
    for (const [env, explicit] of [
      [{ BETTER_AUTH_URL: "https://server.example.org", NEXT_PUBLIC_AUTH_URL: "https://ignored.example.org" }],
      [{ PUBLIC_BETTER_AUTH_URL: "https://server.example.org/shared" }],
      [{ NEXT_PUBLIC_AUTH_URL: "https://client.example.org/", NEXTAUTH_URL: "https://ignored.example.org" }],
      [{ NEXTAUTH_URL: "https://ssr.example.org/legacy/", VERCEL_URL: "ignored.example.org" }],
      [{ NEXTAUTH_URL: "https://ssr.example.org" }],
      [{ BASE_URL: "/", VERCEL_URL: "deploy.example.org/ignored-path" }],
      [{ VERCEL_URL: "http://deploy.example.org:8080/ignored-path" }],
      [{ NEXT_PUBLIC_AUTH_URL: "https://ignored.example.org" }, "https://explicit.example.org"],
    ]) {
      reset(env);
      let requested;
      const sdk = createAuthClient({
        baseURL: explicit,
        fetchOptions: { customFetchImpl: async (url) => {
          requested = String(url);
          return Response.json(null);
        } },
      });
      await sdk.getSession();
      assert.equal(JSON.parse(execFileSync(binary, ["client", explicit ?? ""], {
        encoding: "utf8", timeout: 10000,
      })), requested);
    }
  });
});
