import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { emailOTP, organization, testUtils } from "better-auth/plugins";

test("in-process test fixtures create unsaved defaults and retain the last OTP separately for each instance", async t => {
  async function instance() {
    const database = new DatabaseSync(":memory:");
    t.after(() => database.close());
    const deliveries = [];
    const options = {
      baseURL: "http://localhost:3000",
      secret: "fixture-only-secret-for-test-helpers-0123456789",
      database,
      telemetry: { enabled: false },
      emailAndPassword: { enabled: true },
      plugins: [organization(), testUtils({captureOTP: true}), emailOTP({async sendVerificationOTP(message) { deliveries.push(message); }})],
    };
    await (await getMigrations(options)).runMigrations();
    const auth = betterAuth(options);
    return { database, deliveries, auth, helpers: (await auth.$context).test };
  }
  const {database, deliveries, auth, helpers} = await instance();
  const separate = await instance();
  const user = helpers.createUser();
  assert.ok(user.id);
  assert.equal(user.name, "Test User");
  assert.match(user.email, /^test-[a-z0-9]{8}@example\.com$/);
  assert.equal(user.emailVerified, true);
  assert.equal(+user.createdAt, +user.updatedAt);
  const team = helpers.createOrganization({name:"Cloud   Team"});
  assert.match(team.slug, /^cloud-team-[a-z0-9]{4}$/);
  for (const model of ['user','organization']) assert.equal(database.prepare('SELECT count(*) AS n FROM "'+model+'"').get().n, 0);
  await helpers.saveUser(user);
  for (let i = 0; i < 2; i++) {
    await auth.api.sendVerificationOTP({body:{email:user.email,type:"sign-in"}});
    assert.equal(deliveries.length, i + 1);
    assert.equal(helpers.getOTP(user.email), deliveries.at(-1).otp);
    assert.equal(separate.helpers.getOTP(user.email), undefined);
  }
  const code = helpers.getOTP(user.email);
  const result = await auth.api.signInEmailOTP({body:{email:user.email,otp:code}});
  assert.equal(result.user.id, user.id);
  helpers.clearOTPs();
  assert.equal(helpers.getOTP(user.email), undefined);
});
