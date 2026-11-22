import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { hashPassword } from "better-auth/crypto";

function openDatabase(t, target) {
  if (target.database) return target.database;
  const database = new DatabaseSync(target.databasePath);
  t.after(() => database.close());
  return database;
}

function expectError(result, status, code) {
  assert.equal(result.error?.status, status);
  assert.equal(result.error?.code, code);
}

export async function comparePasswordBounds(t, {reference, goFixture, instrument}) {
  for (const configured of [false, true]) {
    const min = configured ? 10 : 8;
    const max = configured ? 14 : 128;
    let resetToken;
    const ref = await reference(t, [], {
      emailAndPassword: {enabled: true, ...(configured && {minPasswordLength:min, maxPasswordLength:max}),
        sendResetPassword: async message => { resetToken = message.token; }},
      logger: {disabled:true}, rateLimit: {enabled:false},
    });
    const go = await goFixture(t, [], {CONFORMANCE_EMAIL_POLICY: configured ? "bounded" : "", CONFORMANCE_RESET_HOOK:"1"});
    for (const target of [ref, go]) {
      const {client} = instrument(target);
      const db = openDatabase(t, target);
      // Each key is two UTF-16 code units. The decomposed accent is also two.
      const shortest = "🔑".repeat(min / 2);
      const longest = "e\u0301".repeat(max / 2);
      const short = shortest.slice(2) + "x";
      const long = longest + "x";
      const first = {name:"Boundary", email:"boundary@example.test"};
      const signup = password => client.signUp.email({...first, password});
      expectError(await signup(short), 400, "PASSWORD_TOO_SHORT");
      expectError(await signup(long), 400, "PASSWORD_TOO_LONG");
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM user").get().n, 0);
      const owner = await signup(shortest);
      assert.equal(owner.error, null);
      const signIn = password => client.signIn.email({email:first.email, password});
      expectError(await signIn(long), 400, "PASSWORD_TOO_LONG");
      expectError(await client.changePassword({currentPassword:long, newPassword:longest}), 400, "PASSWORD_TOO_LONG");
      expectError(await client.changePassword({currentPassword:shortest, newPassword:short}), 400, "PASSWORD_TOO_SHORT");
      expectError(await client.changePassword({currentPassword:shortest, newPassword:long}), 400, "PASSWORD_TOO_LONG");
      assert.equal((await client.changePassword({currentPassword:shortest, newPassword:longest})).error, null);
      assert.equal((await signIn(longest)).error, null);

      // Simulate importing an existing credential below today's minimum.
      const prior = "oldpass";
      const changed = db.prepare("UPDATE account SET password=? WHERE userId=? AND providerId='credential'")
        .run(await hashPassword(prior), owner.data.user.id);
      assert.equal(changed.changes, 1);
      assert.equal((await signIn(prior)).error, null);
      assert.equal((await client.changePassword({currentPassword:prior, newPassword:shortest})).error, null);
      expectError(await signIn(prior), 401, "INVALID_EMAIL_OR_PASSWORD");
      assert.equal((await signIn(shortest)).error, null);

      const reset = (token, newPassword) => client.resetPassword({token, newPassword});
      expectError(await reset("unused-fixture-proof", short), 400, "PASSWORD_TOO_SHORT");
      expectError(await reset("unused-fixture-proof", long), 400, "PASSWORD_TOO_LONG");
      expectError(await reset("unused-fixture-proof", longest), 400, "INVALID_TOKEN");
      assert.equal((await client.requestPasswordReset({email:first.email, redirectTo:"/done"})).error, null);
      const token = target === go ? await readFile(go.databasePath + ".reset-link", "utf8") : resetToken;
      expectError(await reset(token, long), 400, "PASSWORD_TOO_LONG");
      expectError(await reset(token, short), 400, "PASSWORD_TOO_SHORT");
      assert.equal((await reset(token, longest)).error, null);
      expectError(await reset(token, longest), 400, "INVALID_TOKEN");
      assert.equal((await signIn(longest)).error, null);
    }
  }
}

export async function comparePasswordSwitches(t, {reference, goFixture, instrument}) {
  // Seed a credential with the enabled provider to test an operator disabling
  // registration while continuing to serve existing users.
  const address = "existing@example.test", password = "previous credential";
  for (const mode of ["disabled", "invitation"]) {
    const ref = await reference(t, [], {
      emailAndPassword: mode === "invitation" ? {enabled:true, disableSignUp:true} : {},
      logger: {disabled:true}, rateLimit: {enabled:false},
    });
    const go = await goFixture(t, [], {CONFORMANCE_EMAIL_POLICY:mode});
    for (const target of [ref, go]) {
      const db = openDatabase(t, target);
      const enabled = await reference(t, [], {database:db, logger:{disabled:true}});
      assert.equal((await instrument(enabled).client.signUp.email({name:"Existing", email:address, password})).error, null);
      const {client, requests} = instrument(target);
      expectError(await client.signUp.email({name:"New", email:"new@example.test", password}), 400, "EMAIL_PASSWORD_SIGN_UP_DISABLED");
      assert.deepEqual(requests.at(-1).cookies, []);
      assert.equal(db.prepare("SELECT COUNT(*) AS n FROM user").get().n, 1);
      const login = await client.signIn.email({email:address, password});
      if (mode === "invitation") {
        assert.equal(login.error, null);
        assert.equal((await client.getSession()).data.user.email, address);
      } else {
        expectError(login, 400, "EMAIL_PASSWORD_DISABLED");
        assert.deepEqual(requests.at(-1).cookies, []);
        assert.equal((await client.getSession()).data, null);
      }
    }
  }
}
