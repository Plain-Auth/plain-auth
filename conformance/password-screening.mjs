import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { admin, emailOTP, phoneNumber } from "better-auth/plugins";
import { haveIBeenPwned } from "better-auth/plugins/haveibeenpwned";
import { adminClient, emailOTPClient, phoneNumberClient } from "better-auth/client/plugins";

const blocked = "local breached fixture with a synthetic range";
const safe = "local clean fixture with a different synthetic range";
const digest = createHash("sha1").update(blocked).digest("hex").toUpperCase();

function ok(response) {
  assert.equal(response.error, null);
  return response.data;
}

function denied(response) {
  assert.equal(response.error?.status, 400);
  assert.equal(response.error.code, "PASSWORD_COMPROMISED");
}

export async function comparePasswordScreening(t, { reference, goFixture, instrument }) {
  let link, emailCode, smsCode;
  const sms = async message => { smsCode = message.code; };
  const ref = await reference(t, [haveIBeenPwned(), admin(),
    emailOTP({ sendVerificationOTP: async message => { emailCode = message.otp; } }),
    phoneNumber({ sendOTP: sms, sendPasswordResetOTP: sms, requireVerification: true }),
  ], { emailAndPassword: { enabled: true, revokeSessionsOnPasswordReset: true,
    sendResetPassword: async message => { link = message.token; },
  } });
  const go = await goFixture(t, ["admin", "phone-number"], {
    AUTH_TEST_EMAIL_OTP_MAILBOX: "1", CONFORMANCE_RESET_HOOK: "1", CONFORMANCE_SYNTHETIC_BREACH: digest,
  });
  const goDB = new DatabaseSync(go.databasePath);
  t.after(() => goDB.close());
  const mailbox = async file => JSON.parse(await readFile(join(dirname(go.databasePath), file), "utf8"));

  let ranges = 0;
  let blockedRanges = 0;
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    assert.equal(request.method, "GET");
    assert.equal(url.origin, "https://api.pwnedpasswords.com");
    assert.match(url.pathname, /^\/range\/[A-F0-9]{5}$/);
    assert.equal(request.headers.get("add-padding"), "true");
    ranges++;
    const match = url.pathname === "/range/" + digest.slice(0, 5);
    if (match) blockedRanges++;
    const entry = match ? digest.slice(5) + ":3" : "0".repeat(35) + ":0";
    return new Response(entry + "\r\n", { headers: { "content-type": "text/plain" } });
  });

  for (const target of [ref, go]) {
    const database = target === go ? goDB : ref.database;
    const browser = () => instrument(target, [adminClient(), emailOTPClient(), phoneNumberClient()]).client;
    const owner = browser();
    const email = "screened-owner@example.test";
    const name = "Owner";
    denied(await owner.signUp.email({ email, name, password: blocked }));
    assert.equal(database.prepare('SELECT id FROM "user" WHERE email=?').get(email), undefined);
    const user = ok(await owner.signUp.email({ email, name, password: safe })).user;
    denied(await owner.changePassword({ currentPassword: safe, newPassword: blocked }));
    const beforeLogin = ranges;
    assert.equal(ok(await browser().signIn.email({ email, password: safe })).user.id, user.id);
    assert.equal(ranges, beforeLogin);

    async function checkRecovery(reset, previous, replacement) {
      const oldSession = ok(await owner.getSession()).session.id;
      denied(await reset(blocked));
      assert.equal(ok(await owner.getSession()).session.id, oldSession);
      assert.equal(ok(await browser().signIn.email({ email, password: previous })).user.id, user.id);
      ok(await reset(replacement));
      assert.ok((await reset(safe)).error, "a successful recovery must consume the proof");
      assert.equal(ok(await owner.getSession()), null);
      assert.equal(ok(await owner.signIn.email({ email, password: replacement })).user.id, user.id);
    }

    ok(await owner.requestPasswordReset({ email, redirectTo: "/done" }));
    const token = target === go ? await readFile(go.databasePath + ".reset-link", "utf8") : link;
    await checkRecovery(password => owner.resetPassword({ token, newPassword: password }), safe, safe + "-link");

    ok(await owner.emailOtp.requestPasswordReset({ email }));
    const emailProof = target === go ? (await mailbox("email-otp.json")).OTP : emailCode;
    await checkRecovery(password => owner.emailOtp.resetPassword({ email, otp: emailProof, password }), safe + "-link", safe + "-email");

    const number = "+12025550176";
    ok(await owner.phoneNumber.sendOtp({ phoneNumber: number }));
    const phoneCode = async () => target === go ? (await mailbox("sms.json")).Code : smsCode;
    ok(await owner.phoneNumber.verify({ phoneNumber: number, code: await phoneCode(), updatePhoneNumber: true }));
    ok(await owner.phoneNumber.requestPasswordReset({ phoneNumber: number }));
    const phoneProof = await phoneCode();
    await checkRecovery(password => owner.phoneNumber.resetPassword({ phoneNumber: number, otp: phoneProof, newPassword: password }), safe + "-email", safe + "-phone");

    database.prepare('UPDATE "user" SET role=? WHERE id=?').run("admin", user.id);
    const manager = browser();
    ok(await manager.signIn.email({ email, password: safe + "-phone" }));
    const person = { email: "screened-member@example.test", name: "Member" };
    denied(await manager.admin.createUser({ ...person, password: blocked }));
    assert.equal(database.prepare('SELECT id FROM "user" WHERE email=?').get(person.email), undefined);
    const member = ok(await manager.admin.createUser({ ...person, password: safe })).user;
    denied(await manager.admin.setUserPassword({ userId: member.id, newPassword: blocked }));
    assert.equal(ok(await browser().signIn.email({ email: person.email, password: safe })).user.id, member.id);
    ok(await manager.admin.setUserPassword({ userId: member.id, newPassword: safe + "-admin" }));
    assert.ok((await browser().signIn.email({ email: person.email, password: safe })).error);
    assert.equal(ok(await browser().signIn.email({ email: person.email, password: safe + "-admin" })).user.id, member.id);
  }
  assert.equal(blockedRanges, 7, "each of the seven reference writes checks the blocked range once");
}
