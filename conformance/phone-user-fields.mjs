import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { phoneNumber } from "better-auth/plugins";
import { inferAdditionalFields, phoneNumberClient } from "better-auth/client/plugins";
import { userFields } from "./user-fields.mjs";

export async function comparePhoneUserFields(t, { reference, goFixture, instrument }, defaults) {
  const go = await goFixture(t, ["phone-number"], {
    CONFORMANCE_USER_FIELDS: defaults ? "phone-defaults" : "phone",
  });
  const database = new DatabaseSync(go.databasePath);
  t.after(() => database.close());
  let delivered;
  const signUpOnVerification = { getTempEmail: n => n + "@phone.test" };
  if (!defaults) signUpOnVerification.getTempName = n => "Phone " + n;
  const ref = await reference(t, [phoneNumber({
    signUpOnVerification, sendOTP: async message => { delivered = message; },
  })], {
    database, rateLimit: { enabled: false }, logger: { disabled: true },
    user: { additionalFields: {
      ...userFields, locale: { ...userFields.locale, ...(defaults && { defaultValue: "en" }) },
      code: { type: "string", required: false, fieldName: "profile_code" },
      disableSession: { type: "boolean", required: false, fieldName: "profile_quiet" },
      updatePhoneNumber: { type: "boolean", required: false, fieldName: "profile_replace" },
    } },
  });

  function visible(user, locale, count, flag) {
    assert.equal(user.locale, locale);
    assert.equal(user.count, count);
    assert.equal(user.flag, flag);
    assert.equal(user.accountClass, "standard");
    for (const key of ["code", "disableSession", "updatePhoneNumber"]) assert.equal(user[key], null);
    for (const key of ["preferred_locale", "privateNote", "internalRisk"]) assert.ok(!Object.hasOwn(user, key));
  }

  for (const [writer, reader, suffix] of [[ref, go, "10"], [go, ref, "20"]]) {
    const make = runtime => instrument(runtime, [phoneNumberClient(), inferAdditionalFields()]).client;
    const sender = make(writer);
    const verifier = make(reader);
    const phone = "+141555501" + suffix;
    const send = async number => {
      assert.equal((await sender.phoneNumber.sendOtp({ phoneNumber: number })).error, null);
      if (writer === ref) {
        assert.equal(delivered.phoneNumber, number);
        return delivered.code;
      }
      const sms = JSON.parse(await readFile(join(dirname(go.databasePath), "sms.json"), "utf8"));
      assert.equal(sms.PhoneNumber, number);
      return sms.Code;
    };
    const verify = (number, code, input) => verifier.phoneNumber.verify({ phoneNumber: number, code, ...input });
    if (!defaults) {
      const code = await send(phone);
      assert.equal((await verify(phone, "incorrect", {})).error.code, "INVALID_OTP");
      assert.equal((await verify(phone, code, {})).error.code, "MISSING_FIELD");
      assert.equal((await verify(phone, code, { locale: "en" })).error.code, "OTP_NOT_FOUND");
      assert.equal(database.prepare('SELECT count(*) AS n FROM "user" WHERE "phoneNumber"=?').get(phone).n, 0);
    }
    const unauthorizedFlag = await send(phone);
    const denied = await verify(phone, unauthorizedFlag, { locale: "allowed", phoneNumberVerified: true });
    assert.equal(denied.error.code, "FIELD_NOT_ALLOWED");
    assert.equal((await verify(phone, unauthorizedFlag, { locale: "allowed" })).error.code, "OTP_NOT_FOUND");
    const input = { phoneNumberVerified: false, disableSession: true, updatePhoneNumber: false, name: "From browser", email: "ignored@phone.test", accountClass: "spoof", internalRisk: 500 };
    if (!defaults) Object.assign(input, { locale: "fr", count: 0, flag: false, privateNote: "retained" });
    const signup = await verify(phone, await send(phone), input);
    assert.equal(signup.error, null);
    assert.equal(signup.data.token, null);
    const user = signup.data.user;
    assert.equal(user.email, phone + "@phone.test");
    assert.equal(user.name, defaults ? phone : "Phone " + phone);
    assert.equal(user.phoneNumberVerified, true);
    const expected = [defaults ? "en" : "fr", defaults ? 4 : 0, defaults ? null : false];
    visible(user, ...expected);
    assert.equal((await verifier.getSession()).data, null);

    const changes = { phoneNumberVerified: true, locale: "changed", count: 77, privateNote: "replaced", accountClass: "role", internalRisk: 150 };
    const returning = await verify(phone, await send(phone), changes);
    assert.equal(returning.error, null);
    assert.equal(returning.data.user.id, user.id);
    visible(returning.data.user, ...expected);
    const replacement = "+141555502" + suffix;
    const linked = await verify(replacement, await send(replacement), { ...changes, updatePhoneNumber: true });
    assert.equal(linked.error, null);
    assert.equal(linked.data.token, returning.data.token);
    assert.equal(linked.data.user.phoneNumber, replacement);
    visible(linked.data.user, ...expected);
    visible((await verifier.getSession()).data.user, ...expected);
    assert.deepEqual({ ...database.prepare('SELECT "privateNote", "internalRisk", profile_code, profile_quiet, profile_replace FROM "user" WHERE id=?').get(user.id) },
      { privateNote: defaults ? null : "retained", internalRisk: 9, profile_code: null, profile_quiet: null, profile_replace: null });
  }
}
