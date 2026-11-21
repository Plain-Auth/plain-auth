import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { i18n, locales } from "@better-auth/i18n";
import { i18nClient } from "@better-auth/i18n/client";

export async function localization(t, { reference, goFixture, instrument }) {
  const all = JSON.parse(await readFile(new URL("../plugins/i18n/locales.json", import.meta.url), "utf8"));
  assert.equal(Object.keys(all).length, 22);
  assert.deepEqual(all, { ...locales }, "all bundled locale dictionaries must match the pinned package");
  const translations = { ...locales, de: { ...locales.de, INVALID_EMAIL_OR_PASSWORD: "Custom sign-in message" }, xx: { INVALID_EMAIL_OR_PASSWORD: "XX sign-in" } };
  const plugin = i18n({ translations, defaultLocale: "de", localeCookie: "lang", userLocaleField: "name",
    detection: ["cookie", "session", "callback", "header"], getLocale: ctx => ctx.headers?.get("X-Locale") });
  const email = "i18n@example.test";
  const password = "fixture-password-i18n";
  for (const setup of [() => reference(t, [plugin]), () => goFixture(t, [], { CONFORMANCE_I18N: "1" })]) {
    const { client } = instrument(await setup(), [i18nClient()]);
    for (const [headers, expected] of [
      [{}, "Custom sign-in message"],
      [{"accept-language":"unavailable;q=1, es-MX;q=0.8, ja;q=0.2"}, locales.es.INVALID_EMAIL_OR_PASSWORD],
      [{"x-locale":"xx","accept-language":"fr"}, "XX sign-in"],
      [{"cookie":"lang=%6a%61","x-locale":"xx"}, locales.ja.INVALID_EMAIL_OR_PASSWORD],
      [{"cookie":"lang=unknown","x-locale":"unknown","accept-language":"fr-CA"}, locales.fr.INVALID_EMAIL_OR_PASSWORD],
    ]) {
      const { error } = await client.signIn.email({ email, password, fetchOptions:{headers} });
      assert.deepEqual([error.status, error.code, error.message, error.originalMessage],
        [401, "INVALID_EMAIL_OR_PASSWORD", expected, "Invalid email or password"], "browser client must preserve status, code and source message");
    }
    const signup = await client.signUp.email({ email, name:"fr", password });
    assert.equal(signup.error, null);
    assert.equal(signup.data.user.name, "fr");
    const { error } = await client.changePassword({ currentPassword: "wrong-password", newPassword: "new-password-12345", fetchOptions: { headers: { "x-locale": "de" } } });
    assert.deepEqual([error.status, error.code, error.message, error.originalMessage],
      [400, "INVALID_PASSWORD", locales.fr.INVALID_PASSWORD, "Invalid password"], "authenticated profile preference precedes callback detection");
  }
}
