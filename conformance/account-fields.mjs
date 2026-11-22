import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {browser, issuerFixture} from "./social-user-fields.mjs";

export function mapProviderAccount(tokens, user) {
  return {
    providerEmail: user.email.startsWith("invalid-") ? false : user.email,
    grantKind: tokens.idToken ? "native" : "browser", ownerClass: "administrator",
    privateLabel: tokens.raw?.directory_tag ?? "private", userId: "injected", accountId: "injected", providerId: "injected",
    id: "injected", accessToken: "injected", password: "injected", unknown: "ignored",
  };
}

export function accountFieldOptions(preserve) {
  const stringRule = {"~standard": {version: 1, vendor: "fixture", validate: value =>
    typeof value === "string" ? {value} : {issues: [{message: "Invalid account field providerEmail"}]},
  }};
  return {updateAccountOnSignIn: !preserve, additionalFields: {
    providerEmail: {type: "string", fieldName: "provider_mail", required: false, validator: {input: stringRule}},
    grantKind: {type: "string", required: false, transform:{input:value => value == null ? value : value + "-saved"}}, privateLabel: {type: "string", returned: false, required: false},
    ownerClass: {type: "string", input: false, required: true, defaultValue: "member"},
  }};
}

export async function compareBrowserAccountFields(t, {reference, goFixture, instrument}) {
  const issuer = await issuerFixture(t);
  const fetchLocal = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (resource, init) => {
    const url = new URL(resource instanceof Request ? resource.url : resource);
    const endpoint = new Map([
      ["https://github.com/login/oauth/authorize", "/authorize"], ["https://github.com/login/oauth/access_token", "/token"],
    ]).get(url.origin + url.pathname);
    if (endpoint) return fetchLocal(issuer.base + endpoint + url.search, resource instanceof Request ? new Request(resource, init) : init);
    assert.equal(url.hostname, "127.0.0.1");
    return fetchLocal(resource, init);
  });
  const go = await goFixture(t, [], {CONFORMANCE_PROVIDER:"1", CONFORMANCE_SOCIAL_FIELD_ISSUER:issuer.base, CONFORMANCE_ACCOUNT_FIELDS:"1"});
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const github = {clientId: "profile-app", clientSecret:"local-secret", getAccountFields:mapProviderAccount,
    getUserInfo: async ({accessToken}) => {
      const response = await fetchLocal(issuer.base + "/userinfo", {headers:{authorization:"Bearer " + accessToken}});
      assert.equal(response.status, 200);
      const profile = await response.json();
      return {user: profile, data: profile};
    },
  };
  const ref = await reference(t, [], {database:db, socialProviders:{github}, account:accountFieldOptions(false)});
  for (const [target, label] of [[go, "native"], [ref, "reference"]]) {
    const owner = browser(target, instrument, "github");
    const email = label + "@example.test";
    const signup = await owner.client.signUp.email({email, name:"Owner", password:"local-test-password"});
    assert.equal(signup.error, null);
    const read = () => db.prepare("SELECT * FROM account WHERE providerId='github' AND accountId=?").get(label);
    const profile = {id:label, email, name:"Provider", emailVerified:true};
    issuer.profile(profile, {directory_tag:"browser-directory"});
    assert.equal((await owner.login(["email"])).pathname, "/done");
    const linked = read();
    assert.equal(linked.grantKind, "browser-saved");
    assert.equal(linked.provider_mail, email);
    assert.equal(linked.userId, signup.data.user.id);
    assert.equal(linked.ownerClass, "member");
    assert.equal(linked.privateLabel, "browser-directory");

    const visitor = browser(target, instrument, "github");
    issuer.profile({...profile,email:"invalid-"+email});
    const failure = await visitor.login();
    assert.equal(failure.pathname, "/retry");
    assert.equal(failure.searchParams.get("error"), "VALIDATION_ERROR");
    assert.deepEqual(read(), linked);
    assert.equal((await visitor.client.getSession()).data, null);
    issuer.profile({...profile,email:"new-"+email});
    assert.equal((await visitor.login()).pathname, "/done");
    const updated = read();
    assert.equal(updated.provider_mail, "new-"+email);
    assert.equal(updated.id, linked.id);
    assert.equal(updated.userId, linked.userId);

    // Seed an existing, verified password owner for automatic email linking.
    const local = browser(target, instrument, "github");
    const mailbox = "local-" + email, subject = label + "-implicit";
    const created = await local.client.signUp.email({email:mailbox, name:"Verified owner", password:"local-test-password"});
    assert.equal(created.error, null);
    db.prepare('UPDATE user SET emailVerified=1 WHERE id=?').run(created.data.user.id);
    issuer.profile({id:subject, email:mailbox, emailVerified:true, name:"Same mailbox"});
    const implicit = browser(target, instrument, "github");
    assert.equal((await implicit.login()).pathname, "/done");
    assert.equal((await implicit.client.getSession()).data.user.id, created.data.user.id);
    const account = db.prepare("SELECT userId,provider_mail FROM account WHERE providerId='github' AND accountId=?").get(subject);
    assert.equal(account.userId, created.data.user.id);
    assert.equal(account.provider_mail, mailbox);
  }
}
