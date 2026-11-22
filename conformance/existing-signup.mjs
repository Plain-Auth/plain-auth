import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

async function readEvents(path) {
  try {
    const text = await readFile(path, "utf8");
    return text.trim().split("\n").map(line => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

export async function existingSignUp(t, {reference, goFixture, instrument}) {
  for (const mode of ["verify", "no-session", "both", "ordinary"]) {
    const captured = [];
    const resets = [];
    let resetToken;
    const options = {
      emailAndPassword: {
        enabled: true,
        sendResetPassword: async ({token}) => { resetToken = token; },
        onPasswordReset: async ({user}, request) => { resets.push({id: user.id, path: new URL(request.url).pathname}); },
        requireEmailVerification: ["verify", "both"].includes(mode),
        autoSignIn: !["no-session", "both"].includes(mode),
        onExistingUserSignUp: async ({user}, request) => {
          captured.push({user, path: new URL(request.url).pathname});
        },
      },
      emailVerification: {sendOnSignUp: false},
      rateLimit: {enabled: false},
    };
    const upstream = await reference(t, [], options);
    const go = await goFixture(t, [], {
      CONFORMANCE_SIGNUP_OBSERVER: mode,
      CONFORMANCE_RESET_HOOK: mode === "no-session" ? "1" : "",
    });
    for (const [target, observations] of [
      [upstream, () => captured],
      [go, () => readEvents(go.databasePath + ".signup-events")],
    ]) {
      const {client, requests} = instrument(target);
      const email = "owner@example.test";
      const ownerInput = {name: "Owner", email, password: "valid-owner-password", image: "https://example.test/owner.png"};
      const owner = await client.signUp.email(ownerInput);
      assert.equal(owner.error, null);
      assert.deepEqual(await observations(), [], "the original account creation has no observer");
      const attempt = {name: "Requester", email: email.toUpperCase(), password: "different-fixture-password"};
      const replay = await client.signUp.email(attempt);
      if (mode === "ordinary") {
        assert.equal(replay.error.status, 422);
        assert.equal(replay.error.code, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
        assert.deepEqual(await observations(), []);
        continue;
      }
      assert.equal(replay.error, null);
      assert.equal(replay.data.token, null);
      assert.equal(replay.data.user.name, attempt.name);
      assert.equal(replay.data.user.email, email);
      assert.equal(replay.data.user.image, null);
      assert.notEqual(replay.data.user.id, owner.data.user.id);
      assert.deepEqual(requests.at(-1).cookies, []);
      const notices = await observations();
      assert.equal(notices.length, 1);
      assert.equal(notices[0].path, "/api/auth/sign-up/email");
      assert.equal(notices[0].user.id, owner.data.user.id);
      assert.equal(notices[0].user.name, ownerInput.name);
      assert.equal(notices[0].user.image, ownerInput.image);
      assert.equal(notices[0].user.email, email);
      assert.equal((await client.getSession()).data, null);

      if (mode === "no-session") {
        assert.equal((await client.requestPasswordReset({email, redirectTo: "/done"})).error, null);
        const token = target === go ? await readFile(go.databasePath + ".reset-link", "utf8") : resetToken;
        assert.equal((await client.resetPassword({token, newPassword: "replacement-fixture-password"})).error, null);
        const resetEvents = target === go ? await readEvents(go.databasePath + ".reset-events") : resets;
        assert.equal(resetEvents.length, 1);
        assert.equal(resetEvents[0].path, "/api/auth/reset-password");
        assert.equal(resetEvents[0].id, owner.data.user.id);
        assert.equal((await observations()).length, 1, "a completed password reset is a separate observer event");
      }
    }
  }
}
