import assert from "node:assert/strict";

// validateUserInfo refuses an email sign-up the same way on both runtimes.
export async function compareSignUpValidation(t, {reference, goFixture, instrument}) {
  const upstream = await reference(t, [], {
    emailAndPassword: {enabled: true},
    rateLimit: {enabled: false},
    user: {validateUserInfo: ({user, source}) => {
      assert.equal(source.action, "create-user");
      assert.equal(source.method, "email-password");
      if (!user.email.endsWith("@company.example")) {
        return {error: "email_not_allowed", errorDescription: "Only company emails are allowed"};
      }
    }},
  });
  const go = await goFixture(t, [], {CONFORMANCE_VALIDATE_USER: "1"});
  const outcomes = [];
  for (const target of [upstream, go]) {
    const {client} = instrument(target);
    const admitted = await client.signUp.email({name: "Ada", email: "ada@company.example", password: "valid-owner-password"});
    assert.equal(admitted.error, null);
    const refused = await client.signUp.email({name: "Eve", email: "eve@else.example", password: "valid-owner-password"});
    outcomes.push({status: refused.error?.status, code: refused.error?.code, message: refused.error?.message});
    assert.equal((await client.signIn.email({email: "eve@else.example", password: "valid-owner-password"})).error?.status, 401);
  }
  assert.deepEqual(outcomes[1], outcomes[0]);
  assert.equal(outcomes[0].status, 403);
}
