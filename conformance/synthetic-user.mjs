import assert from "node:assert/strict";

// customSyntheticUser shapes the user returned for a sign-up with an email
// that already exists, the same way on both runtimes.
export async function compareSyntheticUser(t, {reference, goFixture, instrument}) {
  const upstream = await reference(t, [], {
    emailAndPassword: {
      enabled: true, autoSignIn: false,
      customSyntheticUser: ({coreFields, additionalFields, id}) => ({...coreFields, name: "Shaped", plan: "free", ...additionalFields, id}),
    },
    rateLimit: {enabled: false},
  });
  const go = await goFixture(t, [], {CONFORMANCE_SYNTHETIC_USER: "1"});
  const shaped = [];
  for (const target of [upstream, go]) {
    const {client} = instrument(target);
    const email = "owner@example.test";
    const owner = await client.signUp.email({name: "Owner", email, password: "valid-owner-password"});
    assert.equal(owner.error, null);
    const replay = await client.signUp.email({name: "Requester", email, password: "different-fixture-password"});
    assert.equal(replay.error, null);
    assert.equal(replay.data.token, null);
    assert.notEqual(replay.data.user.id, owner.data.user.id);
    // The shaped user has a real sign-up's keys in the same order.
    assert.deepEqual(Object.keys(replay.data.user), Object.keys(owner.data.user));
    const {id, createdAt, updatedAt, ...rest} = replay.data.user;
    assert.ok(id && createdAt && updatedAt);
    shaped.push({keys: Object.keys(replay.data.user).sort(), rest});
  }
  assert.deepEqual(shaped[1], shaped[0]);
  // The hook sets real fields and cannot add others.
  assert.equal(shaped[0].rest.name, "Shaped");
  assert.equal(shaped[0].rest.plan, undefined);
}
