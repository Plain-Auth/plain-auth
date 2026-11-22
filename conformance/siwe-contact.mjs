import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { siweClient } from "better-auth/client/plugins";
import { siwe } from "better-auth/plugins/siwe";
import { verifyMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { domain, signingText } from "./siwe-wallet.mjs";

export async function walletContact(t, { reference, goFixture, instrument }) {
  const go = await goFixture(t, ["siwe"], { CONFORMANCE_WALLET_CONTACT: "1" });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const wallet = () => privateKeyToAccount(generatePrivateKey());
  let hold;
  const plugin = siwe({
    domain, anonymous: false,
    getNonce: async () => randomBytes(20).toString("hex"),
    verifyMessage: ({ address, message, signature }) => verifyMessage({ address, message, signature }),
    ensLookup: async ({ walletAddress }) => {
      if (walletAddress === hold?.wallet) {
        hold.enter();
        await hold.wait;
      }
      return {};
    },
  });
  const ref = await reference(t, [plugin], { database: db });
  const walletClient = runtime => instrument(runtime, [siweClient()]).client;
  async function signed(signer, issuer, chain = 1) {
    const challenge = await walletClient(issuer).siwe.nonce();
    assert.equal(challenge.error, null);
    const message = signingText(signer.address, challenge.data.nonce, chain);
    return { message, signature: await signer.signMessage({ message }) };
  }
  async function success(c, proof, email) {
    const result = await c.siwe.verify({ ...proof, email });
    assert.equal(result.error, null, JSON.stringify(result.error));
    const session = (await c.getSession()).data;
    assert.equal(session.user.id, result.data.user.id);
    assert.equal(session.session.token, result.data.token);
    assert.equal(session.user.emailVerified, false);
    return session.user;
  }
  const credentialOwner = await walletClient(ref).signUp.email({
    name: "Existing mailbox", email: "existing@example.test", password: "strong-local-password",
  });
  assert.equal(credentialOwner.error, null);
  for (const [issuer, verifier, label] of [[go, ref, "ref"], [ref, go, "go"]]) {
    const signer = wallet();
    const email = label + "-contact@example.test";
    const proof = await signed(signer, issuer);
    const c = walletClient(verifier);
    for (const invalid of [{}, { email: null }, { email: "not an email" }]) {
      const bad = await c.siwe.verify({ ...proof, ...invalid });
      assert.equal(bad.error.status, 400);
      assert.equal((await c.getSession()).data, null);
    }
    const owner = await success(c, proof, email.toUpperCase());
    assert.equal(owner.email, email);
    const replay = await walletClient(issuer).siwe.verify({ ...proof, email });
    assert.equal(replay.error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    const returned = await success(walletClient(issuer), await signed(signer, verifier, 137), "elsewhere@example.test");
    assert.deepEqual([returned.id, returned.email], [owner.id, email]);
    for (const [occupied, id] of [[email, owner.id], ["existing@example.test", credentialOwner.data.user.id]]) {
      const other = wallet();
      const own = await success(walletClient(verifier), await signed(other, issuer), occupied);
      assert.notEqual(own.id, id);
      assert.equal(own.email, other.address.toLowerCase() + "@siwe.placeholder.invalid");
    }
  }

  // Hold a real reference reservation during its external display-name callback.
  const holder = wallet(), other = wallet();
  const email = "leased@example.test";
  const reached = Promise.withResolvers(), resume = Promise.withResolvers();
  hold = { wallet: holder.address, enter: reached.resolve, wait: resume.promise };
  const first = success(walletClient(ref), await signed(holder, go), email);
  try {
    await Promise.race([reached.promise, first.then(() => { throw new Error("missing reference reservation"); })]);
    const row = db.prepare('SELECT "id","value" FROM "verification" WHERE "identifier"=?').get("siwe-email-claim-" + email);
    assert.equal(row.value, holder.address);
    const alternative = await success(walletClient(go), await signed(other, ref), email);
    assert.equal(alternative.email, other.address.toLowerCase() + "@siwe.placeholder.invalid");
    assert.equal(db.prepare('SELECT "value" FROM "verification" WHERE id=?').get(row.id).value, holder.address);
  } finally {
    resume.resolve();
  }
  assert.equal((await first).email, email);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM "verification" WHERE "identifier" LIKE ?').get("siwe-email-claim-%").n, 0);
}
