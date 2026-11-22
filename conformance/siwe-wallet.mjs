import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { siweClient } from "better-auth/client/plugins";
import { siwe } from "better-auth/plugins/siwe";
import { verifyMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";

const domain = "wallet.example.test";
function signingText(address, nonce, chainId) {
  return createSiweMessage({
    address, domain, chainId, nonce, uri: "https://" + domain, version: "1",
    issuedAt: new Date(), statement: "Sign in to the local test.",
  });
}

export async function walletSignIn(t, { reference, goFixture, instrument }) {
  const go = await goFixture(t, ["siwe"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const plugin = siwe({
    domain,
    getNonce: async () => randomBytes(20).toString("hex"),
    verifyMessage: ({ address, message, signature }) => verifyMessage({ address, message, signature }),
  });
  const ref = await reference(t, [plugin], { database: db });
  const client = runtime => instrument(runtime, [siweClient()]).client;
  const wallet = privateKeyToAccount(generatePrivateKey());
  const other = privateKeyToAccount(generatePrivateKey());
  let id;
  for (const [issuer, verifier, chainId] of [[ref, go, 1], [go, ref, 137], [go, go, 1]]) {
    const borrower = client(issuer);
    const receiver = client(verifier);
    const challenge = chainId === 1 ? await borrower.siwe.nonce() : await borrower.siwe.getNonce();
    assert.equal(challenge.error, null);
    const { nonce } = challenge.data;
    assert.match(nonce, /^[a-zA-Z0-9]{8,250}$/);
    const expiration = db.prepare('SELECT "expiresAt" FROM "verification" WHERE "identifier"=?').get("siwe:" + nonce);
    const ttl = new Date(expiration.expiresAt).getTime() - Date.now();
    assert.ok(ttl >= 14 * 60_000 && ttl <= 15 * 60_000 + 1_000, "challenge lifetime is 15 minutes");
    const message = signingText(wallet.address, nonce, chainId);
    const signature = await wallet.signMessage({ message });
    const signed = await receiver.siwe.verify({ message, signature, email: "unsolicited@example.test" });
    assert.equal(signed.error, null, JSON.stringify(signed.error));
    id ??= signed.data.user.id;
    assert.deepEqual(signed.data.user, { id, walletAddress: wallet.address, chainId });
    assert.equal(signed.data.success, true);
    const session = (await receiver.getSession()).data;
    assert.equal(session.user.id, id);
    assert.equal(session.user.email, wallet.address.toLowerCase() + "@siwe.placeholder.invalid");
    assert.equal(session.user.emailVerified, false);
    assert.equal(session.session.token, signed.data.token);
    const replay = await borrower.siwe.verify({ message, signature });
    assert.equal(replay.error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
  }
  const associations = db.prepare('SELECT "chainId","isPrimary" FROM "walletAddress" ORDER BY "chainId"').all();
  assert.deepEqual(associations.map(r => [r.chainId, r.isPrimary]), [[1, 1], [137, 0]]);
  const accounts = db.prepare('SELECT COUNT(*) AS n FROM "account" WHERE "providerId"=? AND "userId"=?').get("siwe", id);
  assert.equal(accounts.n, 2);
  for (const runtime of [ref, go]) {
    const c = client(runtime);
    const { data: { nonce } } = await c.siwe.getNonce();
    const message = signingText(wallet.address, nonce, 1);
    const invalid = await c.siwe.verify({ message, signature: await other.signMessage({ message }) });
    assert.equal(invalid.error.status, 401);
    const retried = await c.siwe.verify({ message, signature: await wallet.signMessage({ message }) });
    assert.equal(retried.error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    assert.equal((await c.getSession()).data, null);
  }
}

export async function walletCallbacks(t, { reference, goFixture, instrument }) {
  const signer = privateKeyToAccount(generatePrivateKey());
  const contract = privateKeyToAccount(generatePrivateKey()).address;
  const go = await goFixture(t, ["siwe"], {
    CONFORMANCE_WALLET_CONTROLLER: signer.address,
    CONFORMANCE_WALLET_CONTRACT: contract,
  });
  const callbacks = siwe({
    domain,
    getNonce: async () => "Custom" + randomBytes(20).toString("hex"),
    async verifyMessage({ address, chainId, message, signature, cacao }) {
      assert.deepEqual(cacao, {
        h: { t: "caip122" }, p: { domain, aud: domain, nonce: message.match(/^Nonce: ([A-Za-z0-9]+)$/m)[1], iss: domain, version: "1" },
        s: { t: "eip191", s: signature },
      });
      return address === contract && chainId === 1 && verifyMessage({ address: signer.address, message, signature });
    },
    ensLookup: async ({ walletAddress }) => {
      assert.equal(walletAddress, contract);
      return { name: "fixture.eth", avatar: "https://wallet.example.test/avatar.png" };
    },
  });
  const ref = await reference(t, [callbacks]);
  for (const runtime of [ref, go]) {
    const c = instrument(runtime, [siweClient()]).client;
    for (const chainId of [137, 1]) {
      const { data: { nonce } } = await c.siwe.nonce();
      assert.match(nonce, /^Custom/);
      const message = signingText(contract, nonce, chainId);
      const signature = await signer.signMessage({ message });
      const proof = await c.siwe.verify({ message, signature });
      if (chainId !== 1) {
        assert.equal(proof.error.status, 401);
        assert.equal((await c.getSession()).data, null);
      } else {
        assert.equal(proof.error, null, JSON.stringify(proof.error));
        assert.equal(proof.data.user.walletAddress, contract);
        const user = (await c.getSession()).data.user;
        assert.equal(user.name, "fixture.eth");
        assert.equal(user.image, "https://wallet.example.test/avatar.png");
      }
      const replay = await c.siwe.verify({ message, signature });
      assert.equal(replay.error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    }
  }

  const sharedDB = new DatabaseSync(go.databasePath);
  t.after(() => sharedDB.close());
  const sharedReference = await reference(t, [callbacks], { database: sharedDB });
  for (const [issuer, verifier] of [[sharedReference, go], [go, sharedReference]]) {
    const issuerClient = instrument(issuer, [siweClient()]).client;
    const verifierClient = instrument(verifier, [siweClient()]).client;
    const challenge = await issuerClient.siwe.nonce();
    assert.equal(challenge.error, null);
    assert.match(challenge.data.nonce, /^Custom/);
    const message = signingText(contract, challenge.data.nonce, 1);
    const signature = await signer.signMessage({ message });
    const result = await verifierClient.siwe.verify({ message, signature });
    assert.equal(result.error, null, JSON.stringify(result.error));
    assert.equal(result.data.user.walletAddress, contract);
    assert.equal((await verifierClient.getSession()).data.user.name, "fixture.eth");
    const replay = await issuerClient.siwe.verify({ message, signature });
    assert.equal(replay.error.code, "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
  }
}
