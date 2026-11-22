import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { siweClient } from "better-auth/client/plugins";
import { siwe } from "better-auth/plugins/siwe";
import { verifyMessage } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { domain, signingText } from "./siwe-wallet.mjs";

export async function walletSchema(t,{ reference, goFixture, instrument }) {
  const go = await goFixture(t, ["siwe"], { CONFORMANCE_WALLET_SCHEMA:"1" });
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const plugin = siwe({
    domain, getNonce: async () => randomBytes(18).toString("hex"),
    verifyMessage: args => verifyMessage(args),
    schema: { walletAddress: { modelName:"wallet_address", fields: {
      userId:"user_id", address:"wallet_address", chainId:"chain_id", isPrimary:"is_primary", createdAt:"created_at",
    } } },
  });
  const ref = await reference(t,[plugin],{ database:db });
  const make = node => instrument(node,[siweClient()]).client;
  for (const [issuer, verifier] of [[go,ref],[ref,go]]) {
    const key = privateKeyToAccount(generatePrivateKey());
    let userId;
    for (const [challenge, receiver, chain] of [[issuer,verifier,1],[verifier,issuer,137]]) {
      const source = make(challenge), target = make(receiver);
      const n = await source.siwe.nonce();
      assert.equal(n.error,null);
      const message = signingText(key.address,n.data.nonce,chain);
      const signature = await key.signMessage({message});
      const login = await target.siwe.verify({message,signature});
      assert.equal(login.error,null,JSON.stringify(login.error));
      userId ??= login.data.user.id;
      assert.deepEqual(login.data.user,{ id:userId, walletAddress:key.address, chainId:chain });
      assert.equal((await target.getSession()).data.user.id,userId);
      assert.equal((await source.siwe.verify({message,signature})).error?.code,"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");
    }
    const rows = db.prepare("SELECT user_id,wallet_address,chain_id,is_primary,created_at FROM wallet_address WHERE user_id=? ORDER BY chain_id").all(userId);
    assert.deepEqual(rows.map(r => [r.user_id,r.wallet_address,r.chain_id,r.is_primary]),[
      [userId,key.address,1,1],[userId,key.address,137,0],
    ]);
    assert.ok(rows.every(r => Number.isFinite(Date.parse(r.created_at))));
  }
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_schema WHERE name='walletAddress'").get().n,0);
}
