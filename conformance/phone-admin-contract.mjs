import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { admin, phoneNumber } from "better-auth/plugins";
import { adminClient, phoneNumberClient } from "better-auth/client/plugins";

export async function comparePhoneAdministration(t, { reference, goFixture, instrument }) {
  const pinned = await reference(t, [admin(), phoneNumber({ sendOTP() {} })]);
  const go = await goFixture(t, ["admin","phone-number"]);
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const ok = (result) => {
    assert.equal(result.error, null, JSON.stringify(result.error));
    return result.data;
  };
  for (const [server, database] of [[pinned,pinned.database],[go,db]]) {
    const actor = instrument(server,[adminClient(),phoneNumberClient()]).client;
    const user = instrument(server,[adminClient(),phoneNumberClient()]).client;
    const password = "local-admin-telephone-account";
    const root = ok(await actor.signUp.email({name:"Admin",email:"admin@phone.test",password})).user;
    database.prepare('UPDATE "user" SET "role"=? WHERE "id"=?').run("admin",root.id);
    ok(await actor.signIn.email({email:root.email,password}));
    const target = ok(await user.signUp.email({name:"Target",email:"target@phone.test",password})).user;
    const patch = (data) => actor.admin.updateUser({userId:target.id,data});
    const view = (u) => [u.phoneNumber, u.phoneNumberVerified];
    const n = "+12025550301", next = "+12025550302";
    assert.equal((await user.admin.updateUser({userId:root.id,data:{phoneNumber:n}})).error.status,403);
    assert.deepEqual(view(ok(await patch({phoneNumber:n}))),[n,null]);
    assert.deepEqual(view(ok(await patch({phoneNumberVerified:null}))),[n,null]);
    assert.deepEqual(view(ok(await patch({phoneNumberVerified:true}))),[n,true]);
    assert.deepEqual(view(ok(await actor.admin.getUser({query:{id:target.id}}))),[n,true]);
    // Go binds the verification flag to the exact number. The released server carries it over.
    assert.deepEqual(view(ok(await patch({phoneNumber:next}))),[next,server===pinned]);
    assert.deepEqual(view(ok(await patch({phoneNumber:n,phoneNumberVerified:false}))),[n,false]);
    assert.deepEqual(view(ok(await patch({phoneNumber:next,phoneNumberVerified:true}))),[next,true]);
    assert.deepEqual(view(ok(await patch({phoneNumber:null,phoneNumberVerified:true}))),[null,false]);
    // The released server accepts a true flag without any number. Go rejects this inconsistent state.
    const inconsistent = await patch({phoneNumberVerified:true});
    if (server===pinned) assert.deepEqual(view(ok(inconsistent)),[null,true]);
    else {
      assert.equal(inconsistent.error.status,400);
      assert.deepEqual(view(ok(await actor.admin.getUser({query:{id:target.id}}))),[null,false]);
    }
    const created = ok(await actor.admin.createUser({name:"Created",email:"created@phone.test",data:{phoneNumber:n}})).user;
    assert.deepEqual(view(created),[null,false]);
    const explicit = ok(await actor.admin.createUser({name:"Imported",email:"imported@phone.test",data:{phoneNumber:n,phoneNumberVerified:true}})).user;
    assert.deepEqual(view(explicit),[n,true]);
  }
}
