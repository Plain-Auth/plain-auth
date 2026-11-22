import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { emailOTP } from "better-auth/plugins";
import { emailOTPClient } from "better-auth/client/plugins";

export async function compareVerificationObservers(t, {reference, goFixture, instrument}) {
  const refDB = new DatabaseSync(":memory:");
  t.after(() => refDB.close());
  const rows = [];
  let link, code;
  const observer = stage => async (user, request) => {
    const stored = refDB.prepare('SELECT emailVerified FROM "user" WHERE id=?').get(user.id);
    rows.push({stage, id:user.id, email:user.email, name:user.name, verified:user.emailVerified,
      stored:Boolean(stored.emailVerified), method:request.method, path:new URL(request.url).pathname});
    if (request.headers.get("X-Verify-Outcome") === stage) throw new Error("private observer fixture detail");
  };
  const saveMail = async message => { link = message.token; };
  const ref = await reference(t, [emailOTP({sendVerificationOTP:async m => {code = m.otp;},
    changeEmail:{enabled:true,verifyCurrentEmail:true}})], {
    database:refDB, logger:{disabled:true},
    user:{changeEmail:{enabled:true,sendChangeEmailConfirmation:saveMail}},
    emailVerification:{sendOnSignUp:true,autoSignInAfterVerification:true,sendVerificationEmail:saveMail,
      beforeEmailVerification:observer("before"),afterEmailVerification:observer("after")},
  });
  const go = await goFixture(t, [], {AUTH_TEST_EMAIL_OTP_MAILBOX:"1", CONFORMANCE_VERIFY_HOOKS:"1"});
  const goDB = new DatabaseSync(go.databasePath);
  t.after(() => goDB.close());
  for (const target of [ref,go]) {
    const local = target === go;
    const db = local ? goDB : refDB;
    const events = async () => {
      if (!local) return rows;
      try {
        const data = await readFile(go.databasePath+".verification-events","utf8");
        return data.trim().split("\n").map(line=>JSON.parse(line));
      } catch (err) {if (err.code === "ENOENT") return []; throw err;}
    };
    const mailLink = async () => local ? readFile(go.databasePath+".observer-link","utf8") : link;
    const mailCode = async () => local ? JSON.parse(await readFile(join(dirname(go.databasePath),"email-otp.json"),"utf8")).OTP : code;
    const newClient = () => instrument(target,[emailOTPClient()]).client;
    const signup = async (client,email) => {
      const r=await client.signUp.email({email,name:"Mail owner",password:"fixture password"});
      assert.equal(r.error,null);
      return r.data.user;
    };
    const count = id => db.prepare('SELECT COUNT(*) AS n FROM session WHERE userId=?').get(id).n;
    const expectEvents = async (start, owner, steps) => {
      const actual = (await events()).slice(start);
      assert.deepEqual(actual,steps.map(([stage, email, verified, route])=>({
        stage,id:owner.id,email,name:"Mail owner",verified,stored:verified,
        method:route==="verify-email"?"GET":"POST",path:"/api/auth/"+route})));
    };
    for (const method of ["link","otp"]) {
      for (const failure of ["before","after","success"]) {
        const email=method+"-"+failure+"@hooks.example.test", ownerClient=newClient(), browser=newClient();
        const owner=await signup(ownerClient,email);
        const route=method==="link"?"verify-email":"email-otp/verify-email";
        if(method==="otp") assert.equal((await ownerClient.emailOtp.sendVerificationOtp({email,type:"email-verification"})).error,null);
        const proof=await (method==="link"?mailLink():mailCode());
        const use=async phase=>{
          const fetchOptions={headers:{"X-Verify-Outcome":phase}};
          return method==="link"?browser.verifyEmail({query:{token:proof},fetchOptions}):browser.emailOtp.verifyEmail({email,otp:proof,fetchOptions});
        };
        const start=(await events()).length, sessions=count(owner.id);
        const r=await use(failure);
        if(failure==="success") assert.equal(r.error,null);
        else {assert.equal(r.error?.status,500);assert.doesNotMatch(JSON.stringify(r.error),/private observer fixture/);}
        const steps=[["before",email,false,route]];
        if(failure!=="before") steps.push(["after",email,true,route]);
        await expectEvents(start,owner,steps);
        assert.equal(count(owner.id),sessions+(failure==="success"?1:0));
        assert.equal(Boolean(db.prepare('SELECT emailVerified FROM "user" WHERE id=?').get(owner.id).emailVerified),failure!=="before");
        const again=await use("success");
        if(method==="otp") assert.ok(again.error);
        else {
          assert.equal(again.error,null);
          if(failure==="before") steps.push(["before",email,false,route],["after",email,true,route]);
        }
        await expectEvents(start,owner,steps);
      }
    }
    for (const verified of [true,false]) {
      const browser=newClient(), email="change-"+verified+"@hooks.example.test", next="replaced-"+email;
      const owner=await signup(browser,email);
      if(verified) assert.equal((await browser.verifyEmail({query:{token:await mailLink()}})).error,null);
      const start=(await events()).length;
      assert.equal((await browser.changeEmail({newEmail:next})).error,null);
      assert.equal((await browser.verifyEmail({query:{token:await mailLink()}})).error,null);
      if(verified) {
        await expectEvents(start,owner,[]);
        assert.equal((await browser.verifyEmail({query:{token:await mailLink()}})).error,null);
      }
      await expectEvents(start,owner,verified?[["after",next,true,"verify-email"]]:[]);
    }
    const browser=newClient(), email="otp-change@hooks.example.test", next="replaced-"+email;
    const owner=await signup(browser,email);
    const currentProof=async address=>{
      assert.equal((await browser.emailOtp.sendVerificationOtp({email:address,type:"email-verification"})).error,null);
      return mailCode();
    };
    const start=(await events()).length;
    const oldOTP=await currentProof(email);
    assert.equal((await browser.emailOtp.requestEmailChange({newEmail:next,otp:oldOTP})).error,null);
    assert.equal((await browser.emailOtp.changeEmail({newEmail:next,otp:await mailCode()})).error,null);
    await expectEvents(start,owner,[["before",email,false,"email-otp/change-email"],["after",next,true,"email-otp/change-email"]]);
    const verifiedStart=(await events()).length;
    assert.equal((await browser.emailOtp.verifyEmail({email:next,otp:await currentProof(next)})).error,null);
    await expectEvents(verifiedStart,owner,[["before",next,true,"email-otp/verify-email"],["after",next,true,"email-otp/verify-email"]]);

    // Other mailbox proofs may also promote an address. Their own sign-in and
    // recovery contracts never call the explicit verification hooks.
    for (const flow of ["signin", "reset"]) {
      const separate = newClient(), address=flow+"@isolated.example.test";
      await signup(separate,address);
      const previous=(await events()).length;
      if(flow==="signin"){
        assert.equal((await separate.emailOtp.sendVerificationOtp({email:address,type:"sign-in"})).error,null);
        assert.equal((await separate.signIn.emailOtp({email:address,otp:await mailCode()})).error,null);
      }else{
        assert.equal((await separate.emailOtp.requestPasswordReset({email:address})).error,null);
        assert.equal((await separate.emailOtp.resetPassword({email:address,otp:await mailCode(),password:"replacement fixture password"})).error,null);
      }
      assert.equal((await events()).length,previous);
    }
    for (const failure of ["before","after"]) {
      const ownerClient=newClient(), address="otp-change-fail-"+failure+"@hooks.example.test", next="changed-"+address;
      const subject=await signup(ownerClient,address), start=(await events()).length;
      assert.equal((await ownerClient.emailOtp.sendVerificationOtp({email:address,type:"email-verification"})).error,null);
      assert.equal((await ownerClient.emailOtp.requestEmailChange({newEmail:next,otp:await mailCode()})).error,null);
      const otp=await mailCode();
      const args={newEmail:next,otp,fetchOptions:{headers:{"X-Verify-Outcome":failure}}};
      assert.equal((await ownerClient.emailOtp.changeEmail(args)).error?.status,500);
      const expected=[["before",address,false,"email-otp/change-email"]];
      if(failure==="after") expected.push(["after",next,true,"email-otp/change-email"]);
      await expectEvents(start,subject,expected);
      assert.equal(db.prepare('SELECT email FROM "user" WHERE id=?').get(subject.id).email, failure==="after"?next:address);
      assert.ok((await ownerClient.emailOtp.changeEmail(args)).error);
      await expectEvents(start,subject,expected);
    }
    const linkClient=newClient(), failedAddress="link-change-fail@hooks.example.test", changed="changed-"+failedAddress;
    const subject=await signup(linkClient,failedAddress);
    assert.equal((await linkClient.verifyEmail({query:{token:await mailLink()}})).error,null);
    const previous=(await events()).length;
    assert.equal((await linkClient.changeEmail({newEmail:changed})).error,null);
    assert.equal((await linkClient.verifyEmail({query:{token:await mailLink()}})).error,null);
    const token=await mailLink();
    assert.equal((await linkClient.verifyEmail({query:{token},fetchOptions:{headers:{"X-Verify-Outcome":"after"}}})).error?.status,500);
    assert.ok((await linkClient.verifyEmail({query:{token}})).error);
    await expectEvents(previous,subject,[["after",changed,true,"verify-email"]]);
  }
}
