import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { emailOTP, phoneNumber } from "better-auth/plugins";
import { emailOTPClient, phoneNumberClient } from "better-auth/client/plugins";

export async function comparePasswordResetHook(t, {reference,goFixture,instrument}) {
  const db = new DatabaseSync(":memory:");
  t.after(() => db.close());
  const referenceEvents = [];
  let link, emailCode, sms;
  const ref = await reference(t, [
    emailOTP({sendVerificationOTP: async message => { emailCode = message.otp; }}),
    phoneNumber({sendOTP: async message => {sms = message.code;}, sendPasswordResetOTP: async message => {sms = message.code;}, requireVerification:true}),
  ], {database: db, logger:{disabled:true}, emailAndPassword:{
    enabled:true, revokeSessionsOnPasswordReset:true,
    sendResetPassword: async message => { link = message.token; },
    onPasswordReset: async ({user},req) => {
      const stored = db.prepare('SELECT emailVerified FROM "user" WHERE id=?').get(user.id);
      const sessions = db.prepare('SELECT COUNT(*) AS n FROM session WHERE userId=?').get(user.id).n;
      const record={id:user.id,email:user.email,verified:user.emailVerified,storedVerified:Boolean(stored.emailVerified),sessions,method:req.method,path:new URL(req.url).pathname};
      if (user.phoneNumber) record.phone=user.phoneNumber;
      referenceEvents.push(record);
      if(req.headers.get("X-Reset-Outcome")==="fail") throw new Error("private fixture notification failure");
    },
  }});
  const go = await goFixture(t, ["phone-number"], {AUTH_TEST_EMAIL_OTP_MAILBOX:"1",CONFORMANCE_RESET_HOOK:"1"});
  const goDB = new DatabaseSync(go.databasePath);
  t.after(() => goDB.close());
  const path = go.databasePath;
  const readJSON = async file => JSON.parse(await readFile(join(dirname(path),file),"utf8"));
  for (const target of [ref,go]) {
    const local = target === go;
    const database = local ? goDB : db;
    const events = async () => local ? (await readFile(path+".reset-events","utf8")).trim().split("\n").map(line=>JSON.parse(line)) : referenceEvents;
    let total = 0;
    for (const [index,route] of ["/reset-password","/email-otp/reset-password","/phone-number/reset-password"].entries()) {
      for (const fail of [false,true]) {
        const email = "recovery-" + index + "-" + fail + "@example.test";
        const number = "+1202555040" + index + (fail ? "1" : "0");
        const password = "original password", replacement = "replacement password";
        const client = instrument(target,[emailOTPClient(),phoneNumberClient()]).client;
        const signup = await client.signUp.email({email,name:"Owner",password});
        assert.equal(signup.error,null);
        const id = signup.data.user.id;
        const fetchOptions = { headers: { "X-Reset-Outcome":fail ? "fail":"ok" } };
        let reset;
        if (route === "/reset-password") {
          assert.equal((await client.requestPasswordReset({email,redirectTo:"/done"})).error,null);
          const token = local ? await readFile(path+".reset-link","utf8") : link;
          reset=()=>client.resetPassword({token,newPassword:replacement,fetchOptions});
        } else if (route === "/email-otp/reset-password") {
          assert.equal((await client.emailOtp.requestPasswordReset({email})).error,null);
          const otp = local ? (await readJSON("email-otp.json")).OTP : emailCode;
          reset=()=>client.emailOtp.resetPassword({email,otp,password:replacement,fetchOptions});
        } else {
          database.prepare('UPDATE "user" SET phoneNumber=?, phoneNumberVerified=1 WHERE id=?').run(number,id);
          assert.equal((await client.phoneNumber.requestPasswordReset({phoneNumber:number})).error,null);
          const otp = local ? (await readJSON("sms.json")).Code : sms;
          reset=()=>client.phoneNumber.resetPassword({phoneNumber:number,otp,newPassword:replacement,fetchOptions});
        }
        const result = await reset();
        if (fail) {
          assert.equal(result.error?.status,500);
          assert.doesNotMatch(JSON.stringify(result.error),/private fixture/);
        } else { assert.equal(result.error,null); }
        const entries=await events();
        assert.equal(entries.length,++total);
        const expected={id,email,verified:false,storedVerified:false,sessions:0,method:"POST",path:"/api/auth"+route};
        if (index===2) expected.phone=number;
        assert.deepEqual(entries.at(-1),expected);
        const stored=database.prepare('SELECT emailVerified FROM "user" WHERE id=?').get(id);
        assert.equal(Boolean(stored.emailVerified),index===1&&!fail);
        assert.ok((await reset()).error, "a consumed proof cannot trigger the observer again");
        assert.equal((await events()).length,total);
        assert.equal((await client.signIn.email({email,password})).error?.code,"INVALID_EMAIL_OR_PASSWORD");
        assert.equal((await client.signIn.email({email,password:replacement})).error,null);
      }
    }
  }
}
