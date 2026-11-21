import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { phoneNumber } from "better-auth/plugins";
import { phoneNumberClient } from "better-auth/client/plugins";

export async function comparePhone(t, { reference, goFixture, instrument }) {
  let sms;
  const send = async ({phoneNumber, code}) => { sms = {phoneNumber, code}; };
  const upstream = await reference(t, [phoneNumber({sendOTP: send, sendPasswordResetOTP: send,
    requireVerification: true, signUpOnVerification: {getTempEmail: (number) => number + "@phone.test"}})]);
  const go = await goFixture(t, ["phone-number"]);
  for (const runtime of [upstream, go]) {
    const browser = instrument(runtime, [phoneNumberClient()]).client;
    const other = instrument(runtime, [phoneNumberClient()]).client;
    const delivered = async (number) => {
      const m = runtime === upstream ? sms : JSON.parse(await readFile(join(dirname(go.databasePath), "sms.json"), "utf8"));
      assert.equal(m.phoneNumber ?? m.PhoneNumber, number);
      assert.match(m.code ?? m.Code, /^[0-9]{6}$/);
      return m.code ?? m.Code;
    };
    const number = "+12025550199";
    const password = "the-phone-password-349";
    assert.deepEqual((await browser.phoneNumber.requestPasswordReset({phoneNumber:number})).data, {status:true});
    assert.deepEqual((await browser.phoneNumber.sendOtp({phoneNumber:number})).data, {message:"code sent"});
    const otp = await delivered(number);
    const quiet = await browser.phoneNumber.verify({phoneNumber:number, code:otp, disableSession:true});
    assert.equal(quiet.error,null);
    assert.equal(quiet.data.status,true);
    assert.equal(quiet.data.token,null);
    assert.equal(quiet.data.user.phoneNumber,number);
    assert.equal(quiet.data.user.phoneNumberVerified,true);
    assert.equal(quiet.data.user.email,number+"@phone.test");
    assert.equal((await browser.getSession()).data,null);
    assert.equal((await browser.phoneNumber.verify({phoneNumber:number, code:otp})).error.code,"OTP_NOT_FOUND");
    assert.deepEqual((await browser.phoneNumber.requestPasswordReset({phoneNumber:number})).data,{status:true});
    const reset = await delivered(number);
    assert.equal((await browser.phoneNumber.resetPassword({phoneNumber:number,otp:"wrong",newPassword:password})).error.code,"INVALID_OTP");
    assert.deepEqual((await browser.phoneNumber.resetPassword({phoneNumber:number,otp:reset,newPassword:password})).data,{status:true});
    assert.equal((await browser.signIn.phoneNumber({phoneNumber:number,password:"incorrect"})).error.code,"INVALID_PHONE_NUMBER_OR_PASSWORD");
    const login = await browser.signIn.phoneNumber({phoneNumber:number,password,rememberMe:false});
    assert.equal(login.error,null);
    assert.deepEqual(Object.keys(login.data).sort(),["token","user"]);
    assert.equal(login.data.user.id,quiet.data.user.id);
    assert.equal((await browser.getSession()).data.session.token, login.data.token);
    await other.signUp.email({name:"Other",email:"other@phone.test",password});
    await other.phoneNumber.sendOtp({phoneNumber:number});
    assert.equal((await other.phoneNumber.verify({phoneNumber:number,code:await delivered(number),updatePhoneNumber:true})).error.code,"PHONE_NUMBER_EXIST");
    assert.equal((await browser.updateUser({phoneNumber:"+12025550100"})).error.code,"PHONE_NUMBER_CANNOT_BE_UPDATED");
    assert.equal((await browser.updateUser({phoneNumber:null})).error,null);
    const cleared=(await browser.getSession()).data.user;
    assert.equal(cleared.phoneNumber,null);
    assert.equal(cleared.phoneNumberVerified,false);
    const previous=(await other.getSession()).data.session.token;
    await other.phoneNumber.sendOtp({phoneNumber:number});
    const linked=await other.phoneNumber.verify({phoneNumber:number,code:await delivered(number),updatePhoneNumber:true});
    assert.equal(linked.error,null);
    assert.equal(linked.data.user.phoneNumberVerified,true);
    assert.equal(linked.data.token,previous);
  }
}
