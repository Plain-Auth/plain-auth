import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { inferAdditionalFields } from "better-auth/client/plugins";

export async function compareDateFields(t, {reference, goFixture, instrument}) {
  const settings = {
    user: {additionalFields:{reviewedAt:{type:"date", required:false, fieldName:"profile_reviewed_at"}}},
    session: {additionalFields:{remindAt:{type:"date", required:false, fieldName:"session_remind_at"}}},
  };
  const go = await goFixture(t, [], {CONFORMANCE_DATE_FIELDS:"1"});
  const db = new DatabaseSync(go.databasePath);
  t.after(() => db.close());
  const ref = await reference(t, [], {...settings, database:db});
  const make = host => instrument(host, [inferAdditionalFields()]).client;
  for (const [issuer, reader, tag] of [[go, ref, "go"], [ref, go, "reference"]]) {
    const input = {name:"Account", email:tag+"@dates.test", password:"local date fixture password"};
    const timestamp = new Date("2026-04-06T01:12:53.123Z");
    let sessionCookie;
    const writer = make({...issuer, async send(request) {
      const response = await issuer.send(request);
      if (new URL(request.url).pathname.endsWith("/sign-up/email")) {
        sessionCookie = response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
      }
      return response;
    }});
    const created = await writer.signUp.email({...input, reviewedAt:timestamp});
    assert.equal(created.error, null);
    assert.equal(new Date(created.data.user.reviewedAt).toISOString(), timestamp.toISOString());
    const updated = await writer.updateSession({remindAt:timestamp});
    assert.equal(updated.error, null);
    assert.equal(new Date(updated.data.session.remindAt).toISOString(), timestamp.toISOString());
    assert.ok(sessionCookie);
    const shared = await reader.send(new Request(reader.baseURL + "/api/auth/get-session", {headers:{cookie:sessionCookie}}));
    assert.equal(shared.status, 200);
    const view = await shared.json();
    assert.equal(view.user.reviewedAt, timestamp.toISOString());
    assert.equal(view.session.remindAt, timestamp.toISOString());
    const login = await make(reader).signIn.email(input);
    assert.equal(login.error, null);
    assert.equal(new Date(login.data.user.reviewedAt).toISOString(), timestamp.toISOString());
    const raw = db.prepare('SELECT profile_reviewed_at FROM "user" WHERE id=?').get(created.data.user.id);
    assert.equal(new Date(raw.profile_reviewed_at).toISOString(), timestamp.toISOString());
    const cleared = await writer.updateSession({remindAt:null});
    assert.equal(cleared.error, null);
    assert.equal(cleared.data.session.remindAt, null);
  }
}
