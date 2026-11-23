import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationExpiration(t, { reference, goFixture, instrument }) {
  for (const seconds of [0, 90, -1]) {
    const options = { invitationExpiresIn: seconds };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, ["organization"], { CONFORMANCE_INVITATION_DURATION: seconds+"s" });
    for (const server of [ref, go]) {
      const owner = instrument(server, [organizationClient()]).client;
      const guest = instrument(server, [organizationClient()]).client;
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const email = "guest@example.test";
      const credentials = { password: "invitation-duration-password" };
      ok(await owner.signUp.email({ name: "Owner", email: "owner@example.test", ...credentials }));
      ok(await guest.signUp.email({ name: "Guest", email, ...credentials }));
      ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const validFor = (seconds || 48*60*60) * 1000;
      async function issue(resend, role) {
        const start = Date.now();
        const row = ok(await owner.organization.inviteMember({ email, role, resend }));
        const time = new Date(row.expiresAt).getTime();
        assert.ok(time >= start + validFor && time <= Date.now() + validFor, "issued deadline outside the host policy");
        return row;
      }
      const original = await issue(false, "member");
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        if (seconds < 0) {
          const result = await guest.organization.acceptInvitation({ invitationId: original.id });
          assert.equal(result.error?.code, "INVITATION_NOT_FOUND");
          assert.notEqual((await issue(true, "member")).id, original.id);
          continue;
        }
        // Change the deadline on disk to distinguish renewal from replaying the old response.
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run(new Date(Date.now()+86400000).toISOString(), original.id);
        const renewed = await issue(true, "admin");
        assert.equal(renewed.id, original.id);
        assert.equal(renewed.role, "member");
        assert.equal(new Date(renewed.createdAt).getTime(), new Date(original.createdAt).getTime());
        const stored = db.prepare("SELECT expiresAt FROM invitation WHERE id=?").get(original.id);
        assert.equal(new Date(stored.expiresAt).getTime(), new Date(renewed.expiresAt).getTime());
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
