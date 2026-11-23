import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";

export async function compareInvitationLimits(t, { reference, goFixture, instrument }) {
  for (const mode of ["default", "zero", "fixed", "dynamic"]) {
    const dynamic = ({ user, member, organization: group }) =>
      Number(user.name === "Owner" && member.role === "owner" && member.userId === user.id &&
        member.organizationId === group.id && group.slug === "studio");
    const options = { invitationLimit: { default: undefined, zero: 0, fixed: 1, dynamic }[mode], cancelPendingInvitationsOnReInvite: true };
    const ref = await reference(t, [organization(options)]);
    const go = await goFixture(t, ["organization"], { CONFORMANCE_INVITATION_LIMIT: mode, CONFORMANCE_REPLACE_INVITATION: "1" });
    for (const server of [ref, go]) {
      const owner = instrument(server, [organizationClient()]).client;
      const ok = res => { assert.equal(res.error, null, JSON.stringify(res.error)); return res.data; };
      const limited = res => {
        assert.equal(res.error?.status, 403, JSON.stringify(res));
        assert.equal(res.error.code, "INVITATION_LIMIT_REACHED");
      };
      ok(await owner.signUp.email({ email: "owner@example.test", name: "Owner", password: "pending-invitation-capacity" }));
      const studio = ok(await owner.organization.create({ name: "Studio", slug: "studio" }));
      const other = ok(await owner.organization.create({ name: "Annex", slug: "annex" }));
      const issue = (email, org = studio, resend = false) => owner.organization.inviteMember({ organizationId: org.id, email, role: "member", resend });
      if (mode === "zero") {
        limited(await issue("one@example.test"));
        continue;
      }
      const first = ok(await issue("one@example.test"));
      const db = server.database ?? new DatabaseSync(server.databasePath);
      try {
        if (mode === "default") {
          const insert = db.prepare('INSERT INTO invitation (id,organizationId,inviterId,email,role,status,expiresAt,createdAt) SELECT ?,organizationId,inviterId,?,role,status,expiresAt,createdAt FROM invitation WHERE id=?');
          for (let i = 1; i < 100; i++) insert.run("extra-"+i, "extra-"+i+"@example.test", first.id);
        }
        limited(await issue("two@example.test"));
        assert.equal(ok(await issue("one@example.test", studio, true)).id, first.id);
        const fresh = ok(await issue("one@example.test"));
        assert.notEqual(fresh.id, first.id);
        limited(await issue("two@example.test"));
        if (mode === "dynamic") limited(await issue("other@example.test", other));
        else ok(await issue("other@example.test", other));
        db.prepare("UPDATE invitation SET expiresAt=? WHERE id=?").run("2020-01-01T00:00:00Z", fresh.id);
        assert.equal(ok(await issue("two@example.test")).status, "pending");
      } finally {
        if (!server.database) db.close();
      }
    }
  }
}
