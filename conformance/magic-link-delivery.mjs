import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { magicLink } from "better-auth/plugins";
import { magicLinkClient } from "better-auth/client/plugins";

export async function compareMagicLinkDelivery(t, {reference, goFixture, instrument}) {
  for (const closed of [false, true]) {
    let received;
    const ref = await reference(t, [magicLink({
      disableSignUp:closed, storeToken:"hashed",
      sendMagicLink: async (data, ctx) => {
        received = {Email:data.email, Token:data.token, URL:data.url, Metadata:data.metadata,
          Method:ctx.request.method, Route:new URL(ctx.request.url).pathname, Locale:ctx.request.headers.get("Accept-Language")};
      },
    })], {rateLimit:{enabled:false}});
    const memory = await goFixture(t, [], {CONFORMANCE_MAILBOX:"1", CONFORMANCE_MAGIC_MEMORY:"1", CONFORMANCE_MAGIC_CLOSED:closed ? "1" : ""});
    const sql = await goFixture(t, [], {CONFORMANCE_MAILBOX:"1", CONFORMANCE_MAGIC_CLOSED:closed ? "1" : ""});
    for (const target of [ref, memory, sql]) {
      const {client} = instrument(target, [magicLinkClient()]);
      // Fetch the first navigation without following the application's location.
      const visit = async location => {
        const response = await target.send(new Request(location, {redirect:"manual"}));
        assert.equal(response.status, 302);
        const destination = new URL(response.headers.get("Location"), target.baseURL);
        assert.equal(destination.origin, target.baseURL);
        return destination.pathname + destination.search;
      };
      const metadata = {template:"login", tags:["team","return"], preferences:{compact:true}};
      const email = "links@example.test";
      const requestLink = async (name, withCallbacks = true) => {
        const result = await client.signIn.magicLink({
          email, name, metadata, ...(withCallbacks && {callbackURL:"/back", newUserCallbackURL:"/welcome", errorCallbackURL:"/failed"}),
          fetchOptions:{headers:{"Accept-Language":"fr-CA"}},
        });
        assert.equal(result.error, null);
        assert.deepEqual(result.data, {status:true});
        const m = target === ref ? received : JSON.parse(await readFile(join(dirname(target.databasePath),"mailbox.json"),"utf8"));
        assert.equal(m.Email, email);
        assert.deepEqual(m.Metadata, metadata);
        assert.equal(m.Method, "POST");
        assert.equal(m.Route, "/api/auth/sign-in/magic-link");
        assert.equal(m.Locale, "fr-CA");
        const link = new URL(m.URL);
        assert.equal(link.origin, target.baseURL);
        assert.equal(link.pathname, "/api/auth/magic-link/verify");
        assert.equal(link.searchParams.get("token"), m.Token);
        assert.ok(m.Token.length >= 24);
        assert.equal(link.searchParams.get("callbackURL"), withCallbacks ? "/back" : "/");
        return m;
      };
      const first = await requestLink("First");
      assert.equal(await visit(first.URL), closed ? "/failed?error=new_user_signup_disabled" : "/welcome");
      assert.equal(await visit(first.URL), "/failed?error=INVALID_TOKEN");
      if (closed) {
        assert.equal((await client.signUp.email({email, name:"First", password:"fixture-owned-password"})).error, null);
      }
      const next = await requestLink("Ignored on return");
      assert.notEqual(next.Token, first.Token);
      assert.equal(await visit(next.URL), "/back");
      const fresh = await requestLink("Another", false);
      const verified = await client.magicLink.verify({query:{token:fresh.Token}});
      assert.equal(verified.error, null);
      assert.equal(verified.data.user.email, email);
      assert.equal(verified.data.user.name, "First");
      assert.equal(verified.data.user.emailVerified, true);
      const current = await client.getSession();
      assert.equal(current.data.user.id, verified.data.user.id);
      assert.equal(current.data.session.token, verified.data.token);
      const noErrorTarget = new URL(fresh.URL);
      noErrorTarget.searchParams.set("callbackURL", "/retry?from=mail");
      noErrorTarget.searchParams.delete("errorCallbackURL");
      const afterFailure = new URL(await visit(noErrorTarget), target.baseURL);
      assert.equal(afterFailure.pathname, "/retry");
      assert.equal(afterFailure.searchParams.get("error"), "INVALID_TOKEN");
      assert.equal(afterFailure.searchParams.get("from"), "mail");
    }
  }
}
