import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { organization } from "better-auth/plugins";
import { organizationClient } from "better-auth/client/plugins";
import { stripe } from "@better-auth/stripe";
import { stripeClient } from "@better-auth/stripe/client";
import Stripe from "stripe";

const secret = "whsec_offline_fixture";
const checked = result => { assert.equal(result.error, null, JSON.stringify(result.error)); return result.data; };

async function provider(t) {
  const state = { calls: [], customer: null, checkout: null, subscription: null };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const form = new URLSearchParams(Buffer.concat(chunks).toString());
    const fields = prefix => Object.fromEntries([...form].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k.slice(prefix.length, -1), v]));
    let result;
    state.calls.push([req.method, url.pathname]);
    if (url.pathname === "/v1/customers/search") result = { object: "search_result", has_more: false, data: [] };
    if (url.pathname === "/v1/customers" && req.method === "GET") result = { object: "list", has_more: false, data: [] };
    if (url.pathname === "/v1/customers" && req.method === "POST") {
      result = state.customer = { id: "cus_org", object: "customer", name: form.get("name"), metadata: fields("metadata[") };
    }
    if (url.pathname === "/v1/subscriptions" && req.method === "GET") result = { object: "list", has_more: false, data: [] };
    if (url.pathname === "/v1/prices/price_basic") result = { id: "price_basic", object: "price", active: true, recurring: { interval: "month", interval_count: 1, usage_type: "licensed" } };
    if (url.pathname === "/v1/checkout/sessions" && req.method === "POST") {
      result = state.checkout = { id: "cs_org", object: "checkout.session", mode: form.get("mode"), customer: form.get("customer"),
        url: "https://checkout.example.test/org", client_reference_id: form.get("client_reference_id"), metadata: fields("metadata["),
        subscription: "sub_org", status: "complete", payment_status: "paid", line_items: {object: "list", has_more: false, data: [{id:"li_original", price:{id:form.get("line_items[0][price]")}, quantity:Number(form.get("line_items[0][quantity]"))}]} };
      const start = Math.floor(Date.now() / 1000);
      const price = form.get("line_items[0][price]");
      state.subscription = { id: "sub_org", object: "subscription", customer: result.customer, status: "active",
        metadata: fields("subscription_data[metadata]["), livemode: false, items: { object: "list", has_more: false, data: [{
          id: "si_org", quantity: Number(form.get("line_items[0][quantity]")), current_period_start: start,
          current_period_end: start + 2_592_000, price: { id: price, recurring: { interval: "month", interval_count: 1, usage_type: "licensed" } },
        }] } };
    }
    if (url.pathname === "/v1/checkout/sessions/cs_org" && req.method === "GET") result = state.checkout;
    if (url.pathname === "/v1/subscriptions/sub_org" && req.method === "GET") result = state.subscription;
    if (url.pathname === "/v1/billing_portal/sessions") result = { id: "bps_org", object: "billing_portal.session", customer: form.get("customer"), url: "https://billing.example.test/" + form.get("customer") };
    res.writeHead(result ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(result ?? { error: { type: "invalid_request_error", code: "resource_missing", message: "Unsupported fixture operation" } }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port;
  const api = new Stripe("sk_test_offline_fixture", { host: "127.0.0.1", port, protocol: "http", maxNetworkRetries: 0, telemetry: false });
  return { state, api, url: "http://127.0.0.1:" + port };
}

export async function organizationBilling(t, { reference, goFixture, instrument }) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t);
    const server = runtime === "Go"
      ? await goFixture(t, ["organization", "stripe-organization"], { CONFORMANCE_STRIPE_URL: remote.url })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, plans: [{ name: "basic", priceId: "price_basic" }, { name: "team", priceId: "price_team", annualDiscountPriceId: "price_team_annual" }],
          authorizeReference: async ({ user, referenceId }, ctx) => {
            const member = await ctx.context.adapter.findOne({ model: "member", where: [{ field: "organizationId", value: referenceId }, { field: "userId", value: user.id }] });
            return member?.role === "owner" || member?.role === "admin";
          } },
      })]);
    const browser = () => instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const owner = browser(), peer = browser();
    const account = checked(await owner.signUp.email({ email: "org-buyer@example.test", name: "Owner", password: "test-password-123" }));
    checked(await peer.signUp.email({ email: "outside@example.test", name: "Peer", password: "test-password-123" }));
    const selector = { customerType: "organization" };
    assert.equal((await owner.subscription.list({ query: selector })).error.code, "ORGANIZATION_REFERENCE_ID_REQUIRED");
    const group = checked(await owner.organization.create({ name: "Fixture Group", slug: "fixture-group" }));
    const explicit = { ...selector, referenceId: group.id };
    const denied = await peer.subscription.upgrade({ ...explicit, plan: "basic" });
    assert.equal(denied.error.status, 401);
    assert.equal(denied.error.code, "UNAUTHORIZED");
    assert.equal(remote.state.calls.length, 0);
    const purchase = checked(await owner.subscription.upgrade({ ...selector, plan: "basic", seats: 5, disableRedirect: true }));
    assert.equal(purchase.url, "https://checkout.example.test/org");
    assert.equal(purchase.redirect, false);
    assert.deepEqual(remote.state.customer.metadata, { organizationId: group.id, customerType: "organization" });
    assert.equal(remote.state.customer.name, group.name);
    assert.equal(remote.state.checkout.client_reference_id, group.id);
    assert.equal(remote.state.subscription.items.data[0].quantity, 5);
    assert.equal(remote.state.checkout.customer, "cus_org");
    assert.equal(remote.state.checkout.metadata.referenceId, group.id);
    assert.equal(remote.state.checkout.metadata.userId, account.user.id);
    assert.deepEqual(checked(await owner.subscription.list()), []);
    assert.deepEqual(checked(await owner.subscription.list({ query: explicit })), []);
    async function deliver(id, type, object) {
      const payload = JSON.stringify({ id, type, object: "event", api_version: Stripe.API_VERSION, created: Math.floor(Date.now() / 1000), livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload, secret });
      const resp = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", { method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload }));
      assert.equal(resp.status, 200, await resp.text());
    }
    assert.equal(remote.state.checkout.line_items.data[0].quantity, 5);
    remote.state.subscription.items.data[0].quantity = 8;
    await deliver("evt_checkout_org", "checkout.session.completed", remote.state.checkout);
    const rows = checked(await owner.subscription.list({ query: selector }));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].referenceId, group.id);
    assert.equal(rows[0].seats, 8);
    assert.equal(rows[0].stripeCustomerId, "cus_org");
    assert.equal(rows[0].stripeSubscriptionId, "sub_org");
    assert.equal(rows[0].priceId, "price_basic");
    assert.equal(checked(await owner.subscription.billingPortal({ ...explicit, returnUrl: "/billing", disableRedirect: true })).url, "https://billing.example.test/cus_org");
    assert.equal((await peer.subscription.billingPortal({ ...explicit })).error.code, "UNAUTHORIZED");
    remote.state.subscription.items.data[0].price = { id: "price_team_annual", recurring: { interval: "year", interval_count: 1, usage_type: "licensed" } };
    await deliver("evt_org_renew", "customer.subscription.updated", remote.state.subscription);
    const updated = checked(await owner.subscription.list({ query: explicit }));
    assert.equal(updated[0].plan, "team");
    assert.equal(updated[0].priceId, "price_team_annual");
    assert.deepEqual(checked(await owner.subscription.list()), []);
    assert.deepEqual(checked(await peer.subscription.list()), []);
  });
}
