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

const intervalOf = id => id.endsWith("_annual") ? "year" : "month";

async function provider(t, meteredID) {
  function price(id) {
    return { id, object: "price", active: true, recurring: {
      interval: intervalOf(id), interval_count: 1, usage_type: id === meteredID ? "metered" : "licensed",
    } };
  }
  const state = { calls: [], customer: null, checkout: null, subscription: null, seatUpdates: [] };
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
    if (url.pathname.startsWith("/v1/prices/")) {
      const id = url.pathname.split("/").at(-1);
      result = price(id);
    }
    if (url.pathname === "/v1/checkout/sessions" && req.method === "POST") {
      const lines = [];
      for (let i = 0; form.has(`line_items[${i}][price]`); i++) {
        const line = { id: "li_" + i, price: price(form.get(`line_items[${i}][price]`)) };
        const quantity = form.get(`line_items[${i}][quantity]`);
        if (quantity !== null) line.quantity = Number(quantity);
        lines.push(line);
      }
      result = state.checkout = { id: "cs_org", object: "checkout.session", mode: form.get("mode"), customer: form.get("customer"),
        url: "https://checkout.example.test/org", client_reference_id: form.get("client_reference_id"), metadata: fields("metadata["),
        subscription: "sub_org", status: "complete", payment_status: "paid", line_items: {object: "list", has_more: false, data: lines} };
      const start = Math.floor(Date.now() / 1000);
      state.subscription = { id: "sub_org", object: "subscription", customer: result.customer, status: "active",
        metadata: fields("subscription_data[metadata]["), livemode: false, items: { object: "list", has_more: false, data: lines.map((line, i) => ({
          id: i === 0 ? "si_org" : "si_member", quantity: line.quantity, current_period_start: start,
          current_period_end: start + (intervalOf(line.price.id) === "year" ? 31_536_000 : 2_592_000), price: line.price,
        })) } };
    }
    if (url.pathname === "/v1/checkout/sessions/cs_org" && req.method === "GET") result = state.checkout;
    if (url.pathname === "/v1/subscriptions/sub_org" && req.method === "GET") result = state.subscription;
    if (url.pathname === "/v1/subscriptions/sub_org" && req.method === "POST") {
      const item = form.get("items[0][id]");
      const quantity = Number(form.get("items[0][quantity]"));
      const proration = form.get("proration_behavior");
      const target = state.subscription?.items.data.find(row => row.id === item);
      if (target && Number.isInteger(quantity) && quantity >= 0) {
        state.seatUpdates.push({ item, quantity, proration });
        target.quantity = quantity;
        result = state.subscription;
      }
    }
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

async function organizationBillingPolicy({ user, referenceId }, ctx) {
  const member = await ctx.context.adapter.findOne({ model: "member", where: [
    { field: "organizationId", value: referenceId }, { field: "userId", value: user.id },
  ] });
  return member?.role === "owner" || member?.role === "admin";
}

export async function organizationBilling(t, { reference, goFixture, instrument }, { automatic = false, separate = false, annual = false } = {}) {
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t);
    const basicPlan = { name: "basic", priceId: "price_basic" };
    if (automatic) basicPlan.seatPriceId = separate ? "price_member" : basicPlan.priceId;
    let fixturePricing = separate ? "1" : "";
    if (annual) {
      basicPlan.annualDiscountPriceId = "price_basic_annual";
      basicPlan.seatPriceId = separate ? "price_member_annual" : basicPlan.annualDiscountPriceId;
      // The reference identifies a seat-only plan by its default price.
      if (!separate) basicPlan.priceId = basicPlan.seatPriceId;
      fixturePricing = separate ? "annual" : "annual-seat-only";
    }
    const server = runtime === "Go"
      ? await goFixture(t, ["organization", "stripe-organization"], { CONFORMANCE_STRIPE_URL: remote.url, CONFORMANCE_STRIPE_AUTO_SEATS: automatic ? "1" : "", CONFORMANCE_STRIPE_SEPARATE_PRICE: fixturePricing })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, plans: [basicPlan, { name: "team", priceId: "price_team", annualDiscountPriceId: "price_team_annual" }],
          authorizeReference: organizationBillingPolicy },
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
    if (automatic) {
      await automaticSeats({ browser, owner, peer, group, remote, deliver, separate, annual });
      return;
    }
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

async function automaticSeats({ browser, owner, peer, group, remote, deliver, separate, annual }) {
  const invite = async (client, email) => {
    const invitation = checked(await owner.organization.inviteMember({ organizationId: group.id, email, role: "member" }));
    checked(await client.organization.acceptInvitation({ invitationId: invitation.id }));
  };
  await invite(peer, "outside@example.test");
  const selector = { customerType: "organization", referenceId: group.id };
  const managedCheckout = checked(await owner.subscription.upgrade({ ...selector, plan: "basic", annual, seats: 99, disableRedirect: true }));
  assert.equal(managedCheckout.url, "https://checkout.example.test/org");
  if (annual && !separate) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic_annual", 2]]);
  } else if (annual) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic_annual", 1], ["price_member_annual", 2]]);
  } else if (separate) {
    assert.deepEqual(remote.state.checkout.line_items.data.map(line => [line.price.id, line.quantity]), [["price_basic", 1], ["price_member", 2]]);
  } else {
    assert.equal(remote.state.checkout.line_items.data[0].quantity, 2);
  }
  const seatID = separate ? "si_member" : "si_org";
  assert.equal(remote.state.checkout.customer, "cus_org");
  await deliver("evt_managed_checkout", "checkout.session.completed", remote.state.checkout);
  const member = browser();
  checked(await member.signUp.email({ email: "third@example.test", name: "Third", password: "test-password-123" }));
  async function observe(expected) {
    const deadline = Date.now() + 5_000;
    do {
      const rows = checked(await owner.subscription.list({ query: selector }));
      if (rows.length === 1 && rows[0].priceId === (annual ? "price_basic_annual" : "price_basic") && rows[0].billingInterval === (annual ? "year" : "month") && rows[0].seats === expected && remote.state.subscription.items.data.find(item => item.id === seatID)?.quantity === expected) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    } while (Date.now() < deadline);
    assert.fail("Membership quantity did not reach " + expected);
  }
  await invite(member, "third@example.test");
  await observe(3);
  checked(await owner.organization.removeMember({ organizationId: group.id, memberIdOrEmail: "third@example.test" }));
  await observe(2);
  if (separate) assert.equal(remote.state.subscription.items.data.find(item => item.id === "si_org").quantity, 1);
  assert.deepEqual(remote.state.seatUpdates, [
    { item: seatID, quantity: 3, proration: "create_prorations" },
    { item: seatID, quantity: 2, proration: "create_prorations" },
  ]);
  assert.deepEqual(checked(await owner.subscription.list()), []);
}

export async function meteredCheckout(t, { reference, goFixture, instrument }, isOrganization) {
  const priceID = "price_team_annual";
  for (const runtime of ["reference", "Go"]) await t.test(runtime, async t => {
    const remote = await provider(t, priceID);
    const profile = isOrganization ? ["organization", "stripe-organization"] : ["stripe-subscriptions"];
    const server = runtime === "Go"
      ? await goFixture(t, profile, { CONFORMANCE_STRIPE_URL: remote.url })
      : await reference(t, [organization(), stripe({
        stripeClient: remote.api, stripeWebhookSecret: secret, organization: { enabled: true },
        subscription: { enabled: true, authorizeReference: organizationBillingPolicy,
          plans: [{ name: "team", priceId: "price_team", annualDiscountPriceId: priceID }] },
      })]);
    const browser = () => instrument(server, [organizationClient(), stripeClient({ subscription: true })]).client;
    const owner = browser(), other = browser();
    const signup = (client, name) => client.signUp.email({ name, email: name + "@example.test", password: "meter-fixture-password" });
    const account = checked(await signup(owner, "buyer"));
    checked(await signup(other, "peer"));
    let referenceId = account.user.id;
    let selection = {};
    if (isOrganization) {
      const group = checked(await owner.organization.create({ name: "Metered org", slug: "metered" }));
      referenceId = group.id;
      selection = { referenceId, customerType: "organization" };
      const denied = await other.subscription.upgrade({ ...selection, plan: "team", annual: true });
      assert.equal(denied.error.status, 401);
      assert.equal(remote.state.calls.length, 0);
    }
    const checkout = checked(await owner.subscription.upgrade({ ...selection, plan: "team", annual: true, seats: 9, disableRedirect: true }));
    assert.equal(checkout.redirect, false);
    assert.equal(checkout.url, remote.state.checkout.url);
    assert.equal(remote.state.checkout.client_reference_id, referenceId);
    const [line] = remote.state.checkout.line_items.data;
    assert.equal(line.price.id, priceID);
    assert.equal(Object.hasOwn(line, "quantity"), false);
    const list = () => owner.subscription.list({ query: selection });
    assert.deepEqual(checked(await list()), []);
    // An event may identify the bought price without expanding its recurring details.
    const receipt = structuredClone(remote.state.checkout);
    receipt.line_items.data[0].price = priceID;
    for (const [type, object] of [["checkout.session.completed", receipt], ["customer.subscription.updated", remote.state.subscription]]) {
      const payload = JSON.stringify({ id: "evt_" + type, type, object: "event", api_version: Stripe.API_VERSION,
        created: Math.floor(Date.now() / 1000), livemode: false, data: { object } });
      const signature = remote.api.webhooks.generateTestHeaderString({ payload, secret });
      const reply = await server.send(new Request(server.baseURL + "/api/auth/stripe/webhook", {
        method: "POST", headers: { "content-type": "application/json", "stripe-signature": signature }, body: payload,
      }));
      assert.equal(reply.status, 200, await reply.text());
      const [row] = checked(await list());
      assert.deepEqual([row.referenceId, row.plan, row.priceId, row.billingInterval, row.seats], [referenceId, "team", priceID, "year", 1]);
      assert.deepEqual(checked(await other.subscription.list()), []);
      if (isOrganization) assert.deepEqual(checked(await owner.subscription.list()), []);
    }
  });
}
