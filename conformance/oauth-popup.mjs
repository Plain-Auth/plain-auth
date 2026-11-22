import assert from "node:assert/strict";
import { createAuthClient } from "better-auth/client";
import { oauthPopupClient } from "better-auth/client/plugins";
import { genericOAuth, oauthPopup, bearer } from "better-auth/plugins";

const app = "http://127.0.0.1:32391"; // The provider request is intercepted in this fixture.
function payload(html) {
  return JSON.parse(html.match(/<script\b[^>]*type="application\/json"[^>]*>(.*?)<\/script>/s)[1]);
}
export async function comparePopup(t, { reference, goFixture }) {
  const provider = genericOAuth({
    config: [
      {
        providerId: "work",
        clientId: "popup-client",
        clientSecret: "secret",
        scopes: ["profile"],
        pkce: true,
        authorizationUrl: app + "/authorize",
        tokenUrl: app + "/token",
        disableImplicitSignUp: true,
        getToken: async () => ({ accessToken: "local-access", tokenType: "Bearer" }),
        getUserInfo: async () => ({
          id: "popup-user",
          email: "popup@example.org",
          name: "Popup",
          emailVerified: true
        }),
        accountSubject: ({ profile }) => profile.id
      }
    ]
  });
  const ref = await reference(t, [provider, oauthPopup(), bearer()], { trustedOrigins: [app] });
  const go = await goFixture(t, [], {
    CONFORMANCE_POPUP_ORIGIN: app,
    CONFORMANCE_POPUP_MESSAGE_TYPE: "better-auth:oauth-popup"
  });
  for (const server of [ref, go]) {
    const jar = new Map();
    const request = async (raw, options = {}) => {
      const h = new Headers(options.headers);
      h.set("cookie", [...jar].map(([k, v]) => k + "=" + v).join("; "));
      const res = await server.send(
        new Request(raw, { ...options, headers: h, redirect: "manual" })
      );
      for (const cookie of res.headers.getSetCookie()) {
        const pair = cookie.split(";")[0],
          at = pair.indexOf("=");
        if (pair.slice(at + 1)) jar.set(pair.slice(0, at), pair.slice(at + 1));
        else jar.delete(pair.slice(0, at));
      }
      return res;
    };
    const popupWindow = new EventTarget();
    popupWindow.location = new URL(app);
    popupWindow.self = popupWindow.top = popupWindow;
    popupWindow.screenX = popupWindow.screenY = 0;
    popupWindow.outerWidth = 1200;
    popupWindow.outerHeight = 800;
    globalThis.window = popupWindow;
    let task, mode, posted;
    popupWindow.open = (start) => {
      const child = {
        closed: false,
        close() {
          this.closed = true;
        },
        focus() {}
      };
      // Navigation is first-party to the auth origin; SSL/network providers are never contacted.
      task = (async () => {
        const started = await request(start);
        let done = started;
        if (started.status === 302) {
          const auth = new URL(started.headers.get("location"));
          assert.equal(auth.searchParams.get("code_challenge_method"), "S256");
          assert.ok(auth.searchParams.get("scope").split(" ").includes("email"));
          const callback = new URL(auth.searchParams.get("redirect_uri"));
          callback.searchParams.set("state", auth.searchParams.get("state"));
          if (mode === "declined") callback.searchParams.set("error", "access_denied");
          else callback.searchParams.set("code", "fixture");
          done = await request(callback);
        }
        assert.equal(done.status, 200);
        assert.equal(done.headers.get("cache-control"), "no-store");
        assert.match(done.headers.get("content-security-policy"), /sha256-/);
        posted = payload(await done.text());
        assert.equal(posted.targetOrigin, app);
        const event = Object.assign(new Event("message"), {
          data: posted,
          source: child,
          origin: server.baseURL
        });
        popupWindow.dispatchEvent(event);
      })();
      return child;
    };
    try {
      const client = createAuthClient({
        baseURL: server.baseURL,
        plugins: [oauthPopupClient()],
        fetchOptions: { customFetchImpl: request }
      });
      const opts = {
        providerId: "work",
        requestSignUp: true,
        scopes: ["email"],
        additionalData: {
          campaign: "local",
          link: { userId: "ignore" },
          serverContext: { ignore: true }
        },
        callbackURL: app + "/return",
        newUserCallbackURL: app + "/welcome",
        errorCallbackURL: app + "/error",
        timeoutMs: 2500
      };
      for (mode of ["created", "returning", "declined", "unknown"]) {
        const promise = client.signIn.popup({
          ...opts,
          ...(mode === "unknown" ? { provider: "absent" } : {})
        });
        await task;
        const result = await promise;
        if (mode === "declined" || mode === "unknown") {
          assert.equal(
            result.error?.code,
            mode === "declined" ? "access_denied" : "provider_not_found"
          );
          assert.equal(posted.token, undefined);
        } else {
          assert.deepEqual(result, { data: { success: true }, error: null });
          assert.equal(posted.redirectTo, app + (mode === "created" ? "/welcome" : "/return"));
          const res = await server.send(
            new Request(server.baseURL + "/api/auth/get-session", {
              headers: { authorization: "Bearer " + posted.token }
            })
          );
          assert.equal((await res.json()).user.email, "popup@example.org");
        }
      }
    } finally {
      delete globalThis.window;
    }
  }
}
