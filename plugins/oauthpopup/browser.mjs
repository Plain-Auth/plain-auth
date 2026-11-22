// The application can select a single alternative wire protocol when creating the client.
export const POPUP_MESSAGE_TYPE = "stonewrit:oauth-popup";
export const POPUP_ERRORS = Object.freeze({
  POPUP_SIGN_IN_FAILED: "Popup sign-in failed",
  POPUP_BLOCKED: "Sign-in popup was blocked by the browser",
  POPUP_CLOSED: "Sign-in popup was closed before completing",
  POPUP_TIMEOUT: "Sign-in popup timed out"
});
let active;

function embedded() {
  if (window.top === window.self) return false;
  try {
    void window.top.location.href;
    return false;
  } catch {
    return true;
  }
}
function outcome(code, message = POPUP_ERRORS[code], status) {
  return { data: null, error: { code, message, ...(status ? { status } : {}) } };
}
function centered() {
  const left = window.screenX + (window.outerWidth - 500) / 2;
  const top = window.screenY + (window.outerHeight - 600) / 2;
  return `width=500,height=600,left=${left},top=${top},menubar=no,toolbar=no`;
}

function awaitMessage(popup, origin, nonce, messageType, timeoutMs, signal) {
  return new Promise((resolve) => {
    function finish(result) {
      window.removeEventListener("message", receive);
      signal?.removeEventListener("abort", cancel);
      clearInterval(closed);
      clearTimeout(timer);
      try {
        popup.close();
      } catch {}
      resolve(result);
    }
    function receive(event) {
      const data = event.data;
      if (
        event.origin !== origin ||
        event.source !== popup ||
        data?.type !== messageType ||
        data.nonce !== nonce
      )
        return;
      if (typeof data.error?.code === "string") {
        finish(outcome(data.error.code, data.error.description || data.error.code));
      } else if (typeof data.token === "string" && data.token) {
        finish({ token: data.token });
      }
    }
    const cancel = () => finish(outcome("POPUP_CLOSED"));
    const closed = setInterval(() => {
      if (popup.closed) cancel();
    }, 500);
    const timer = setTimeout(() => finish(outcome("POPUP_TIMEOUT")), timeoutMs);
    window.addEventListener("message", receive);
    signal?.addEventListener("abort", cancel, { once: true });
    if (signal?.aborted) cancel();
  });
}

// Create once for an auth mount. Call signIn.popup synchronously from a user gesture.
export function createPopupClient({
  baseURL = "/api/auth",
  messageType = POPUP_MESSAGE_TYPE,
  onSession,
  fetch: transport = globalThis.fetch
} = {}) {
  if (
    typeof messageType !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(messageType) ||
    messageType.trim() !== messageType
  ) {
    throw new TypeError("Expected a namespace:event popup message type");
  }
  const base = new URL(baseURL, window.location.href);
  if (
    !["http:", "https:"].includes(base.protocol) ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new TypeError("Expected an HTTP(S) auth URL");
  }
  const mount = base.pathname.replace(/\/$/, "") || "/api/auth";
  base.pathname = mount;
  const storageKey = "stonewrit.oauth-popup:" + base.href;
  const getStoredPopupToken = () => {
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  };
  function persist(token) {
    try {
      if (token) window.localStorage.setItem(storageKey, token);
      else window.localStorage.removeItem(storageKey);
    } catch {}
  }
  async function authFetch(path, options = {}) {
    // Limit credentials to this exact origin and mount, including after URL normalization.
    if (
      typeof path !== "string" ||
      !path.startsWith("/") ||
      path.startsWith("//") ||
      /[\\#]/.test(path)
    )
      throw new TypeError("Expected an auth endpoint path");
    const url = new URL(base.href + path);
    if (
      url.origin !== base.origin ||
      !url.pathname.startsWith(mount + "/") ||
      /%2f|%5c/i.test(url.pathname)
    )
      throw new TypeError("Path escapes the configured auth mount");
    const headers = new Headers(options.headers);
    const isEmbedded = embedded();
    const token = isEmbedded && getStoredPopupToken();
    if (token && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + token);
    const response = await transport(url.href, {
      ...options,
      headers,
      credentials: isEmbedded && headers.has("Authorization") ? "omit" : "include",
      redirect: "error"
    });
    if (
      response.ok &&
      [
        "/sign-out",
        "/revoke-session",
        "/revoke-sessions",
        "/revoke-other-sessions",
        "/delete-user"
      ].includes(url.pathname.slice(mount.length))
    )
      persist(null);
    return response;
  }
  async function popup(options = {}) {
    const { provider, providerId, windowFeatures, timeoutMs = 300000, signal } = options;
    if (!provider && !providerId) return outcome("POPUP_SIGN_IN_FAILED", "A provider is required");
    if (signal?.aborted) return outcome("POPUP_CLOSED");
    if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > 2147483647)
      throw new TypeError("Invalid popup timeout");
    if (active) {
      try {
        active.focus();
      } catch {}
      return outcome("POPUP_SIGN_IN_FAILED", "A popup sign-in is already pending");
    }
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)), (x) =>
      x.toString(16).padStart(2, "0")
    ).join("");
    const start = new URL(base.href + "/oauth-popup/start");
    start.searchParams.set("popupOrigin", window.location.origin);
    start.searchParams.set("popupNonce", nonce);
    start.searchParams.set("provider", provider || providerId);
    for (const k of ["callbackURL", "errorCallbackURL", "newUserCallbackURL"])
      if (options[k]) start.searchParams.set(k, options[k]);
    if (options.requestSignUp) start.searchParams.set("requestSignUp", "true");
    if (options.scopes?.length) start.searchParams.set("scopes", options.scopes.join(","));
    if (options.additionalData)
      start.searchParams.set("additionalData", JSON.stringify(options.additionalData));
    let child;
    try {
      child = window.open(start, "_blank", windowFeatures ?? centered());
    } catch {
      /* Browser policy may forbid popups. */
    }
    if (!child) return outcome("POPUP_BLOCKED");
    active = child;
    try {
      const result = await awaitMessage(child, base.origin, nonce, messageType, timeoutMs, signal);
      if (result.error) return result;
      const isEmbedded = embedded();
      persist(isEmbedded ? result.token : null);
      if (isEmbedded && getStoredPopupToken() !== result.token)
        return outcome("POPUP_SIGN_IN_FAILED", "Browser storage is unavailable");
      let response, session;
      try {
        response = await authFetch("/get-session", { signal });
        if (response.ok) session = await response.json();
      } catch {
        /* Treat a failed handoff like an unavailable session. */
      }
      if (!session || signal?.aborted) {
        if (getStoredPopupToken() === result.token) persist(null);
        return outcome("POPUP_SIGN_IN_FAILED", "Unable to confirm the session", response?.status);
      }
      onSession?.(session);
      return { data: { success: true }, error: null };
    } finally {
      active = null;
    }
  }
  return { signIn: { popup }, fetch: authFetch, getStoredPopupToken };
}
