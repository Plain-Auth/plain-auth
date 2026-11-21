// Google Identity Services owns the prompt and the optional sign-in button.
const googleScript = "https://accounts.google.com/gsi/client";
let library;
let started = false;

function loadGoogle(scriptNonce) {
  if (globalThis.google?.accounts?.id) return Promise.resolve(globalThis.google.accounts.id);
  if (!library) {
    library = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = googleScript;
      script.async = true;
      if (scriptNonce) script.nonce = scriptNonce;
      script.onload = () => globalThis.google?.accounts?.id
        ? resolve(globalThis.google.accounts.id)
        : reject(new Error("Google Identity Services was unavailable"));
      script.onerror = () => reject(new Error("Unable to load Google Identity Services"));
      document.head.append(script);
    }).catch((error) => { library = undefined; throw error; });
  }
  return library;
}

function localURL(value) {
  const url = new URL(value, window.location.href);
  if (url.origin !== window.location.origin || url.username || url.password ||
      (url.protocol !== "https:" && url.protocol !== "http:")) {
    throw new Error("One Tap requires a same-origin HTTP URL");
  }
  return url;
}

async function post(url, body, signal, fetchOptions = {}) {
  const headers = new Headers(fetchOptions.headers);
  headers.set("Content-Type", "application/json");
  headers.set("Accept", "application/json");
  const response = await fetch(url, {
    method: "POST", mode: "same-origin", credentials: "same-origin", redirect: "error", signal,
    headers,
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("One Tap request failed (HTTP " + response.status + ")");
  return response.json();
}

const sdkOptions = new Set(["color_scheme", "prompt_parent_id", "itp_support", "login_hint", "hd",
  "use_fedcm_for_button", "button_auto_select"]);

// Start once per document. A host nonce must first be bound server-side.
export async function startOneTap({
  authPath = "/api/auth", callbackURL, clientId, nonce, nonceExpiresAt, getChallenge, autoSelect = false,
  cancelOnTapOutside = true, context = "signin", uxMode = "popup", redirectURI,
  scriptNonce, button, showPrompt = !button, onPromptNotification, additionalOptions = {},
  promptOptions = {}, fetchOptions = {},
} = {}) {
  const mount = localURL(authPath);
  if (mount.search || mount.hash) throw new Error("The auth mount must be a path");
  const redirect = callbackURL ? localURL(callbackURL).href : undefined;
  const receiver = redirectURI ? localURL(redirectURI).href : undefined;
  if (!["popup", "redirect"].includes(uxMode) || (uxMode === "redirect" && (!receiver || !button))) {
    throw new Error("Redirect UX requires a sign-in button and same-origin redirectURI");
  }
  if (!["signin", "signup", "use"].includes(context)) throw new Error("Invalid One Tap context");
  if (nonce !== undefined && (typeof nonce !== "string" || !nonce || !clientId || getChallenge)) {
    throw new Error("A host nonce requires a clientId and a single challenge source");
  }
  const { baseDelay = 1000, maxAttempts = 5 } = promptOptions;
  if (!Number.isSafeInteger(baseDelay) || baseDelay < 0 || baseDelay > 60_000 ||
      !Number.isSafeInteger(maxAttempts) || maxAttempts < 0 || maxAttempts > 10) {
    throw new Error("Invalid One Tap prompt retry settings");
  }
  for (const key of Object.keys(additionalOptions)) {
    if (!sdkOptions.has(key)) throw new Error("Unsupported One Tap SDK option: " + key);
  }
  let element;
  if (button) {
    const target = button.container ?? button.element;
    element = typeof target === "string" ? document.querySelector(target) : target;
    if (!element) throw new Error("One Tap button container not found");
  }
  if (started) throw new Error("One Tap has already started on this page");
  started = true;
  const base = mount.href.replace(/\/$/, "");
  const controller = new AbortController();
  const signal = fetchOptions.signal ? AbortSignal.any([controller.signal, fetchOptions.signal]) : controller.signal;
  let id, resolve, reject, timer, expiryTimer;
  const result = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  let used = false;
  const cancel = () => {
    clearTimeout(timer);
    clearTimeout(expiryTimer);
    controller.abort();
    id?.cancel();
    reject(new DOMException("One Tap canceled", "AbortError"));
  };
  try {
    signal.throwIfAborted();
    const challengeSource = nonce ? { nonce, clientId, expiresAt: nonceExpiresAt } : getChallenge
      ? getChallenge({ signal }) : post(base + "/one-tap/nonce", {}, signal, fetchOptions);
    const [challenge, sdk] = await Promise.all([challengeSource, loadGoogle(scriptNonce)]);
    signal.throwIfAborted();
    if (!challenge?.clientId || !challenge.nonce || (clientId && clientId !== challenge.clientId)) {
      throw new Error("Invalid browser challenge");
    }
    const now = Date.now();
    const deadline = challenge.expiresAt === undefined ? now + 300_000 : Math.min(now + 300_000, Number(challenge.expiresAt));
    if (!Number.isFinite(deadline) || deadline <= now) throw new Error("The One Tap browser challenge has expired");
    id = sdk;
    id.initialize({
      ...additionalOptions, client_id: challenge.clientId, nonce: challenge.nonce, auto_select: autoSelect,
      cancel_on_tap_outside: cancelOnTapOutside, context, ux_mode: uxMode,
      ...(uxMode === "redirect" ? {login_uri: receiver} : {}),
      callback: async (response) => {
        if (used || signal.aborted) return;
        used = true;
        clearTimeout(timer);
        try {
          if (typeof response?.credential !== "string" || !response.credential) throw new Error("Google did not return a credential");
          const body = { idToken: response.credential };
          if (redirect) body.callbackURL = redirect;
          const account = await post(base + "/one-tap/callback", body, signal, fetchOptions);
          if (signal.aborted) return;
          if (redirect) window.location.assign(redirect);
          resolve(account);
        } catch (error) { reject(error); }
      },
    });
    if (button) id.renderButton(element, button.config ?? button.options ?? { type: "icon" });
    const prompt = (attempt) => {
      if (used || signal.aborted) return;
      let handled = false;
      id.prompt((moment) => {
        if (used || signal.aborted || handled) return;
        const dismissed = moment?.isDismissedMoment?.();
        if (!dismissed && !moment?.isSkippedMoment?.() && !moment?.isNotDisplayed?.()) return;
        handled = true;
        const reason = dismissed ? moment.getDismissedReason?.() : undefined;
        if (dismissed && reason !== "cancel_called" && reason !== "credential_returned" && attempt < maxAttempts) {
          timer = setTimeout(() => prompt(attempt + 1), baseDelay * 2 ** attempt);
          return;
        }
        onPromptNotification?.(moment);
        if (!button && reason !== "credential_returned") { used = true; resolve(null); }
      });
    };
    expiryTimer = setTimeout(() => {
      used = true;
      clearTimeout(timer);
      controller.abort();
      id.cancel();
      reject(new DOMException("One Tap challenge expired", "TimeoutError"));
    }, deadline - now);
    expiryTimer.unref?.();
    if (showPrompt) prompt(0);
    fetchOptions.signal?.addEventListener("abort", cancel, { once: true });
    if (fetchOptions.signal?.aborted) cancel();
  } catch (error) {
    clearTimeout(timer); clearTimeout(expiryTimer);
    controller.abort();
    if (!id) started = false;
    throw error;
  }
  const finished = () => {
    clearTimeout(timer); clearTimeout(expiryTimer);
    fetchOptions.signal?.removeEventListener("abort", cancel);
  };
  result.then(finished, finished);
  return { result, cancel };
}

// Sign out the local session and clear optional automatic Google/FedCM selection.
export async function signOutOneTap({ authPath = "/api/auth", promptOptions = {}, fetchOptions = {} } = {}) {
  const mount = localURL(authPath);
  if (mount.search || mount.hash) throw new Error("The auth mount must be a path");
  const response = await post(mount.href.replace(/\/$/, "") + "/sign-out", {}, fetchOptions.signal, fetchOptions);
  // Browser policy can reject these optional operations after the local
  // session has already been revoked.
  const resets = [() => globalThis.google?.accounts?.id?.disableAutoSelect?.()];
  if (promptOptions.fedCM !== false && "IdentityCredential" in window) {
    resets.push(() => globalThis.navigator?.credentials?.preventSilentAccess?.());
  }
  await Promise.allSettled(resets.map((reset) => Promise.resolve().then(reset)));
  return response;
}
