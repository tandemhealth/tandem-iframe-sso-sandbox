// The partner (EHR) side of Tandem's iframe SSO flow, step by step as in the
// integration guide:
//
//   1. embed Tandem in an iframe
//   2. listen for AuthorizeWithoutRedirect from the Tandem origin
//   3. redirect the user to your OIDC provider's authorize endpoint
//   4. on the callback, read code + state and check state
//   5. post CustomTokenExchangeResponseAuthCode to the iframe
//
// Everything Tandem needs to know across the redirect (requestId, state,
// partner, redirect URI) is kept in localStorage.

(async () => {
  const logEl = document.getElementById("log");
  const log = (msg) => {
    const line = document.createElement("div");
    const t = document.createElement("span");
    t.className = "t";
    t.textContent = new Date().toISOString().slice(11, 19) + " ";
    line.append(t, document.createTextNode(msg));
    logEl.append(line);
  };

  const config = await (await fetch("/config")).json();
  if (config.error) {
    log("Config error: " + config.error);
    return;
  }
  const iframe = document.getElementById("tandem-iframe");
  const tandemOrigin = config.sandboxOrigin; // https://app.tandemhealth.ai in production
  const STORAGE_KEY = "tandem_auth_attempt";

  // Step 4/5: are we returning from the identity provider?
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
  let pendingResponse = null;
  if (code && state) {
    if (!stored) {
      log("Callback received but no stored attempt; ignoring.");
    } else if (state !== stored.state) {
      log(`State mismatch: got ${state}, stored ${stored.state}. Ignoring callback.`);
    } else {
      log(
        `Callback received for requestId ${stored.requestId}; will post the code to Tandem once the iframe is ready.`,
      );
      pendingResponse = {
        type: "CustomTokenExchangeResponseAuthCode",
        requestId: stored.requestId,
        partner: stored.partner,
        state,
        code,
        iss: stored.iss,
        redirectUri: stored.redirectUri,
      };
    }
    localStorage.removeItem(STORAGE_KEY);
    window.history.replaceState({}, "", "/");
  } else if (params.get("error")) {
    log(`Identity provider returned an error: ${params.get("error")} ${params.get("error_description") || ""}`);
    window.history.replaceState({}, "", "/");
  }

  // Step 2: listen for Tandem's authorization request.
  let authInProgress = false;
  window.addEventListener("message", (event) => {
    if (event.origin !== tandemOrigin) return;
    const message = event.data;
    if (!message || message.type !== "AuthorizeWithoutRedirect") return;
    log(`AuthorizeWithoutRedirect received (requestId ${message.requestId}).`);

    if (pendingResponse) {
      // Tandem reloaded after our redirect and sent a new request; we answer
      // the one we actually authorized. Tandem routes by requestId.
      log(`Posting CustomTokenExchangeResponseAuthCode for requestId ${pendingResponse.requestId}.`);
      iframe.contentWindow.postMessage(pendingResponse, tandemOrigin);
      pendingResponse = null;
      return;
    }
    if (authInProgress) return;
    if (message.clientId !== config.clientId) {
      log(`Unexpected clientId ${message.clientId}; expected ${config.clientId}. Ignoring.`);
      return;
    }
    authInProgress = true;

    // Step 3: remember what we need after the redirect, then go to the IdP.
    // `iss` is your provider's issuer exactly as its discovery document states it.
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        requestId: message.requestId,
        state: message.state,
        partner: message.partner,
        redirectUri: config.redirectUri,
        iss: config.issuer,
      }),
    );
    const authorizeUrl = new URL(config.authorizationEndpoint);
    authorizeUrl.search = new URLSearchParams({
      client_id: message.clientId,
      response_type: "code",
      redirect_uri: config.redirectUri,
      state: message.state,
      code_challenge: message.codeChallenge,
      code_challenge_method: message.codeChallengeMethod,
      scope: "openid profile email",
    }).toString();
    log("Redirecting to the identity provider…");
    window.location.assign(authorizeUrl.toString());
  });

  // Step 1: embed Tandem.
  iframe.src = config.sandboxUrl;
  log(`Embedded ${config.sandboxUrl}; waiting for AuthorizeWithoutRedirect.`);
})();
