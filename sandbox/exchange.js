/**
 * What Tandem does with the partner's authorization code.
 *
 * Mirrors Tandem's token exchange step for step (see the table
 * in AGENTS.md). Where Tandem rejects, `rejection` carries the same message
 * Tandem would produce, so partners see what they would see in production.
 */

import { Checker, newStep } from "./checks.js";
import { recordedFetch, redactInline, scrubValues } from "./http.js";

/** @import { Step, Transcript } from './checks.js' */
/** @import { Config } from './config.js' */

/**
 * @typedef {object} ExchangeInput
 * @property {string} code
 * @property {string} iss
 * @property {string} codeVerifier
 * @property {string} state
 * @property {string} redirectUri
 *
 * @typedef {object} LinkedUser
 * @property {string} user_id
 * @property {string} [given_name]
 * @property {string} [family_name]
 * @property {string} [email]
 *
 * @typedef {object} ExchangeResult
 * @property {Step[]} steps
 * @property {Transcript[]} transcripts
 * @property {LinkedUser | null} user      The user Tandem would sign in.
 * @property {string | null} rejection     Tandem's rejection message, if any.
 */

/**
 * @param {ExchangeInput} input
 * @param {Pick<Config, 'idpClientId' | 'idpClientSecret' | 'idpWellKnownUrl' | 'allowInsecureIdp'>} config
 * @param {{ fetchImpl?: typeof fetch }} [deps]
 * @returns {Promise<ExchangeResult>}
 */
export async function exchange(input, config, deps = {}) {
  /** @type {Step[]} */
  const steps = [];
  /** @type {Transcript[]} */
  const transcripts = [];
  // Values we sent that must never come back out through a provider's error
  // body, in transcripts or in messages. The access token joins once we have
  // one; `known` is shared by reference so later fetches scrub it too.
  const known = [config.idpClientSecret, input.code, input.codeVerifier];
  const http = { allowInsecure: config.allowInsecureIdp, fetchImpl: deps.fetchImpl, scrub: known };
  /** @param {string} text */
  const safe = (text) => scrubValues(redactInline(text), known);

  // --- Step 1: required payload -------------------------------------
  const payloadStep = newStep("payload", "Token exchange payload");
  steps.push(payloadStep);
  const payload = new Checker(payloadStep);
  const missing = [
    ["code", input.code],
    ["iss", input.iss],
    ["code_verifier", input.codeVerifier],
    ["state", input.state],
    ["redirect_uri", input.redirectUri],
  ]
    .filter(([, v]) => !v)
    .map(([k]) => k);
  payload.check(
    "payload.required",
    "Tandem has everything it needs: code, iss, code_verifier, state, redirect_uri",
    missing.length === 0,
    { detail: missing.length ? `Missing: ${missing.join(", ")}` : "code_verifier is Tandem's own PKCE verifier." },
  );
  if (missing.length) {
    return {
      steps,
      transcripts,
      user: null,
      rejection: `Invalid subject_token payload: missing ${missing.join(", ")}`,
    };
  }

  // --- Step 2: discovery ---------------------------------------------
  const discoveryStep = newStep("discovery", "OpenID Connect discovery");
  steps.push(discoveryStep);
  const discovery = new Checker(discoveryStep);
  const wk = await recordedFetch("GET", config.idpWellKnownUrl, http);
  transcripts.push(wk.transcript);
  discovery.check("discovery.reachable", "The discovery document is reachable", wk.response !== null, {
    detail: wk.transcript.error,
  });
  const doc = wk.response ? parseObject(wk.response.text) : null;
  if (wk.response) {
    discovery.check("discovery.status", "GET well-known returns 200", wk.response.status === 200, {
      detail: `Got HTTP ${wk.response.status}.`,
    });
    discovery.check("discovery.json", "The discovery document is a JSON object", doc !== null);
  }
  const issuer = doc ? asString(doc.issuer) : null;
  const tokenEndpoint = doc ? asString(doc.token_endpoint) : null;
  const userinfoEndpoint = doc ? asString(doc.userinfo_endpoint) : null;
  if (doc) {
    discovery.check("discovery.issuer", "issuer is present", issuer !== null, {
      detail: issuer ? `issuer: ${issuer}` : undefined,
    });
    discovery.check("discovery.token_endpoint", "token_endpoint is present", tokenEndpoint !== null, {
      detail: tokenEndpoint ? `token_endpoint: ${tokenEndpoint}` : undefined,
    });
    discovery.check(
      "discovery.userinfo_endpoint",
      "userinfo_endpoint is present (Tandem reads the user's identity from it)",
      userinfoEndpoint !== null,
      { detail: userinfoEndpoint ? `userinfo_endpoint: ${userinfoEndpoint}` : undefined },
    );
  }
  if (!wk.response || wk.response.status !== 200 || !doc || !issuer || !tokenEndpoint || !userinfoEndpoint) {
    const why = !wk.response
      ? wk.transcript.error
      : wk.response.status !== 200
        ? `Failed to fetch OIDC config: ${wk.response.status}`
        : !doc
          ? "discovery document is not JSON"
          : !issuer
            ? "issuer not found in OIDC configuration"
            : !tokenEndpoint
              ? "token_endpoint not found in OIDC configuration"
              : "userinfo_endpoint not found in OIDC configuration";
    return {
      steps,
      transcripts,
      user: null,
      rejection: `Failed to discover OIDC endpoints from well-known URL: ${why}`,
    };
  }

  // --- Step 3: issuer must match the message's iss --------------------
  const issuerMatches = discovery.check(
    "discovery.issuer_matches",
    "The discovered issuer equals the iss your app sent",
    issuer === input.iss,
    {
      detail:
        issuer === input.iss
          ? undefined
          : `Discovery says ${JSON.stringify(issuer)}, your message said ${JSON.stringify(input.iss)}. ` +
            "They must be byte-for-byte equal (watch trailing slashes and tenant-specific issuers).",
    },
  );
  if (!issuerMatches) {
    return {
      steps,
      transcripts,
      user: null,
      rejection: `Security warning: issuer from OIDC config (${issuer}) does not match issuer from subject token (${input.iss})`,
    };
  }

  // --- Step 4: code exchange ------------------------------------------
  const tokenStep = newStep("token", "Authorization code exchange at your token endpoint");
  steps.push(tokenStep);
  const token = new Checker(tokenStep);
  token.info(
    "token.method",
    "Tandem authenticates with client_secret_post and sends code_verifier, state and redirect_uri",
    "Your token endpoint must accept the client secret in the form body and require redirect_uri to match the authorization request.",
  );
  const tk = await recordedFetch("POST", tokenEndpoint, {
    ...http,
    form: {
      grant_type: "authorization_code",
      client_id: config.idpClientId,
      client_secret: config.idpClientSecret,
      code: input.code,
      code_verifier: input.codeVerifier,
      state: input.state,
      redirect_uri: input.redirectUri,
    },
  });
  transcripts.push(tk.transcript);
  token.check("token.reachable", "The token endpoint responded", tk.response !== null, { detail: tk.transcript.error });
  if (!tk.response) {
    return { steps, transcripts, user: null, rejection: `Token exchange failed: ${tk.transcript.error}` };
  }
  const tokenBody = parseObject(tk.response.text);
  token.check("token.status", "The token exchange returns 200", tk.response.status === 200, {
    detail:
      `Got HTTP ${tk.response.status}.` +
      (tk.response.status === 200 ? "" : ` ${errorSummary(tokenBody, safe(tk.response.text), known)}`),
  });
  const accessToken = tokenBody ? asString(tokenBody.access_token) : null;
  token.check("token.access_token", "The response contains an access_token", accessToken !== null);
  if (tk.response.status !== 200) {
    return {
      steps,
      transcripts,
      user: null,
      rejection: `Token exchange failed: ${tk.response.status} ${safe(tk.response.text)}`,
    };
  }
  if (!accessToken) {
    return { steps, transcripts, user: null, rejection: "No access token in response" };
  }
  known.push(accessToken);

  // --- Step 5: userinfo -----------------------------------------------
  const userStep = newStep("userinfo", "User identity from your userinfo endpoint");
  steps.push(userStep);
  const user = new Checker(userStep);
  const ui = await recordedFetch("GET", userinfoEndpoint, {
    ...http,
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  transcripts.push(ui.transcript);
  user.check("userinfo.reachable", "The userinfo endpoint responded", ui.response !== null, {
    detail: ui.transcript.error,
  });
  if (!ui.response) {
    return { steps, transcripts, user: null, rejection: `User Info request failed: ${ui.transcript.error}` };
  }
  const profile = parseObject(ui.response.text);
  user.check("userinfo.status", "GET userinfo returns 200", ui.response.status === 200, {
    detail: `Got HTTP ${ui.response.status}.`,
  });
  if (ui.response.status !== 200) {
    return {
      steps,
      transcripts,
      user: null,
      rejection: `User Info request failed: ${ui.response.status} ${safe(ui.response.text)}`,
    };
  }
  const sub = profile ? asString(profile.sub) : null;
  user.check("userinfo.sub", "The profile has a sub (Tandem's stable user id for this person)", sub !== null, {
    detail: sub ? `sub: ${sub}` : undefined,
  });
  if (!sub) {
    return { steps, transcripts, user: null, rejection: "No user_id (sub) in user profile response" };
  }
  const email = asString(profile?.email);
  const givenName = asString(profile?.given_name);
  const familyName = asString(profile?.family_name);
  user.check("userinfo.email", "The profile has an email", email !== null, {
    severity: "warn",
    detail: email
      ? `email: ${email}`
      : "Tandem stores the email on the user; without it clinicians are hard to identify in Tandem's admin tools.",
  });
  user.check("userinfo.name", "The profile has given_name and family_name", givenName !== null && familyName !== null, {
    severity: "warn",
    detail: `given_name: ${givenName ?? "missing"}, family_name: ${familyName ?? "missing"}. Shown as the clinician's name in Tandem.`,
  });

  // --- Step 6: link the user ------------------------------------------
  return {
    steps,
    transcripts,
    user: {
      user_id: sub,
      given_name: givenName ?? undefined,
      family_name: familyName ?? undefined,
      email: email ?? undefined,
    },
    rejection: null,
  };
}

/** @param {string} text @returns {Record<string, unknown> | null} */
function parseObject(text) {
  try {
    const value = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/** @param {unknown} v */
function asString(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** @param {Record<string, unknown> | null} body @param {string} text */
/**
 * @param {Record<string, unknown> | null} body   Parsed response, if JSON
 * @param {string} safeText                       Already-redacted response text
 * @param {string[]} known                        Secret values to scrub from free text
 */
function errorSummary(body, safeText, known) {
  if (body && typeof body.error === "string") {
    const desc = typeof body.error_description === "string" ? `: ${scrubValues(body.error_description, known)}` : "";
    return `Your provider said ${scrubValues(body.error, known)}${desc}`;
  }
  return safeText ? `Response: ${safeText.slice(0, 300)}` : "";
}
