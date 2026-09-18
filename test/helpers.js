import { createHash, randomBytes } from "node:crypto";

import { createMockIdp } from "./mock-idp.js";

export const CLIENT_ID = "sandbox-client";
export const CLIENT_SECRET = "sandbox-secret";
export const REDIRECT_URI = "http://localhost:3000/callback";

/**
 * Start a mock IdP and return everything a test needs to talk to it.
 * @param {Partial<import('./mock-idp.js').MockIdpOptions>} [options]
 */
export async function startIdp(options = {}) {
  const idp = createMockIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, ...options });
  const url = await idp.start();
  return {
    idp,
    url,
    wellKnownUrl: `${url}/.well-known/openid-configuration`,
    config: {
      idpClientId: CLIENT_ID,
      idpClientSecret: CLIENT_SECRET,
      idpWellKnownUrl: `${url}/.well-known/openid-configuration`,
      allowInsecureIdp: true,
    },
  };
}

export function pkce() {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge };
}

/**
 * Play the browser: hit the IdP's authorize endpoint and pull the code out of
 * the redirect back to the partner.
 * @param {string} idpUrl
 * @param {{ codeChallenge: string, state: string, redirectUri?: string, clientId?: string }} args
 */
export async function authorize(idpUrl, args) {
  const url = new URL(`${idpUrl}/authorize`);
  url.search = new URLSearchParams({
    client_id: args.clientId ?? CLIENT_ID,
    response_type: "code",
    redirect_uri: args.redirectUri ?? REDIRECT_URI,
    state: args.state,
    code_challenge: args.codeChallenge,
    code_challenge_method: "S256",
    scope: "openid profile email",
  }).toString();
  const response = await fetch(url, { redirect: "manual" });
  const location = new URL(response.headers.get("location") ?? "");
  return {
    code: location.searchParams.get("code"),
    state: location.searchParams.get("state"),
    error: location.searchParams.get("error"),
  };
}

/**
 * @param {import('../sandbox/checks.js').Step[]} steps
 * @param {string} id
 */
export function findCheck(steps, id) {
  for (const step of steps) {
    const check = step.checks.find((c) => c.id === id);
    if (check) return check;
  }
  throw new Error(
    `No check ${id} in ${steps
      .map((s) => s.checks.map((c) => c.id))
      .flat()
      .join(", ")}`,
  );
}
