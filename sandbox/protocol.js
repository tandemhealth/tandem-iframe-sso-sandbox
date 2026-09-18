/**
 * Validation of the partner's `CustomTokenExchangeResponseAuthCode` message
 * against the `AuthorizeWithoutRedirect` the sandbox sent.
 *
 * Tandem silently ignores messages that fail these checks; the sandbox reports
 * them instead, so partners can see why nothing happened.
 */

import { Checker, newStep } from "./checks.js";

/** @import { Step } from './checks.js' */

export const REQUEST_TYPE = "AuthorizeWithoutRedirect";
export const RESPONSE_TYPE = "CustomTokenExchangeResponseAuthCode";

/**
 * @typedef {object} Attempt
 * @property {number} requestId
 * @property {string} state
 * @property {string} codeVerifier
 * @property {string} codeChallenge
 *
 * @typedef {object} ResponsePayload
 * @property {string} code
 * @property {string} iss
 * @property {string} redirectUri
 */

/**
 * @param {object} args
 * @param {Attempt} args.attempt
 * @param {string} args.origin           `event.origin` as seen by the iframe.
 * @param {unknown} args.message         `event.data`.
 * @param {string[]} args.partnerOrigins
 * @param {string} args.partnerName
 * @returns {{ step: Step, payload: ResponsePayload | null }}
 */
export function validateResponse({ attempt, origin, message, partnerOrigins, partnerName }) {
  const step = newStep("protocol", "postMessage response from your app");
  const checker = new Checker(step);

  checker.check(
    "protocol.origin",
    "The message comes from a registered partner origin",
    partnerOrigins.includes(origin),
    { detail: `event.origin: ${origin}. Tandem ignores messages from any other origin.` },
  );

  const data = isRecord(message) ? message : null;
  checker.check("protocol.object", "event.data is an object (not a JSON string)", data !== null, {
    detail: data === null ? `Got ${describe(message)}. Post the object itself; do not JSON.stringify it.` : undefined,
  });
  if (data === null) return { step, payload: null };

  checker.check("protocol.type", `type is "${RESPONSE_TYPE}"`, data.type === RESPONSE_TYPE, {
    detail: `type: ${describe(data.type)}`,
  });

  checker.check(
    "protocol.request_id",
    `requestId echoes the one from ${REQUEST_TYPE}`,
    data.requestId === attempt.requestId,
    {
      detail:
        `Got ${describe(data.requestId)}, expected ${attempt.requestId} (a number). ` +
        "Tandem sends a new requestId on every load, so persist the one you are answering across the redirect.",
    },
  );

  checker.check("protocol.partner", "partner echoes the value Tandem sent", data.partner === partnerName, {
    detail: `Got ${describe(data.partner)}, expected ${JSON.stringify(partnerName)}.`,
  });

  checker.check("protocol.state", `state echoes the one from ${REQUEST_TYPE}`, data.state === attempt.state, {
    detail: data.state === attempt.state ? undefined : `Got ${describe(data.state)}. Pass the state through unchanged.`,
  });

  const code = nonEmptyString(data.code);
  checker.check("protocol.code", "code is the authorization code from your identity provider", code !== null, {
    detail: code === null ? `Got ${describe(data.code)}.` : undefined,
  });

  const iss = nonEmptyString(data.iss);
  checker.check("protocol.iss", "iss is your identity provider's issuer URL", iss !== null && isHttpUrl(iss), {
    detail:
      iss === null
        ? `Got ${describe(data.iss)}.`
        : `iss: ${iss}. It must equal the "issuer" in your provider's discovery document (checked below).`,
  });

  const redirectUri = nonEmptyString(data.redirectUri);
  checker.check(
    "protocol.redirect_uri",
    "redirectUri is the redirect URI you used in the authorization request",
    redirectUri !== null && isHttpUrl(redirectUri),
    {
      detail:
        redirectUri === null
          ? `Got ${describe(data.redirectUri)}. Tandem must send the same redirect_uri to your token endpoint, or the exchange fails.`
          : `redirectUri: ${redirectUri}`,
    },
  );

  const passed = step.checks.every((c) => c.passed || c.severity !== "fail");
  if (!passed || code === null || iss === null || redirectUri === null) {
    return { step, payload: null };
  }
  return { step, payload: { code, iss, redirectUri } };
}

/** @param {unknown} v @returns {v is Record<string, unknown>} */
function isRecord(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** @param {unknown} v */
function nonEmptyString(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}

/** @param {string} v */
function isHttpUrl(v) {
  try {
    const url = new URL(v);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

/** @param {unknown} v */
export function describe(v) {
  if (v === undefined) return "undefined (missing)";
  if (typeof v === "string") return JSON.stringify(v.length > 80 ? v.slice(0, 77) + "..." : v);
  if (typeof v === "number" || typeof v === "boolean" || v === null) return String(v);
  return `a ${Array.isArray(v) ? "array" : typeof v}`;
}
