import { existsSync } from "node:fs";
import path from "node:path";

/**
 * @typedef {object} Config
 * @property {string[]} partnerOrigins  Origins allowed to embed the sandbox and send messages.
 * @property {string} partnerName       Value of `partner` in the messages.
 * @property {string} idpClientId       Client id of the Tandem app registration in the partner's IdP.
 * @property {string} idpClientSecret   Its client secret; server-side only.
 * @property {string} idpWellKnownUrl   OpenID Connect discovery document URL.
 * @property {boolean} allowInsecureIdp Permit http:// IdP URLs (tests, local mock IdP).
 * @property {string} host
 * @property {number} port
 */

/**
 * Load `.env` from the working directory (if present) and build the config.
 * Values already in the environment take precedence over the file.
 *
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {Config}
 */
export function loadConfig(env = process.env) {
  const envFile = path.resolve(process.cwd(), ".env");
  if (env === process.env && existsSync(envFile)) {
    process.loadEnvFile(envFile);
  }
  return configFromEnv(env);
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @returns {Config}
 */
export function configFromEnv(env) {
  const partnerOrigins = (env.PARTNER_ORIGINS ?? "http://localhost:3000")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  for (const origin of partnerOrigins) {
    if (!isOrigin(origin)) {
      throw new ConfigError(
        `PARTNER_ORIGINS entry ${JSON.stringify(origin)} is not an origin (scheme://host[:port], no path).`,
      );
    }
  }

  const allowInsecureIdp = env.ALLOW_INSECURE_IDP === "true";
  const idpWellKnownUrl = env.IDP_WELL_KNOWN_URL ?? "";
  if (!idpWellKnownUrl) {
    throw new ConfigError("IDP_WELL_KNOWN_URL is required (your IdP's OpenID Connect discovery document).");
  }
  const wellKnown = tryUrl(idpWellKnownUrl);
  if (!wellKnown) {
    throw new ConfigError("IDP_WELL_KNOWN_URL is not a valid URL.");
  }
  if (wellKnown.protocol !== "https:" && !(allowInsecureIdp && wellKnown.protocol === "http:")) {
    throw new ConfigError(
      "IDP_WELL_KNOWN_URL must be https:// (Tandem only talks to https identity providers). " +
        "Set ALLOW_INSECURE_IDP=true for a local http:// mock.",
    );
  }

  const idpClientId = env.IDP_CLIENT_ID ?? "";
  const idpClientSecret = env.IDP_CLIENT_SECRET ?? "";
  if (!idpClientId || !idpClientSecret) {
    throw new ConfigError("IDP_CLIENT_ID and IDP_CLIENT_SECRET are required.");
  }

  const port = Number(env.SANDBOX_PORT ?? 8000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError("SANDBOX_PORT must be a port number.");
  }

  return {
    partnerOrigins,
    partnerName: env.PARTNER_NAME ?? "partner",
    idpClientId,
    idpClientSecret,
    idpWellKnownUrl,
    allowInsecureIdp,
    host: env.SANDBOX_HOST ?? "127.0.0.1",
    port,
  };
}

export class ConfigError extends Error {}

/** @param {string} value */
function tryUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/** @param {string} value */
export function isOrigin(value) {
  const url = tryUrl(value);
  return url !== null && url.origin === value && (url.protocol === "https:" || url.protocol === "http:");
}
