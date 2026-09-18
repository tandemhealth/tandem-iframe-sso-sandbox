/**
 * Reference implementation of the partner (EHR) side of the iframe SSO flow,
 * following Tandem's "iframe Authentication" guide. Run it next to the sandbox
 * to see a complete, working exchange before wiring up your own application.
 *
 * It reads the same `.env` as the sandbox (it needs the IdP discovery URL and
 * client id, never the secret).
 */

import { existsSync, readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * @typedef {object} PartnerConfig
 * @property {string} sandboxUrl        Where the sandbox iframe is served.
 * @property {string} idpWellKnownUrl
 * @property {string} idpClientId       Must equal the clientId Tandem sends.
 * @property {string} host
 * @property {number} port
 */

/** @param {NodeJS.ProcessEnv} env @returns {PartnerConfig} */
export function partnerConfigFromEnv(env) {
  return {
    sandboxUrl: env.SANDBOX_URL ?? `http://localhost:${env.SANDBOX_PORT ?? 8000}`,
    idpWellKnownUrl: env.IDP_WELL_KNOWN_URL ?? "",
    idpClientId: env.IDP_CLIENT_ID ?? "",
    host: env.PARTNER_HOST ?? "127.0.0.1",
    port: Number(env.PARTNER_PORT ?? 3000),
  };
}

/** @param {PartnerConfig} config */
export function createPartnerServer(config) {
  const page = readFileSync(path.join(HERE, "static", "index.html"), "utf8");
  const script = readFileSync(path.join(HERE, "static", "partner.js"), "utf8");
  /** @type {Promise<{ issuer: string, authorizationEndpoint: string }> | null} */
  let discovery = null;

  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://partner");
    if (url.pathname === "/" || url.pathname === "/callback") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(page);
    }
    if (url.pathname === "/partner.js") {
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(script);
    }
    if (url.pathname === "/config") {
      // The partner's own backend knows its IdP; discover the authorize URL once.
      discovery ??= discover(config.idpWellKnownUrl);
      try {
        const { issuer, authorizationEndpoint } = await discovery;
        const origin = `http://${req.headers.host}`;
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(
          JSON.stringify({
            sandboxUrl: config.sandboxUrl,
            sandboxOrigin: new URL(config.sandboxUrl).origin,
            clientId: config.idpClientId,
            issuer,
            authorizationEndpoint,
            redirectUri: `${origin}/callback`,
          }),
        );
      } catch (err) {
        discovery = null;
        res.writeHead(500, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      }
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  });
}

/** @param {string} wellKnownUrl */
async function discover(wellKnownUrl) {
  if (!wellKnownUrl) throw new Error("IDP_WELL_KNOWN_URL is not set.");
  let response;
  try {
    response = await fetch(wellKnownUrl, { signal: AbortSignal.timeout(10_000) });
  } catch (err) {
    throw new Error(`Could not reach the identity provider at ${wellKnownUrl}: ${describeFetchError(err)}`);
  }
  if (!response.ok) throw new Error(`Discovery at ${wellKnownUrl} failed: HTTP ${response.status}`);
  const doc = /** @type {{ issuer?: string, authorization_endpoint?: string }} */ (await response.json());
  if (!doc.issuer || !doc.authorization_endpoint) {
    throw new Error("issuer or authorization_endpoint missing from discovery document.");
  }
  return { issuer: doc.issuer, authorizationEndpoint: doc.authorization_endpoint };
}

/** @param {unknown} err */
export function describeFetchError(err) {
  if (!(err instanceof Error)) return String(err);
  const cause = /** @type {{ code?: string, message?: string } | undefined} */ (err.cause);
  const code = cause?.code ?? cause?.message;
  if (code === "ECONNREFUSED") return "connection refused (is it running?)";
  if (code === "ENOTFOUND") return "host not found (check the URL and your network/VPN)";
  return code ? `${err.message} (${code})` : err.message;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const envFile = path.resolve(process.cwd(), ".env");
  if (existsSync(envFile)) process.loadEnvFile(envFile);
  const config = partnerConfigFromEnv(process.env);
  const server = createPartnerServer(config);
  server.on("error", (err) => {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === "EADDRINUSE") {
      console.error(`Port ${config.port} is already in use. Stop the other process or set PARTNER_PORT in .env.`);
      process.exit(1);
    }
    throw err;
  });
  server.listen(config.port, config.host, () => {
    console.log(`Partner example listening on http://localhost:${config.port} (embedding ${config.sandboxUrl})`);
    console.log(`Make sure PARTNER_ORIGINS in .env includes http://localhost:${config.port}`);
    discover(config.idpWellKnownUrl).then(
      ({ issuer }) => console.log(`Identity provider reachable; issuer ${issuer}`),
      (err) => console.warn(`Warning: ${err instanceof Error ? err.message : err}`),
    );
  });
}
