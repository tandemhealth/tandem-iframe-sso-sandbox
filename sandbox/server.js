/**
 * The sandbox HTTP server. Plays Tandem: serves the iframe page, hands out
 * authorization attempts, validates the partner's response and performs the
 * token exchange the way Tandem does.
 */

import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ConfigError, loadConfig } from "./config.js";
import { exchange } from "./exchange.js";
import { recordedFetch } from "./http.js";
import { validateResponse } from "./protocol.js";
import { renderError, renderList, renderReport } from "./report.js";
import { Store } from "./store.js";

/** @import { Config } from './config.js' */

const STATIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "static");
const MAX_BODY_BYTES = 64 * 1024;

/**
 * @param {Config} config
 * @param {{ store?: Store, fetchImpl?: typeof fetch }} [deps]
 */
export function createServer(config, deps = {}) {
  const store = deps.store ?? new Store();
  const iframePage = readFileSync(path.join(STATIC_DIR, "index.html"), "utf8");
  const iframeScript = readFileSync(path.join(STATIC_DIR, "tandem.js"), "utf8");
  const frameAncestors = `frame-ancestors ${config.partnerOrigins.join(" ")}`;

  return http.createServer(async (req, res) => {
    try {
      await route(req, res);
    } catch (err) {
      console.error("Unhandled error on %s %s:", req.method, req.url, err);
      if (!res.headersSent) {
        html(res, 500, renderError(500, "The sandbox hit an unexpected error; see the terminal."), "'none'");
      } else {
        res.end();
      }
    }
  });

  /**
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   */
  async function route(req, res) {
    const url = new URL(req.url ?? "/", "http://sandbox");
    const method = req.method ?? "GET";

    // --- the page partners embed --------------------------------------------
    if (method === "GET" && url.pathname === "/") {
      return html(res, 200, iframePage, frameAncestors);
    }
    if (method === "GET" && url.pathname === "/tandem.js") {
      res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
      return res.end(iframeScript);
    }
    if (method === "GET" && url.pathname === "/config") {
      // Public values only: what Tandem itself would put in the message.
      return json(res, 200, {
        partner: config.partnerName,
        clientId: config.idpClientId,
        partnerOrigins: config.partnerOrigins,
      });
    }
    if (method === "GET" && url.pathname === "/health") {
      return json(res, 200, { status: "ok" });
    }

    // --- attempts -----------------------------------------------------------
    if (method === "POST" && url.pathname === "/attempts") {
      const attempt = store.create();
      console.log("Attempt %d created; AuthorizeWithoutRedirect will be sent to the parent.", attempt.requestId);
      return json(res, 201, {
        requestId: attempt.requestId,
        state: attempt.state,
        codeChallenge: attempt.codeChallenge,
        codeChallengeMethod: "S256",
      });
    }

    const responseMatch = url.pathname.match(/^\/attempts\/(\d{1,10})\/response$/);
    if (method === "POST" && responseMatch) {
      const attempt = store.get(Number(responseMatch[1]));
      if (!attempt) return json(res, 404, { error: "Unknown attempt." });
      if (attempt.status === "completed")
        return json(res, 409, { error: "Attempt already answered.", reportUrl: `/attempts/${attempt.requestId}` });
      const body = await readJson(req);
      if (!body || typeof body.origin !== "string" || !("message" in body)) {
        return json(res, 400, { error: "Expected {origin, message}." });
      }

      attempt.origin = body.origin;
      attempt.status = "completed";
      attempt.completedAt = new Date();
      const { step, payload } = validateResponse({
        attempt,
        origin: body.origin,
        message: body.message,
        partnerOrigins: config.partnerOrigins,
        partnerName: config.partnerName,
      });
      attempt.steps.push(step);
      if (payload) {
        const result = await exchange(
          { ...payload, codeVerifier: attempt.codeVerifier, state: attempt.state },
          config,
          { fetchImpl: deps.fetchImpl },
        );
        attempt.steps.push(...result.steps);
        attempt.transcripts = result.transcripts;
        attempt.user = result.user;
        attempt.rejection = result.rejection;
      }
      console.log(
        "Attempt %d completed: %s",
        attempt.requestId,
        attempt.user ? `Tandem would sign in ${attempt.user.user_id}` : `rejected (${attempt.rejection ?? "protocol"})`,
      );
      return json(res, 200, {
        accepted: attempt.user !== null,
        rejection: attempt.rejection,
        reportUrl: `/attempts/${attempt.requestId}`,
      });
    }

    // --- reports ------------------------------------------------------------
    if (method === "GET" && url.pathname === "/attempts") {
      return html(res, 200, renderList(store.list(), config), "'none'");
    }
    const reportMatch = url.pathname.match(/^\/attempts\/(\d{1,10})$/);
    if (method === "GET" && reportMatch) {
      const attempt = store.get(Number(reportMatch[1]));
      if (!attempt)
        return html(
          res,
          404,
          renderError(404, "No such attempt (the sandbox forgets attempts when restarted)."),
          "'none'",
        );
      return html(res, 200, renderReport(attempt, config), "'none'");
    }

    return html(res, 404, renderError(404, "Not found."), "'none'");
  }
}

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {string} body
 * @param {string} frameAncestors  CSP frame-ancestors source list.
 */
function html(res, status, body, frameAncestors) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors ${frameAncestors}`,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function json(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

/**
 * @param {http.IncomingMessage} req
 * @returns {Promise<Record<string, unknown> | null>}
 */
async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`Configuration error: ${err.message}\nCopy .env.example to .env and fill it in.`);
      process.exit(1);
    }
    throw err;
  }
  const server = createServer(config);
  server.on("error", (err) => {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === "EADDRINUSE") {
      console.error(`Port ${config.port} is already in use. Stop the other process or set SANDBOX_PORT in .env.`);
      process.exit(1);
    }
    throw err;
  });
  server.listen(config.port, config.host, () => {
    console.log(`Tandem iframe SSO Sandbox listening on http://${config.host}:${config.port}`);
    console.log(
      `  Embed  http://localhost:${config.port}/  in your app (allowed origins: ${config.partnerOrigins.join(", ")})`,
    );
    console.log(`  Reports at http://localhost:${config.port}/attempts`);
    probeIdp(config);
  });
}

/**
 * Warn at startup if the identity provider cannot be discovered, so a wrong
 * URL or a mock IdP that is not running shows up before the first attempt.
 * @param {Config} config
 */
async function probeIdp(config) {
  const { response, transcript } = await recordedFetch("GET", config.idpWellKnownUrl, {
    allowInsecure: config.allowInsecureIdp,
  });
  if (!response) {
    console.warn(`  Warning: identity provider not reachable at ${config.idpWellKnownUrl}: ${transcript.error}`);
    if (transcript.error?.includes("ECONNREFUSED")) {
      console.warn("  (Using the mock IdP? Start it with: node test/mock-idp.js)");
    }
    return;
  }
  if (response.status !== 200) {
    console.warn(`  Warning: discovery document at ${config.idpWellKnownUrl} returned HTTP ${response.status}`);
    return;
  }
  console.log(`  Identity provider reachable at ${new URL(config.idpWellKnownUrl).host}`);
}
