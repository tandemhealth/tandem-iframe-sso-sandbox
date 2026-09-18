/**
 * Minimal OpenID Connect provider: discovery, authorize (auto-approves a fixed
 * test user), token (authorization_code with PKCE S256 and client_secret_post)
 * and userinfo. Used by the tests so the whole flow runs offline, and runnable
 * on its own (`npm run start:mock-idp`) to see a green run before pointing the
 * sandbox at a real identity provider.
 *
 * It accepts exactly what Tandem sends and nothing more lenient, so a
 * sandbox pass against it means Tandem would pass too.
 */

import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import { fileURLToPath } from "node:url";

/**
 * @typedef {object} MockIdpOptions
 * @property {string} clientId
 * @property {string} clientSecret
 * @property {string[]} [redirectUris]         Allowed redirect URIs; any when omitted.
 * @property {boolean} [wrongIssuer]            Advertise an issuer that differs from the real base URL.
 * @property {boolean} [omitUserinfoEndpoint]
 * @property {boolean} [omitSub]
 * @property {boolean} [omitEmail]
 * @property {boolean} [rejectRedirectUriMismatch]  Default true, as real providers do.
 * @property {boolean} [echoCredentialsInErrors]  Echo the submitted secret, code and
 *   access token in error bodies, as a badly configured provider might.
 */

export const TEST_USER = {
  sub: "user-0001",
  email: "dr.test@example-ehr.test",
  given_name: "Testa",
  family_name: "Läkare",
};

/**
 * @param {MockIdpOptions} options
 */
export function createMockIdp(options) {
  /** @type {Map<string, { codeChallenge: string, redirectUri: string, clientId: string, used: boolean }>} */
  const codes = new Map();
  /** @type {Set<string>} */
  const accessTokens = new Set();
  const state = {
    tokenRequests: /** @type {Record<string, string>[]} */ ([]),
    authorizeRequests: /** @type {Record<string, string>[]} */ ([]),
  };
  /** @type {string} */
  let baseUrl = "";

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", baseUrl || "http://idp");
    const issuer = options.wrongIssuer ? "https://someone-else.example" : baseUrl;

    if (url.pathname === "/.well-known/openid-configuration") {
      /** @type {Record<string, unknown>} */
      const doc = {
        issuer,
        authorization_endpoint: `${baseUrl}/authorize`,
        token_endpoint: `${baseUrl}/token`,
        userinfo_endpoint: `${baseUrl}/userinfo`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
        scopes_supported: ["openid", "profile", "email"],
      };
      if (options.omitUserinfoEndpoint) delete doc.userinfo_endpoint;
      return json(res, 200, doc);
    }

    if (url.pathname === "/authorize") {
      const q = Object.fromEntries(url.searchParams);
      state.authorizeRequests.push(q);
      const redirectUri = q.redirect_uri;
      if (!redirectUri) return json(res, 400, { error: "invalid_request", error_description: "redirect_uri required" });
      if (options.redirectUris && !options.redirectUris.includes(redirectUri)) {
        return json(res, 400, { error: "invalid_request", error_description: "redirect_uri not registered" });
      }
      const target = new URL(redirectUri);
      const fail = (/** @type {string} */ error, /** @type {string} */ description) => {
        target.search = new URLSearchParams({
          error,
          error_description: description,
          ...(q.state ? { state: q.state } : {}),
        }).toString();
        res.writeHead(302, { Location: target.toString() });
        res.end();
      };
      if (q.client_id !== options.clientId) return fail("unauthorized_client", "unknown client_id");
      if (q.response_type !== "code") return fail("unsupported_response_type", "only code is supported");
      if (!q.code_challenge || q.code_challenge_method !== "S256") return fail("invalid_request", "PKCE S256 required");
      if (!q.state) return fail("invalid_request", "state required");
      const code = randomBytes(16).toString("base64url");
      codes.set(code, { codeChallenge: q.code_challenge, redirectUri, clientId: q.client_id, used: false });
      target.search = new URLSearchParams({ code, state: q.state }).toString();
      res.writeHead(302, { Location: target.toString() });
      return res.end();
    }

    if (url.pathname === "/token") {
      if (req.method !== "POST") return json(res, 405, { error: "invalid_request" });
      const form = Object.fromEntries(new URLSearchParams(await readBody(req)));
      state.tokenRequests.push(form);
      if (form.grant_type !== "authorization_code") return json(res, 400, { error: "unsupported_grant_type" });
      if (form.client_id !== options.clientId || form.client_secret !== options.clientSecret) {
        /** @type {Record<string, unknown>} */
        const body = { error: "invalid_client", error_description: "client authentication failed" };
        if (options.echoCredentialsInErrors) {
          body.error_description = `client authentication failed for secret ${form.client_secret}`;
          body.client_secret = form.client_secret;
          body.code = form.code;
          body.code_verifier = form.code_verifier;
        }
        return json(res, 401, body);
      }
      const grant = codes.get(form.code ?? "");
      if (!grant || grant.used || grant.clientId !== form.client_id) {
        return json(res, 400, { error: "invalid_grant", error_description: "unknown or used code" });
      }
      if (options.rejectRedirectUriMismatch !== false && form.redirect_uri !== grant.redirectUri) {
        return json(res, 400, {
          error: "invalid_grant",
          error_description: "redirect_uri does not match the authorization request",
        });
      }
      const expected = createHash("sha256")
        .update(form.code_verifier ?? "")
        .digest("base64url");
      if (expected !== grant.codeChallenge) {
        return json(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      }
      grant.used = true;
      const accessToken = randomBytes(24).toString("base64url");
      accessTokens.add(accessToken);
      return json(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid profile email",
      });
    }

    if (url.pathname === "/userinfo") {
      const auth = req.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (!accessTokens.has(token)) {
        return json(
          res,
          401,
          options.echoCredentialsInErrors
            ? { error: "invalid_token", access_token: token }
            : { error: "invalid_token" },
        );
      }
      /** @type {Record<string, string>} */
      const profile = { ...TEST_USER };
      if (options.omitSub) delete profile.sub;
      if (options.omitEmail) delete profile.email;
      return json(res, 200, profile);
    }

    json(res, 404, { error: "not_found" });
  });

  return {
    server,
    state,
    /** Listen on an ephemeral (or given) port and return the base URL. */
    start: (/** @type {number} */ port = 0) =>
      new Promise((resolve) => {
        server.listen(port, "127.0.0.1", () => {
          const address = /** @type {import('node:net').AddressInfo} */ (server.address());
          baseUrl = `http://127.0.0.1:${address.port}`;
          resolve(baseUrl);
        });
      }),
    stop: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  };
}

/** @param {http.ServerResponse} res @param {number} status @param {unknown} body */
function json(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

/** @param {http.IncomingMessage} req */
async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const clientId = process.env.MOCK_IDP_CLIENT_ID ?? "sandbox-client";
  const clientSecret = process.env.MOCK_IDP_CLIENT_SECRET ?? "sandbox-secret";
  const idp = createMockIdp({ clientId, clientSecret });
  idp.start(Number(process.env.MOCK_IDP_PORT ?? 9000)).then((url) => {
    console.log(`Mock identity provider listening on ${url}`);
    console.log("Put this in .env to run the sandbox against it:");
    console.log(`  IDP_WELL_KNOWN_URL=${url}/.well-known/openid-configuration`);
    console.log(`  IDP_CLIENT_ID=${clientId}`);
    console.log(`  IDP_CLIENT_SECRET=${clientSecret}`);
    console.log("  ALLOW_INSECURE_IDP=true");
    console.log(`Signs everyone in as ${TEST_USER.email} without asking.`);
  });
}
