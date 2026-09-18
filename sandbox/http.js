/**
 * HTTP calls to the partner's identity provider, recorded as redacted
 * transcripts for the report.
 *
 * The only URLs fetched are the operator-configured discovery document and the
 * endpoints that document names, so the guard is deliberately light: https
 * unless explicitly relaxed, a response size cap, and a timeout.
 */

/** @import { Transcript } from './checks.js' */

export const MAX_RESPONSE_BYTES = 1_000_000;
export const TIMEOUT_MS = 15_000;
export const REDACTED = "<redacted>";

const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "set-cookie"]);
const SENSITIVE_FORM_FIELDS = new Set(["client_secret", "code", "code_verifier"]);
const SENSITIVE_JSON_FIELDS = new Set(["access_token", "refresh_token", "id_token", "client_secret", "code_verifier"]);

/**
 * @typedef {object} RecordedResponse
 * @property {number} status
 * @property {Headers} headers
 * @property {string} text
 */

/**
 * @param {string} method
 * @param {string} url
 * @param {{ headers?: Record<string, string>, form?: Record<string, string>, allowInsecure: boolean, fetchImpl?: typeof fetch, scrub?: string[] }} opts
 *   `scrub` lists secret values (the client secret, code, verifier, tokens) to
 *   remove from the recorded response body wherever they appear, since
 *   providers sometimes echo them inside free-text error descriptions.
 * @returns {Promise<{ response: RecordedResponse | null, transcript: Transcript }>}
 */
export async function recordedFetch(method, url, opts) {
  /** @type {Record<string, string>} */
  const headers = { Accept: "application/json", ...(opts.headers ?? {}) };
  let body;
  if (opts.form) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(opts.form).toString();
  }
  /** @type {Transcript} */
  const transcript = {
    method,
    url,
    requestHeaders: redactHeaders(headers),
    requestBody: opts.form ? redactForm(opts.form) : undefined,
  };

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    transcript.error = "Not a valid URL.";
    return { response: null, transcript };
  }
  if (parsed.protocol !== "https:" && !(opts.allowInsecure && parsed.protocol === "http:")) {
    transcript.error = `Only https:// URLs are allowed (got ${parsed.protocol}//). Tandem never calls plain-http endpoints.`;
    return { response: null, transcript };
  }

  const fetchImpl = opts.fetchImpl ?? fetch;
  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await readCapped(response);
    transcript.status = response.status;
    transcript.responseHeaders = redactHeaders(Object.fromEntries(response.headers));
    transcript.responseBody = scrubValues(redactBody(text), opts.scrub ?? []);
    if (response.status >= 300 && response.status < 400) {
      transcript.error = "Redirect responses are not followed; the endpoint must answer directly.";
      return { response: null, transcript };
    }
    return { response: { status: response.status, headers: response.headers, text }, transcript };
  } catch (err) {
    transcript.error = describeError(err);
    return { response: null, transcript };
  }
}

/**
 * `fetch` reports network failures as a bare "fetch failed" with the real
 * reason (ECONNREFUSED, ENOTFOUND, certificate errors) on `cause`.
 * @param {unknown} err
 */
export function describeError(err) {
  if (!(err instanceof Error)) return String(err);
  const cause = /** @type {{ code?: string, message?: string } | undefined} */ (err.cause);
  const reason = cause?.code ?? cause?.message;
  return reason ? `${err.message}: ${reason}` : `${err.name}: ${err.message}`;
}

/** @param {Response} response */
async function readCapped(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes.`);
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

/** @param {Record<string, string>} headers */
export function redactHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k, SENSITIVE_HEADERS.has(k.toLowerCase()) ? REDACTED : v]),
  );
}

/** @param {Record<string, string>} form */
export function redactForm(form) {
  return new URLSearchParams(
    Object.fromEntries(Object.entries(form).map(([k, v]) => [k, SENSITIVE_FORM_FIELDS.has(k) ? REDACTED : v])),
  ).toString();
}

/**
 * One-line, redacted rendering of a response body for messages that end up in
 * logs, JSON replies and report headlines (the transcript keeps the full,
 * pretty-printed redaction). Never hand `response.text` to those sinks directly.
 * @param {string} text
 */
export function redactInline(text) {
  return redactBody(text).replace(/\s+/g, " ").trim().slice(0, 500);
}

/**
 * Replace every occurrence of the given secret values in free text, including
 * their URL-encoded and HTML-escaped forms, which providers commonly use when
 * echoing request parameters inside error descriptions.
 * @param {string} text
 * @param {string[]} values
 */
export function scrubValues(text, values) {
  let out = text;
  for (const value of values) {
    if (!value || value.length < 4) continue;
    for (const form of new Set([
      value,
      encodeURIComponent(value),
      escapeHtml(value),
      JSON.stringify(value).slice(1, -1),
    ])) {
      if (form.length >= 4) out = out.split(form).join(REDACTED);
    }
  }
  return out;
}

/** @param {string} s */
function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** @param {string} text */
export function redactBody(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return text.slice(0, 20_000);
  }
  return JSON.stringify(redactJson(parsed), null, 2).slice(0, 20_000);
}

/** @param {unknown} value @returns {unknown} */
function redactJson(value) {
  if (Array.isArray(value)) return value.map(redactJson);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, SENSITIVE_JSON_FIELDS.has(k) ? REDACTED : redactJson(v)]),
    );
  }
  return value;
}
