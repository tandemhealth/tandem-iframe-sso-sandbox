/**
 * Server-rendered HTML for the attempt list and the per-attempt report. Every
 * interpolated value is untrusted (it came from the partner's app or IdP) and
 * goes through `esc`.
 */

import { overallStatus, stepStatus } from "./checks.js";

/** @import { AttemptRecord } from './store.js' */
/** @import { Check, Step, Transcript } from './checks.js' */

/** @param {unknown} value */
export function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const CSS = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #1c1917; background: #fafaf9; }
header { background: #fff; border-bottom: 1px solid #e7e5e4; padding: 12px 24px; display: flex; gap: 12px; align-items: baseline; }
header a { color: inherit; text-decoration: none; font-weight: 600; }
header .sub { color: #78716c; font-size: 13px; }
main { max-width: 980px; margin: 0 auto; padding: 24px; }
.notice { background: #fffbeb; border: 1px solid #fde68a; color: #92400e; border-radius: 8px; padding: 10px 14px; font-size: 14px; margin-bottom: 20px; }
h1 { font-size: 22px; margin: 0 0 6px; }
.muted { color: #78716c; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
code { background: #f5f5f4; padding: 1px 5px; border-radius: 4px; }
.badge { display: inline-block; font-size: 12px; font-weight: 600; padding: 2px 8px; border-radius: 999px; text-transform: lowercase; }
.badge.passed { background: #dcfce7; color: #166534; }
.badge.warning { background: #fef3c7; color: #92400e; }
.badge.failed { background: #fee2e2; color: #991b1b; }
.badge.awaiting { background: #e7e5e4; color: #44403c; }
.card { background: #fff; border: 1px solid #e7e5e4; border-radius: 10px; padding: 18px 20px; margin: 16px 0; }
.card h2 { font-size: 16px; margin: 0 0 12px; display: flex; gap: 10px; align-items: center; }
.check { border-left: 3px solid #d6d3d1; background: #fafaf9; padding: 8px 12px; margin: 8px 0; border-radius: 0 6px 6px 0; }
.check.pass { border-color: #16a34a; }
.check.fail { border-color: #dc2626; background: #fef2f2; }
.check.warn { border-color: #d97706; background: #fffbeb; }
.check.info { border-color: #a8a29e; }
.check .desc { font-weight: 500; }
.check .detail { color: #57534e; font-size: 13px; margin-top: 2px; white-space: pre-wrap; word-break: break-word; }
details { margin-top: 12px; }
summary { cursor: pointer; color: #57534e; font-size: 13px; }
pre { background: #f5f5f4; border-radius: 6px; padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 8px 0; }
table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e7e5e4; border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #f5f5f4; font-size: 14px; }
th { color: #78716c; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.verdict { padding: 14px 18px; border-radius: 10px; margin: 16px 0; }
.verdict.ok { background: #f0fdf4; border: 1px solid #bbf7d0; }
.verdict.no { background: #fef2f2; border: 1px solid #fecaca; }
`;

/**
 * @param {string} title
 * @param {string} body
 */
function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — Tandem iframe SSO Sandbox</title>
<style>${CSS}</style>
</head>
<body>
<header><a href="/attempts">Tandem iframe SSO Sandbox</a><span class="sub">partner conformance harness</span></header>
<main>
<div class="notice">This is a developer sandbox. Use test identities only — never point it at a production identity provider or a production Tandem environment.</div>
${body}
</main>
</body>
</html>`;
}

/** @param {AttemptRecord} attempt */
function statusOf(attempt) {
  return attempt.status === "awaiting" ? "awaiting" : overallStatus(attempt.steps);
}

/**
 * @param {AttemptRecord[]} attempts
 * @param {{ partnerName: string, partnerOrigins: string[], idpWellKnownUrl: string, port: number }} config
 */
export function renderList(attempts, config) {
  const rows = attempts
    .map(
      (a) => `<tr>
<td><code>${esc(a.createdAt.toISOString().replace("T", " ").slice(0, 19))}Z</code></td>
<td><code>${esc(a.requestId)}</code></td>
<td>${esc(a.origin ?? "—")}</td>
<td><span class="badge ${statusOf(a)}">${statusOf(a)}</span></td>
<td>${a.status === "completed" ? `<a href="/attempts/${esc(a.requestId)}">report</a>` : '<span class="muted">waiting for your app</span>'}</td>
</tr>`,
    )
    .join("");
  return page(
    "Attempts",
    `<h1>Authorization attempts</h1>
<p class="muted">Playing Tandem for <strong>${esc(config.partnerName)}</strong> · accepting messages from ${config.partnerOrigins.map((o) => `<code>${esc(o)}</code>`).join(", ")} · identity provider <code>${esc(config.idpWellKnownUrl)}</code></p>
<p>Every load of the sandbox iframe in your app creates an attempt and sends <code>AuthorizeWithoutRedirect</code>. When your app answers with <code>CustomTokenExchangeResponseAuthCode</code>, the attempt completes and a report appears here. Embed <code>http://localhost:${esc(config.port)}/</code> in your app to start.</p>
${
  attempts.length
    ? `<table><tr><th>Started</th><th>requestId</th><th>From origin</th><th>Result</th><th></th></tr>${rows}</table>`
    : '<p class="muted">No attempts yet.</p>'
}`,
  );
}

/** @param {Check} check */
function renderCheck(check) {
  const cls = check.passed ? "pass" : check.severity;
  const mark = check.severity === "info" ? "ⓘ" : check.passed ? "✓" : "✕";
  return `<div class="check ${cls}" data-check-result="${esc(check.id)}:${check.passed ? "pass" : "fail"}">
<div class="desc">${mark} ${esc(check.description)}</div>
${check.detail ? `<div class="detail">${esc(check.detail)}</div>` : ""}
</div>`;
}

/** @param {Step} step @param {number} index */
function renderStep(step, index) {
  const status = stepStatus(step);
  return `<section class="card" data-step="${esc(step.id)}">
<h2><span class="badge ${status}">${status}</span> ${index + 1}. ${esc(step.title)}</h2>
${step.checks.map(renderCheck).join("")}
</section>`;
}

/** @param {Transcript} t */
function renderTranscript(t) {
  const req = `${t.method} ${t.url}\n${Object.entries(t.requestHeaders)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n")}${t.requestBody ? `\n\n${t.requestBody}` : ""}`;
  const res = t.error
    ? `ERROR: ${t.error}`
    : `HTTP ${t.status}\n${Object.entries(t.responseHeaders ?? {})
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n")}\n\n${t.responseBody ?? ""}`;
  return `<details><summary>${esc(t.method)} ${esc(t.url)}${t.status ? ` → ${esc(t.status)}` : t.error ? " → error" : ""}</summary>
<pre>${esc(req)}</pre><pre>${esc(res)}</pre></details>`;
}

/**
 * @param {AttemptRecord} attempt
 * @param {{ partnerName: string }} config
 */
export function renderReport(attempt, config) {
  const status = statusOf(attempt);
  const verdict =
    attempt.status !== "completed"
      ? ""
      : attempt.user
        ? `<div class="verdict ok" data-overall-status="${status}"><strong>Tandem would sign this user in.</strong><br>
<code>sub</code> ${esc(attempt.user.user_id)}${attempt.user.email ? ` · <code>email</code> ${esc(attempt.user.email)}` : ""}${
            attempt.user.given_name || attempt.user.family_name
              ? ` · name ${esc([attempt.user.given_name, attempt.user.family_name].filter(Boolean).join(" "))}`
              : ""
          }<br><span class="muted">In production Tandem creates or links the clinician account by <code>sub</code> and stores email and name on it.</span></div>`
        : `<div class="verdict no" data-overall-status="${status}"><strong>Tandem would reject this sign-in.</strong><br>
${attempt.rejection ? `Production error: <code>${esc(attempt.rejection)}</code>` : "Your app's message did not pass the protocol checks, so Tandem would have ignored it."}</div>`;

  return page(
    `Attempt ${attempt.requestId}`,
    `<h1>Authorization attempt <span class="badge ${status}">${status}</span></h1>
<p class="muted">${esc(config.partnerName)} · requestId <code>${esc(attempt.requestId)}</code> · started ${esc(attempt.createdAt.toISOString())}${attempt.origin ? ` · answered from <code>${esc(attempt.origin)}</code>` : ""}</p>
${verdict}
${attempt.steps.map(renderStep).join("")}
${
  attempt.transcripts.length
    ? `<section class="card"><h2>HTTP transcripts</h2><p class="muted">Every request Tandem made to your identity provider. Secrets, codes and tokens are redacted.</p>${attempt.transcripts.map(renderTranscript).join("")}</section>`
    : ""
}
<p class="muted"><a href="/attempts">All attempts</a></p>`,
  );
}

/**
 * @param {number} status
 * @param {string} message
 */
export function renderError(status, message) {
  return page(
    String(status),
    `<h1>${esc(status)}</h1><p>${esc(message)}</p><p><a href="/attempts">All attempts</a></p>`,
  );
}
