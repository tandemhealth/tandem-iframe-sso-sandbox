import assert from "node:assert/strict";
import { test } from "node:test";

import { createServer } from "../sandbox/server.js";
import { RESPONSE_TYPE } from "../sandbox/protocol.js";
import { REDIRECT_URI, authorize, startIdp } from "./helpers.js";
import { TEST_USER } from "./mock-idp.js";

const PARTNER_ORIGIN = "http://localhost:3000";

async function startSandbox() {
  const env = await startIdp();
  const server = createServer({
    partnerOrigins: [PARTNER_ORIGIN],
    partnerName: "Example EHR",
    host: "127.0.0.1",
    port: 0,
    ...env.config,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(undefined)));
  const address = /** @type {import('node:net').AddressInfo} */ (server.address());
  const base = `http://127.0.0.1:${address.port}`;
  return {
    base,
    env,
    stop: async () => {
      await new Promise((resolve) => server.close(() => resolve(undefined)));
      await env.idp.stop();
    },
  };
}

test("full flow through the HTTP API ends in a passing report", async () => {
  const sb = await startSandbox();
  try {
    // The iframe page creates an attempt and posts AuthorizeWithoutRedirect.
    const created = await (await fetch(`${sb.base}/attempts`, { method: "POST" })).json();
    assert.equal(created.codeChallengeMethod, "S256");

    // The partner sends the user to the IdP and gets a code back.
    const { code } = await authorize(sb.env.url, { codeChallenge: created.codeChallenge, state: created.state });

    // The partner answers; the iframe page forwards the message with its origin.
    const answer = await fetch(`${sb.base}/attempts/${created.requestId}/response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        origin: PARTNER_ORIGIN,
        message: {
          type: RESPONSE_TYPE,
          requestId: created.requestId,
          partner: "Example EHR",
          state: created.state,
          code,
          iss: sb.env.url,
          redirectUri: REDIRECT_URI,
        },
      }),
    });
    const result = await answer.json();
    assert.equal(result.accepted, true);

    const report = await (await fetch(`${sb.base}${result.reportUrl}`)).text();
    assert.match(report, /data-overall-status="passed"/);
    assert.ok(report.includes(TEST_USER.email));
    assert.ok(!report.includes("sandbox-secret"));
    assert.ok(!report.includes(code ?? "!"));

    // Answering twice is refused; the state was single-use.
    const again = await fetch(`${sb.base}/attempts/${created.requestId}/response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ origin: PARTNER_ORIGIN, message: {} }),
    });
    assert.equal(again.status, 409);

    const list = await (await fetch(`${sb.base}/attempts`)).text();
    assert.ok(list.includes(String(created.requestId)));
  } finally {
    await sb.stop();
  }
});

test("a protocol failure produces a failed report without touching the IdP", async () => {
  const sb = await startSandbox();
  try {
    const created = await (await fetch(`${sb.base}/attempts`, { method: "POST" })).json();
    const answer = await fetch(`${sb.base}/attempts/${created.requestId}/response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        origin: "https://evil.example",
        message: {
          type: RESPONSE_TYPE,
          requestId: created.requestId,
          state: created.state,
          code: "x",
          iss: sb.env.url,
        },
      }),
    });
    const result = await answer.json();
    assert.equal(result.accepted, false);
    const report = await (await fetch(`${sb.base}${result.reportUrl}`)).text();
    assert.match(report, /data-overall-status="failed"/);
    assert.match(report, /data-check-result="protocol.origin:fail"/);
    assert.equal(sb.env.idp.state.tokenRequests.length, 0);
  } finally {
    await sb.stop();
  }
});

test("the iframe page is embeddable only by partner origins; reports are not", async () => {
  const sb = await startSandbox();
  try {
    const page = await fetch(`${sb.base}/`);
    assert.match(page.headers.get("content-security-policy") ?? "", new RegExp(`frame-ancestors ${PARTNER_ORIGIN}`));
    const list = await fetch(`${sb.base}/attempts`);
    assert.match(list.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
    // Values rendered into HTML are escaped.
    const created = await (await fetch(`${sb.base}/attempts`, { method: "POST" })).json();
    await fetch(`${sb.base}/attempts/${created.requestId}/response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ origin: PARTNER_ORIGIN, message: { type: "<script>alert(1)</script>" } }),
    });
    const report = await (await fetch(`${sb.base}/attempts/${created.requestId}`)).text();
    assert.ok(!report.includes("<script>alert(1)</script>"));
    assert.ok(report.includes("&lt;script&gt;"));
  } finally {
    await sb.stop();
  }
});

test("unknown attempts and bad bodies are rejected", async () => {
  const sb = await startSandbox();
  try {
    assert.equal((await fetch(`${sb.base}/attempts/1/response`, { method: "POST", body: "{}" })).status, 404);
    assert.equal((await fetch(`${sb.base}/attempts/1`)).status, 404);
    const created = await (await fetch(`${sb.base}/attempts`, { method: "POST" })).json();
    assert.equal(
      (await fetch(`${sb.base}/attempts/${created.requestId}/response`, { method: "POST", body: "not json" })).status,
      400,
    );
  } finally {
    await sb.stop();
  }
});
