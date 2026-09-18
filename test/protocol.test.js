import assert from "node:assert/strict";
import { test } from "node:test";

import { RESPONSE_TYPE, validateResponse } from "../sandbox/protocol.js";

const attempt = { requestId: 4711, state: "state-1", codeVerifier: "v", codeChallenge: "c" };
const base = {
  attempt,
  origin: "http://localhost:3000",
  partnerOrigins: ["http://localhost:3000"],
  partnerName: "Example EHR",
};
const good = {
  type: RESPONSE_TYPE,
  requestId: 4711,
  partner: "Example EHR",
  state: "state-1",
  code: "abc",
  iss: "https://login.example.test/tenant/v2.0",
  redirectUri: "http://localhost:3000/callback",
};

/** @param {import('../sandbox/checks.js').Step} step @param {string} id */
const check = (step, id) => step.checks.find((c) => c.id === id) ?? assert.fail(`missing ${id}`);

test("a well-formed response passes every check and yields the payload", () => {
  const { step, payload } = validateResponse({ ...base, message: good });
  assert.ok(step.checks.every((c) => c.passed));
  assert.deepEqual(payload, { code: "abc", iss: good.iss, redirectUri: good.redirectUri });
});

test("messages from an unregistered origin are refused", () => {
  const { step, payload } = validateResponse({ ...base, origin: "https://evil.example", message: good });
  assert.equal(check(step, "protocol.origin").passed, false);
  assert.equal(payload, null);
});

test("a JSON string instead of an object is called out", () => {
  const { step, payload } = validateResponse({ ...base, message: JSON.stringify(good) });
  assert.equal(check(step, "protocol.object").passed, false);
  assert.match(check(step, "protocol.object").detail ?? "", /JSON.stringify/);
  assert.equal(payload, null);
});

test("each echoed field is checked individually", () => {
  const cases = /** @type {[string, Record<string, unknown>][]} */ ([
    ["protocol.type", { type: "AuthorizeResponse" }],
    ["protocol.request_id", { requestId: "4711" }], // string instead of number
    ["protocol.request_id", { requestId: 1 }],
    ["protocol.partner", { partner: "Tandem" }],
    ["protocol.state", { state: "other" }],
    ["protocol.code", { code: "" }],
    ["protocol.iss", { iss: "login.example.test" }], // not a URL
    ["protocol.redirect_uri", { redirectUri: undefined }],
  ]);
  for (const [id, override] of cases) {
    const { step, payload } = validateResponse({ ...base, message: { ...good, ...override } });
    assert.equal(check(step, id).passed, false, id);
    assert.equal(payload, null, id);
    // Everything else still passes, so the report points at exactly one problem.
    assert.equal(step.checks.filter((c) => !c.passed).length, 1, id);
  }
});

test("the missing redirectUri failure explains why Tandem needs it", () => {
  const { step } = validateResponse({ ...base, message: { ...good, redirectUri: undefined } });
  assert.match(check(step, "protocol.redirect_uri").detail ?? "", /token endpoint/);
});
