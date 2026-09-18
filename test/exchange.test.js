import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import { exchange } from "../sandbox/exchange.js";
import { REDIRECT_URI, authorize, findCheck, pkce, startIdp } from "./helpers.js";
import { TEST_USER } from "./mock-idp.js";

/**
 * Drive the IdP up to a code, then run the exchange the way the sandbox does.
 * @param {Awaited<ReturnType<typeof startIdp>>} env
 * @param {{ iss?: string, redirectUri?: string, codeVerifier?: string }} [override]
 */
async function run(env, override = {}) {
  const { codeVerifier, codeChallenge } = pkce();
  const state = randomUUID();
  const { code } = await authorize(env.url, { codeChallenge, state });
  assert.ok(code, "mock IdP issued a code");
  return exchange(
    {
      code,
      iss: override.iss ?? env.url,
      codeVerifier: override.codeVerifier ?? codeVerifier,
      state,
      redirectUri: override.redirectUri ?? REDIRECT_URI,
    },
    env.config,
  );
}

test("happy path: Tandem would sign the user in", async () => {
  const env = await startIdp();
  try {
    const result = await run(env);
    assert.equal(result.rejection, null);
    assert.deepEqual(result.user, {
      user_id: TEST_USER.sub,
      given_name: TEST_USER.given_name,
      family_name: TEST_USER.family_name,
      email: TEST_USER.email,
    });
    assert.ok(result.steps.every((s) => s.checks.every((c) => c.passed)));
    // Tandem authenticates with client_secret_post and forwards redirect_uri + state.
    const tokenRequest = env.idp.state.tokenRequests[0];
    assert.equal(tokenRequest.client_secret, env.config.idpClientSecret);
    assert.equal(tokenRequest.redirect_uri, REDIRECT_URI);
    assert.ok(tokenRequest.state);
    // Transcripts never contain the secret, the code, or the token.
    const dumped = JSON.stringify(result.transcripts);
    assert.ok(!dumped.includes(env.config.idpClientSecret));
    assert.ok(!dumped.includes(tokenRequest.code));
    assert.ok(!dumped.includes(tokenRequest.code_verifier));
    assert.ok(!dumped.includes(env.idp.state.tokenRequests[0].code));
  } finally {
    await env.idp.stop();
  }
});

test("missing fields are rejected with Tandem's message", async () => {
  const env = await startIdp();
  try {
    const result = await exchange(
      { code: "", iss: env.url, codeVerifier: "v", state: "s", redirectUri: "" },
      env.config,
    );
    assert.equal(result.rejection, "Invalid subject_token payload: missing code, redirect_uri");
    assert.equal(result.transcripts.length, 0, "nothing is fetched");
  } finally {
    await env.idp.stop();
  }
});

test("issuer mismatch is rejected before the code is used", async () => {
  const env = await startIdp();
  try {
    const result = await run(env, { iss: env.url + "/" });
    assert.match(result.rejection ?? "", /^Security warning: issuer from OIDC config/);
    assert.equal(findCheck(result.steps, "discovery.issuer_matches").passed, false);
    assert.equal(env.idp.state.tokenRequests.length, 0);
  } finally {
    await env.idp.stop();
  }
});

test("a discovery document that advertises the wrong issuer fails the same way", async () => {
  const env = await startIdp({ wrongIssuer: true });
  try {
    const result = await run(env);
    assert.equal(findCheck(result.steps, "discovery.issuer_matches").passed, false);
  } finally {
    await env.idp.stop();
  }
});

test("missing userinfo_endpoint fails discovery", async () => {
  const env = await startIdp({ omitUserinfoEndpoint: true });
  try {
    const result = await run(env);
    assert.equal(findCheck(result.steps, "discovery.userinfo_endpoint").passed, false);
    assert.match(result.rejection ?? "", /userinfo_endpoint not found/);
  } finally {
    await env.idp.stop();
  }
});

test("wrong client secret surfaces the provider's error", async () => {
  const env = await startIdp();
  try {
    const result = await run({ ...env, config: { ...env.config, idpClientSecret: "nope" } });
    assert.equal(findCheck(result.steps, "token.status").passed, false);
    assert.match(findCheck(result.steps, "token.status").detail ?? "", /invalid_client/);
    assert.match(result.rejection ?? "", /^Token exchange failed: 401/);
  } finally {
    await env.idp.stop();
  }
});

test("provider error bodies are redacted before they reach the rejection and report", async () => {
  // A misconfigured provider echoes what we sent back in its error. None of
  // it may surface in the rejection (logged, returned as JSON) or check detail.
  const env = await startIdp({ echoCredentialsInErrors: true });
  try {
    const result = await run({ ...env, config: { ...env.config, idpClientSecret: "nope-nope" } });
    const sent = env.idp.state.tokenRequests[0];
    const leaked = ["nope-nope", sent.code, sent.code_verifier];
    const rejection = result.rejection ?? "";
    assert.match(rejection, /^Token exchange failed: 401/);
    const detail = findCheck(result.steps, "token.status").detail ?? "";
    assert.match(detail, /invalid_client/);
    for (const value of leaked) {
      assert.ok(value.length >= 8, "test values must be long enough to be meaningful");
      assert.ok(!rejection.includes(value), `rejection leaks ${value}`);
      assert.ok(!detail.includes(value), `check detail leaks ${value}`);
      assert.ok(!JSON.stringify(result.transcripts).includes(value), `transcript leaks ${value}`);
    }
    assert.ok(rejection.includes("<redacted>"));
    // Rejections stay one line and bounded, however verbose the provider is.
    assert.ok(!rejection.includes("\n"));
    assert.ok(rejection.length < 700);
  } finally {
    await env.idp.stop();
  }
});

test("scrubbing also catches URL-encoded and HTML-escaped echoes of a secret", async () => {
  const { scrubValues } = await import("../sandbox/http.js");
  const secret = 'p@ss w/rd+"<x>~';
  const echoes = [
    `raw ${secret}`,
    `form ${encodeURIComponent(secret)}`,
    `html p@ss w/rd+&quot;&lt;x&gt;~`,
    `json ${JSON.stringify(secret).slice(1, -1)}`,
  ];
  for (const text of echoes) {
    const out = scrubValues(text, [secret]);
    assert.ok(out.includes("<redacted>"), text);
    for (const fragment of ["p@ss", "p%40ss", "w/rd", "w%2Frd"])
      assert.ok(!out.includes(fragment), `${text} -> ${out}`);
  }
});

test("redirect_uri that differs from the authorization request fails at the token endpoint", async () => {
  const env = await startIdp();
  try {
    const result = await run(env, { redirectUri: "http://localhost:3000/other" });
    assert.equal(findCheck(result.steps, "token.status").passed, false);
    assert.match(findCheck(result.steps, "token.status").detail ?? "", /redirect_uri/);
  } finally {
    await env.idp.stop();
  }
});

test("PKCE verifier mismatch fails at the token endpoint", async () => {
  const env = await startIdp();
  try {
    const result = await run(env, { codeVerifier: "not-the-verifier" });
    assert.match(findCheck(result.steps, "token.status").detail ?? "", /PKCE/);
  } finally {
    await env.idp.stop();
  }
});

test("profile without sub is rejected; without email only warns", async () => {
  const noSub = await startIdp({ omitSub: true });
  try {
    const result = await run(noSub);
    assert.equal(result.user, null);
    assert.equal(result.rejection, "No user_id (sub) in user profile response");
  } finally {
    await noSub.idp.stop();
  }
  const noEmail = await startIdp({ omitEmail: true });
  try {
    const result = await run(noEmail);
    assert.ok(result.user);
    assert.equal(result.user.email, undefined);
    const check = findCheck(result.steps, "userinfo.email");
    assert.equal(check.passed, false);
    assert.equal(check.severity, "warn");
  } finally {
    await noEmail.idp.stop();
  }
});

test("plain-http providers are refused unless explicitly allowed", async () => {
  const env = await startIdp();
  try {
    const result = await run({ ...env, config: { ...env.config, allowInsecureIdp: false } });
    assert.equal(findCheck(result.steps, "discovery.reachable").passed, false);
    assert.match(result.transcripts[0].error ?? "", /Only https/);
  } finally {
    await env.idp.stop();
  }
});
