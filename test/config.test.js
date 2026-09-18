import assert from "node:assert/strict";
import { test } from "node:test";

import { ConfigError, configFromEnv, isOrigin } from "../sandbox/config.js";

const valid = {
  PARTNER_ORIGINS: "http://localhost:3000, https://ehr.example",
  PARTNER_NAME: "Example EHR",
  IDP_CLIENT_ID: "id",
  IDP_CLIENT_SECRET: "secret",
  IDP_WELL_KNOWN_URL: "https://login.example/.well-known/openid-configuration",
};

test("a complete .env produces a config with secure defaults", () => {
  const config = configFromEnv(valid);
  assert.deepEqual(config.partnerOrigins, ["http://localhost:3000", "https://ehr.example"]);
  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.port, 8000);
  assert.equal(config.allowInsecureIdp, false);
});

test("required values and shapes are enforced", () => {
  const bad = /** @type {[Record<string, string | undefined>, RegExp][]} */ ([
    [{ IDP_WELL_KNOWN_URL: undefined }, /IDP_WELL_KNOWN_URL is required/],
    [{ IDP_WELL_KNOWN_URL: "not a url" }, /not a valid URL/],
    [{ IDP_WELL_KNOWN_URL: "http://localhost:9000/.well-known/openid-configuration" }, /must be https/],
    [{ IDP_CLIENT_SECRET: undefined }, /IDP_CLIENT_ID and IDP_CLIENT_SECRET/],
    [{ PARTNER_ORIGINS: "http://localhost:3000/app" }, /not an origin/],
    [{ PARTNER_ORIGINS: "ftp://ehr.example" }, /not an origin/],
    [{ SANDBOX_PORT: "80000" }, /port number/],
  ]);
  for (const [override, message] of bad) {
    assert.throws(
      () => configFromEnv({ ...valid, ...override }),
      (err) => err instanceof ConfigError && message.test(err.message),
      JSON.stringify(override),
    );
  }
});

test("ALLOW_INSECURE_IDP=true admits an http:// provider", () => {
  const config = configFromEnv({
    ...valid,
    IDP_WELL_KNOWN_URL: "http://127.0.0.1:9000/.well-known/openid-configuration",
    ALLOW_INSECURE_IDP: "true",
  });
  assert.equal(config.allowInsecureIdp, true);
});

test("isOrigin", () => {
  assert.equal(isOrigin("https://ehr.example"), true);
  assert.equal(isOrigin("http://localhost:3000"), true);
  assert.equal(isOrigin("https://ehr.example/"), false);
  assert.equal(isOrigin("ehr.example"), false);
});
