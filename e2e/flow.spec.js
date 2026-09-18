// The whole thing in a real browser: the partner example embeds the sandbox,
// gets AuthorizeWithoutRedirect, bounces through the mock IdP, posts the code
// back, and the sandbox produces a passing report.

import { expect, test } from "@playwright/test";

import { createPartnerServer } from "../partner-example/server.js";
import { createServer } from "../sandbox/server.js";
import { CLIENT_ID, CLIENT_SECRET } from "../test/helpers.js";
import { TEST_USER, createMockIdp } from "../test/mock-idp.js";

const SANDBOX_PORT = 18000;
const PARTNER_PORT = 13000;
const SANDBOX_URL = `http://localhost:${SANDBOX_PORT}`;
const PARTNER_URL = `http://localhost:${PARTNER_PORT}`;

/** @type {ReturnType<typeof createMockIdp>} */
let idp;
/** @type {import('node:http').Server[]} */
let servers = [];

test.beforeAll(async () => {
  idp = createMockIdp({ clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUris: [`${PARTNER_URL}/callback`] });
  const idpUrl = await idp.start();
  const wellKnown = `${idpUrl}/.well-known/openid-configuration`;

  const sandbox = createServer({
    partnerOrigins: [PARTNER_URL],
    partnerName: "Example EHR",
    idpClientId: CLIENT_ID,
    idpClientSecret: CLIENT_SECRET,
    idpWellKnownUrl: wellKnown,
    allowInsecureIdp: true,
    host: "127.0.0.1",
    port: SANDBOX_PORT,
  });
  const partner = createPartnerServer({
    sandboxUrl: SANDBOX_URL,
    idpWellKnownUrl: wellKnown,
    idpClientId: CLIENT_ID,
    host: "127.0.0.1",
    port: PARTNER_PORT,
  });
  servers = [sandbox, partner];
  await Promise.all(
    servers.map(
      (s, i) => new Promise((r) => s.listen([SANDBOX_PORT, PARTNER_PORT][i], "127.0.0.1", () => r(undefined))),
    ),
  );
});

test.afterAll(async () => {
  await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r(undefined)))));
  await idp.stop();
});

test("partner example signs in through the sandbox and gets a passing report", async ({ page }) => {
  await page.goto(PARTNER_URL);

  // The iframe announces itself, the partner redirects to the IdP, the IdP
  // sends us back with a code, and the partner posts it into the iframe.
  const frame = page.frameLocator("#tandem-iframe");
  await expect(frame.locator("#status")).toContainText("Tandem would sign the user in", { timeout: 15_000 });
  await expect(page.locator("#log")).toContainText("Posting CustomTokenExchangeResponseAuthCode");
  await page.setViewportSize({ width: 1100, height: 520 });
  await page.screenshot({ path: "test-results/partner-example.png" });

  // The report shows the linked user and every check green.
  const reportHref = await frame.locator("#status a").getAttribute("href");
  expect(reportHref).toMatch(/^\/attempts\/\d+$/);
  await page.goto(`${SANDBOX_URL}${reportHref}`);
  await expect(page.locator("[data-overall-status]")).toHaveAttribute("data-overall-status", "passed");
  await expect(page.locator("body")).toContainText(TEST_USER.email);
  expect(await page.locator('[data-check-result$=":fail"]').count()).toBe(0);
  await page.setViewportSize({ width: 1100, height: 1100 });
  await page.screenshot({ path: "test-results/report.png" });
});

test("a malformed answer is rejected with a report naming each problem", async ({ page }) => {
  // A bare host page on the partner origin, so the partner example's own
  // (correct) handling does not kick in.
  await page.goto(`${PARTNER_URL}/partner.js`);
  await page.setContent(`<!doctype html><iframe id="tandem-iframe" src="${SANDBOX_URL}/"></iframe>`);
  const frame = page.frameLocator("#tandem-iframe");
  const status = frame.locator("#status");
  await expect(status).toContainText("Waiting for CustomTokenExchangeResponseAuthCode");
  const requestId = Number((await status.textContent())?.match(/requestId (\d+)/)?.[1]);
  expect(requestId).toBeGreaterThan(0);

  // The host answers with the wrong state and without redirectUri.
  await page.evaluate(
    ({ requestId }) => {
      const iframe = /** @type {HTMLIFrameElement} */ (document.getElementById("tandem-iframe"));
      iframe.contentWindow?.postMessage(
        {
          type: "CustomTokenExchangeResponseAuthCode",
          requestId,
          partner: "Example EHR",
          state: "stale",
          code: "x",
          iss: "https://idp.example",
        },
        "*",
      );
    },
    { requestId },
  );
  await expect(status).toContainText("Tandem would reject");
  await page.goto(`${SANDBOX_URL}/attempts/${requestId}`);
  await expect(page.locator("[data-overall-status]")).toHaveAttribute("data-overall-status", "failed");
  await expect(page.locator('[data-check-result="protocol.state:fail"]')).toBeVisible();
  await expect(page.locator('[data-check-result="protocol.redirect_uri:fail"]')).toBeVisible();
  await expect(page.locator('[data-check-result="protocol.origin:pass"]')).toBeVisible();
});
