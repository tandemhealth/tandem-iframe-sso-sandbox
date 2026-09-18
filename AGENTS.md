# Repository guidelines

This is a public, partner-facing tool. Partners (EHR vendors) clone it and run
it on their own machines to test the iframe SSO flow described in Tandem's
"iframe Authentication" guide, without involving Tandem or Tandem's identity
platform. Read this before changing anything.

## What the sandbox is

- `sandbox/` plays **Tandem's role**: the page a partner embeds in an iframe
  (stands in for `app.tandemhealth.ai`), and the token exchange Tandem
  performs against the partner's identity provider.
- `partner-example/` is a reference implementation of the **partner's side**,
  following the guide literally. It doubles as the partner half of the tests.
- `test/mock-idp.js` is a minimal OpenID Connect provider used only by tests so
  the whole flow runs offline. Partners point the sandbox at their real IdP.

## Fidelity to the real exchange

The exchange in `sandbox/exchange.js` reproduces the behaviour of Tandem's
internal token exchange, step for step. That code is **not** copied here: it is
Tandem-internal. Instead each sandbox check maps to one step of the exchange:

| Sandbox check              | Tandem step                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `payload.required`         | reject when `code`, `iss`, `code_verifier`, `state`, `redirect_uri` missing                                                                             |
| `discovery.*`              | fetch well-known; require `issuer`, `token_endpoint`, `userinfo_endpoint`                                                                               |
| `discovery.issuer_matches` | reject when discovered `issuer` != message `iss`                                                                                                        |
| `token.*`                  | POST `grant_type=authorization_code` with `client_id`, `client_secret` (body), `code`, `code_verifier`, `state`, `redirect_uri`; require `access_token` |
| `userinfo.*`               | GET userinfo with bearer token; require `sub`                                                                                                           |
| `userinfo.claims`          | link user by `sub`, `given_name`, `family_name`, `email`                                                                                                |

When Tandem's exchange changes, change `exchange.js` to match and update this
table. Do not add checks here that Tandem does not perform: the sandbox must
predict exactly what Tandem will do, no more and no less.

## House rules

- **Zero runtime dependencies.** Partners run `node sandbox/server.js` with
  nothing to install. Node built-ins only in `sandbox/` and `partner-example/`.
  Dev dependencies are fine for tests, type checking and formatting.
- **Plain ESM JavaScript with JSDoc types**, checked by `npm run check`
  (`tsc --checkJs`). No build step.
- **Secrets stay on the partner's machine.** `IDP_CLIENT_SECRET` is read from
  `.env` and used server-side only; it never reaches the browser, logs, or the
  report. Transcripts redact `code`, `code_verifier`, `client_secret`, and
  tokens before storage, and every value the sandbox sent is scrubbed from
  provider response bodies wherever it appears. Never put `response.text` in a
  rejection, log line or check detail directly: go through `redactInline` and
  the `known` scrub list in `exchange.js`.
- **Escape everything rendered into HTML.** Every value in a report comes from
  the partner's app or IdP and is untrusted.
- **Nothing here is PHI**, but the sandbox must still never be pointed at a
  production system; the UI says so.
- Keep the partner-facing README in sync with the guide's message interface. If
  the guide and the code disagree, the code (and Tandem's exchange) win — fix the
  guide.

## Checks before committing

```bash
npm test && npm run check && npm run format:check
npm run e2e   # needs `npx playwright install chromium` once
```
