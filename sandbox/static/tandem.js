// Runs inside the partner's iframe and behaves like the Tandem web app:
// announce an authorization request to the parent, then hand the parent's
// answer to the sandbox backend, which validates it and performs the exchange.
//
// Nothing secret lives here. The PKCE verifier stays on the server.

(async () => {
  const statusEl = document.getElementById("status");
  const hintEl = document.getElementById("hint");
  const set = (html, cls) => {
    statusEl.innerHTML = html;
    statusEl.className = cls || "";
  };
  const esc = (v) =>
    String(v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

  if (window.parent === window) {
    set(
      "This page is meant to be embedded in an <code>&lt;iframe&gt;</code> by your application. " +
        'Open <a href="/attempts">the attempts list</a> to see reports.',
    );
    return;
  }

  const config = await (await fetch("/config")).json();
  const attempt = await (await fetch("/attempts", { method: "POST" })).json();

  const request = {
    type: "AuthorizeWithoutRedirect",
    requestId: attempt.requestId,
    partner: config.partner,
    clientId: config.clientId,
    state: attempt.state,
    codeChallenge: attempt.codeChallenge,
    codeChallengeMethod: attempt.codeChallengeMethod,
  };

  // Tandem sends a fresh request on every load. Post to each registered
  // partner origin; the browser drops the copies whose origin does not match.
  for (const origin of config.partnerOrigins) {
    window.parent.postMessage(request, origin);
  }
  set(
    `Sent <code>AuthorizeWithoutRedirect</code> (requestId <code>${esc(attempt.requestId)}</code>). ` +
      `Waiting for <code>CustomTokenExchangeResponseAuthCode</code> from your app…`,
  );
  hintEl.innerHTML =
    "Your app should now redirect the user to your identity provider and, on return, post the authorization code " +
    'back to this frame. Reports: <a href="/attempts" target="_blank" rel="noopener">all attempts</a>.';

  let answered = false;
  window.addEventListener("message", async (event) => {
    if (event.source === window || answered) return;
    const data = event.data;
    // Forward anything object-shaped so misspelt types show up in the report.
    if (typeof data !== "object" || data === null) return;

    // The parent may be answering an earlier request (it reloaded this frame
    // after the redirect). Route by the requestId it sends, when present.
    const requestId =
      typeof data.requestId === "number" && Number.isInteger(data.requestId) ? data.requestId : attempt.requestId;
    answered = true;
    set(`Received a message from <code>${esc(event.origin)}</code>; Tandem is validating it and exchanging the code…`);

    const response = await fetch(`/attempts/${requestId}/response`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ origin: event.origin, message: data }),
    });
    const result = await response.json();
    hintEl.innerHTML =
      'Reload your app to start another attempt. <a href="/attempts" target="_blank" rel="noopener">All attempts</a>.';
    const link = result.reportUrl
      ? ` <a href="${esc(result.reportUrl)}" target="_blank" rel="noopener">Open the report</a>.`
      : "";
    if (response.status === 404) {
      set(
        `Your app answered with requestId <code>${esc(requestId)}</code>, which this sandbox does not know ` +
          "(it forgets attempts on restart). Reload your app to start a new attempt.",
        "bad",
      );
    } else if (result.accepted) {
      set(`✓ Tandem would sign the user in.${link}`, "ok");
    } else {
      set(
        `✕ Tandem would reject this sign-in.${result.rejection ? ` <code>${esc(result.rejection)}</code>` : ""}${link}`,
        "bad",
      );
    }
  });
})().catch((err) => {
  document.getElementById("status").textContent = "Sandbox error: " + (err && err.message ? err.message : err);
  document.getElementById("status").className = "bad";
});
