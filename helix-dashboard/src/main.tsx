/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { installSessionFetch, startLogin, goToLoginDirect, handleCallback, SESSION_PROBE } from "./api/session";
import "./styles/tokens.css";
import "./styles/components.css";

// The admin console logs in via OIDC (authorization_code + PKCE against the seeded helix-console client)
// so the admin session shows on the Sessions screen and is SLO-revocable. /admin still rides the SESSION
// cookie the authorize flow establishes. Boot order: (1) if this is the /console/callback, finish the
// token exchange (that's what registers the sid'd SSO session), then fall through; (2) probe the
// session-gated account endpoint with the NATIVE fetch; (3) if unauthenticated, start the OIDC flow; (4)
// otherwise install the global fetch wrapper and render. A failed callback drops to the break-glass
// form-login so a misconfigured client can never fully lock an admin out.
async function boot() {
  try {
    await handleCallback();
  } catch {
    goToLoginDirect();
    return;
  }
  let authed = false;
  try {
    const res = await window.fetch(SESSION_PROBE, { redirect: "manual", credentials: "include" });
    authed = res.ok;
  } catch {
    authed = false;
  }
  if (!authed) {
    void startLogin();
    return;
  }
  installSessionFetch();
  createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}

void boot();
