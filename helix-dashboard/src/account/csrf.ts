/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Helix IAM #322: the account console is a session-cookie SPA, so its writes (PUT/DELETE/POST) need a
 * CSRF token. The auth server uses `CookieCsrfTokenRepository.withHttpOnlyFalse()`, which sets a
 * JS-readable `XSRF-TOKEN` cookie; the SPA echoes it back in the `X-XSRF-TOKEN` header. This pure helper
 * reads that cookie value out of a cookie string (so it is unit-testable without a DOM).
 */
export function readXsrfToken(cookieString: string | null | undefined): string | null {
  if (!cookieString) return null;
  for (const part of cookieString.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    if (name === "XSRF-TOKEN") {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

/** The CSRF header to attach to an unsafe (write) request, or `{}` when no token / a safe method. */
export function csrfHeader(method: string | undefined, cookieString: string | null | undefined): Record<string, string> {
  const m = (method ?? "GET").toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS" || m === "TRACE") return {};
  const token = readXsrfToken(cookieString);
  return token ? { "X-XSRF-TOKEN": token } : {};
}
