// Helix admin console — CSRF for session-authenticated writes. The auth server issues a JS-readable
// XSRF-TOKEN cookie (CookieCsrfTokenRepository.withHttpOnlyFalse); every mutating request must echo it in
// the X-XSRF-TOKEN header or the CsrfFilter rejects the write (HTTP 405/403). Pure helpers, unit-tested.

const MUTATING = new Set(["POST", "PUT", "DELETE", "PATCH"]);

/** Read a cookie value from a cookie string (defaults to document.cookie), URL-decoded; null if absent. */
export function readCookie(name: string, cookieString: string = typeof document !== "undefined" ? document.cookie : ""): string | null {
  for (const part of cookieString.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

/** True when the HTTP method mutates state and therefore needs a CSRF token. */
export function needsCsrf(method: string): boolean {
  return MUTATING.has((method || "GET").toUpperCase());
}

/** The CSRF header(s) to add for a request — X-XSRF-TOKEN for mutating methods when the cookie is present. */
export function csrfHeaders(
  method: string,
  cookieString: string = typeof document !== "undefined" ? document.cookie : "",
): Record<string, string> {
  if (!needsCsrf(method)) return {};
  const token = readCookie("XSRF-TOKEN", cookieString);
  return token ? { "X-XSRF-TOKEN": token } : {};
}
