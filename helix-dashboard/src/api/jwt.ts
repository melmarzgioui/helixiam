/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Decode selected claims from an OIDC id_token (base64url JSON payload). No signature check — used only to
// flag the admin's own row on the Sessions screen. Returns null on any parse failure.
function payload(idToken: string | null): Record<string, unknown> | null {
  if (!idToken) return null;
  const parts = idToken.split(".");
  if (parts.length < 2) return null;
  try {
    return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** The `sid` claim (precise session id) if present, else null. */
export function decodeJwtSid(idToken: string | null): string | null {
  const sid = payload(idToken)?.sid;
  return typeof sid === "string" ? sid : null;
}

/** The `sub` claim (subject / user id) if present, else null. */
export function decodeJwtSub(idToken: string | null): string | null {
  const sub = payload(idToken)?.sub;
  return typeof sub === "string" ? sub : null;
}
