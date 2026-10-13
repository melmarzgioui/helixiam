/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Maps a refused client save's `fieldErrors` (the admin API's request field names) onto the client form: errors for
 * fields the form shows go on those fields, and the tab to open is the first one with such an error; the rest are
 * shown in the banner.
 */
const FIELD_TABS: Record<string, "keys" | "login"> = {
  jwksUrl: "keys",
  tokenEndpointAuthMethod: "keys",
  redirectUris: "login",
  postLogoutRedirectUris: "login",
  webOrigins: "login",
  backchannelLogoutUri: "login",
  frontchannelLogoutUri: "login",
};

/**
 * Known server field errors mapped onto the client's own i18n keys, so a refused save shows translated text instead
 * of the server's English-only message. Preferred: the server's stable, language-neutral `fieldErrorCodes` (the
 * admin API sends these for JwksUrlPolicy and the token-endpoint auth-method check — ClientAdminController). Falls
 * back to matching the exact English message text, for a server that doesn't send a code for this field yet. A
 * message this console doesn't recognize (unknown code AND unmatched text) is returned verbatim — never dropped.
 */
const CODE_KEYS: Record<string, Record<string, string>> = {
  jwksUrl: {
    notUrl: "clientDetail.jwksUrlInvalid",
    notHttps: "clientDetail.jwksUrlHttps",
  },
  tokenEndpointAuthMethod: {
    unknown: "clientDetail.authMethodUnknown",
  },
};

const MESSAGE_KEYS: Record<string, Record<string, string>> = {
  jwksUrl: {
    "The JWKS URL is not a valid URL.": "clientDetail.jwksUrlInvalid",
    "The JWKS URL must be an https URL.": "clientDetail.jwksUrlHttps",
  },
  tokenEndpointAuthMethod: {
    "Unknown token endpoint auth method (use private_key_jwt, client_secret_basic or none).": "clientDetail.authMethodUnknown",
  },
};

/** The i18n key for `field`'s server error, or the raw `message` when this console doesn't recognize it. */
function translateServerError(field: string, message: string, code?: string): string {
  return (code && CODE_KEYS[field]?.[code]) ?? MESSAGE_KEYS[field]?.[message] ?? message;
}

export function splitClientServerErrors(fieldErrors: Record<string, string>, fieldErrorCodes: Record<string, string> = {}): {
  fields: Record<string, string>;
  other: string[];
  tab: "keys" | "login" | null;
  /** Every error landed on a field the form shows (so the banner can point at the field instead of repeating it). */
  allMapped: boolean;
} {
  const fields: Record<string, string> = {};
  const other: string[] = [];
  let tab: "keys" | "login" | null = null;
  for (const [key, message] of Object.entries(fieldErrors)) {
    const fieldTab = FIELD_TABS[key];
    if (fieldTab) {
      fields[key] = translateServerError(key, message, fieldErrorCodes[key]);
      tab = tab ?? fieldTab;
    } else {
      other.push(translateServerError(key, message, fieldErrorCodes[key]));
    }
  }
  return { fields, other, tab, allMapped: other.length === 0 && Object.keys(fields).length > 0 };
}
