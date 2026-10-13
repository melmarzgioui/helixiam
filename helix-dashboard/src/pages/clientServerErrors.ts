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

export function splitClientServerErrors(fieldErrors: Record<string, string>): {
  fields: Record<string, string>;
  other: string[];
  tab: "keys" | "login" | null;
} {
  const fields: Record<string, string> = {};
  const other: string[] = [];
  let tab: "keys" | "login" | null = null;
  for (const [key, message] of Object.entries(fieldErrors)) {
    const fieldTab = FIELD_TABS[key];
    if (fieldTab) {
      fields[key] = message;
      tab = tab ?? fieldTab;
    } else {
      other.push(message);
    }
  }
  return { fields, other, tab };
}
