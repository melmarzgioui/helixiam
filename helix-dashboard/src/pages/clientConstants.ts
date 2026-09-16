/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** Shared client constants for the Clients list + the client detail page. */

/** Every grant type the auth server honours. Standard OAuth 2.1 grants + the advanced ones wired in
 *  Epic 7 (device authorization, token-exchange, CIBA). Legacy `password` (ROPC) and `implicit` are
 *  intentionally absent — both removed in OAuth 2.1 and unsupported by Spring Authorization Server. */
export const GRANT_TYPES = [
  { value: "authorization_code", label: "Authorization code (browser login)" },
  { value: "refresh_token", label: "Refresh token" },
  { value: "client_credentials", label: "Client credentials (service-to-service)" },
  { value: "urn:ietf:params:oauth:grant-type:device_code", label: "Device authorization (CLI / smart TV)" },
  { value: "urn:ietf:params:oauth:grant-type:token-exchange", label: "Token exchange (delegation / impersonation)" },
  { value: "urn:openid:params:grant-type:ciba", label: "CIBA (decoupled / backchannel)" },
];

export const SCOPES = ["openid", "profile", "email", "offline_access"];
