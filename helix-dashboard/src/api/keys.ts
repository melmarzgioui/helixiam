/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A per-realm JWT signing key as the Realm Keys screen shows it (B8). Public material only. */
export interface RealmKey {
  keyId: string;
  algorithm: string;
  status: "ACTIVE" | "ROTATED" | "RETIRED" | string;
  publicKey: string | null;
  createdAt: number | null;
  rotatedAt: number | null;
}

export interface RealmKeyApi {
  list(realmId: string): Promise<RealmKey[]>;
  rotate(realmId: string): Promise<RealmKey>;
  retire(realmId: string, keyId: string): Promise<void>;
}

function json(res: Response) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}
const send = (url: string, method: string) => fetch(url, { method }).then(json);

/** HTTP-backed client for the B8 realm signing-key admin API. */
export function createRealmKeyHttpClient(baseUrl = ""): RealmKeyApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, suffix = "") =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/keys${suffix}`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    rotate: (realmId) => send(url(realmId, "/rotate"), "POST"),
    retire: (realmId, keyId) => send(url(realmId, `/${encodeURIComponent(keyId)}`), "DELETE").then(() => undefined),
  };
}
