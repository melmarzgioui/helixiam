/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A per-client protocol mapper from the Wave 3 mappers admin API. */
export interface ProtocolMapper {
  mapperId: string;
  realmId: string;
  clientId: string;
  name: string;
  /** `USER_ATTRIBUTE` (copies a user attribute) or `HARDCODED` (emits a literal value). */
  mapperType: string;
  /** The attribute key (USER_ATTRIBUTE) or the literal value (HARDCODED). */
  source: string | null;
  /** The target token claim. */
  claimName: string;
  addToAccessToken: boolean;
  addToIdToken: boolean;
}

export interface MapperWrite {
  name: string;
  mapperType: string;
  source: string | null;
  claimName: string;
  addToAccessToken: boolean;
  addToIdToken: boolean;
}

export interface MapperApi {
  list(realmId: string, clientId: string): Promise<ProtocolMapper[]>;
  create(realmId: string, clientId: string, body: MapperWrite): Promise<ProtocolMapper>;
  update(realmId: string, clientId: string, mapperId: string, body: MapperWrite): Promise<ProtocolMapper>;
  remove(realmId: string, clientId: string, mapperId: string): Promise<void>;
}

/** HTTP-backed client for the Wave 3 per-client protocol mappers REST API. */
export function createMapperHttpClient(baseUrl = ""): MapperApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, clientId: string, mapperId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/clients/${encodeURIComponent(clientId)}/mappers${
      mapperId ? `/${encodeURIComponent(mapperId)}` : ""
    }`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId, clientId) => fetch(url(realmId, clientId)).then(json),
    create: (realmId, clientId, body) =>
      fetch(url(realmId, clientId), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    update: (realmId, clientId, mapperId, body) =>
      fetch(url(realmId, clientId, mapperId), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    remove: (realmId, clientId, mapperId) =>
      fetch(url(realmId, clientId, mapperId), { method: "DELETE" }).then(json).then(() => undefined),
  };
}
