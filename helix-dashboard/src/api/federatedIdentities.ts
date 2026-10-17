/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { adminJson } from "./adminError";

/** How a federated link was made (server LinkProvenance). */
export type LinkProvenance = "JIT" | "SELF" | "WALLET" | "ADMIN_CONFIRMED" | "LEGACY" | "AUTO" | "UNRESOLVED";

/** One of a user's linked identities (server FederatedLinkTrustService.LinkView). */
export interface LinkedIdentity {
  idpAlias: string;
  externalSubject: string;
  /** The external subject with only its ends shown, for the console. */
  subjectHint?: string;
  createdVia: LinkProvenance | string;
  linkedAt: number | null;
  /** Whether this link may sign the user in while they are an administrator. */
  trustedForAdmins: boolean;
}

export interface LinkedIdentities {
  identities: LinkedIdentity[];
  /** Whether the signed-in admin may confirm links or revoke trust (realm-admin). */
  canManageTrust: boolean;
}

export interface FederatedIdentityApi {
  list(realmId: string, userId: string): Promise<LinkedIdentities>;
  /** Confirms one link: a user may have several links of one provider. */
  confirm(realmId: string, userId: string, alias: string, externalSubject: string): Promise<void>;
  revokeTrust(realmId: string, userId: string, alias: string, externalSubject: string): Promise<void>;
}

/** The actions a realm admin may take on a link: confirm an untrusted one, revoke trust in a trusted one. */
export function linkActions(link: LinkedIdentity, canManageTrust: boolean): Array<"confirm" | "revoke"> {
  if (!canManageTrust) return [];
  return link.trustedForAdmins ? ["revoke"] : ["confirm"];
}

/** The i18n key of a provenance; unknown values read as AUTO (the least trusted), like the server. */
export function provenanceKey(via: string | null | undefined): string {
  const known = ["JIT", "SELF", "WALLET", "ADMIN_CONFIRMED", "LEGACY", "AUTO", "UNRESOLVED"];
  const v = (via ?? "").trim().toUpperCase();
  return `userIdentities.via.${known.includes(v) ? v : "AUTO"}`;
}

export function createFederatedIdentityHttpClient(baseUrl = ""): FederatedIdentityApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, userId: string, suffix = "") =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/users/${encodeURIComponent(userId)}/federated-identities${suffix}`;
  const post = (u: string, externalSubject: string) =>
    fetch(u, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ externalSubject }) })
      .then((r) => adminJson<null>(r)).then(() => undefined);
  return {
    list: (realmId, userId) => fetch(url(realmId, userId)).then((r) => adminJson<LinkedIdentities>(r)),
    confirm: (realmId, userId, alias, externalSubject) =>
      post(url(realmId, userId, `/${encodeURIComponent(alias)}/confirm`), externalSubject),
    revokeTrust: (realmId, userId, alias, externalSubject) =>
      post(url(realmId, userId, `/${encodeURIComponent(alias)}/revoke-trust`), externalSubject),
  };
}

/** The subject as the console shows it: the server's masked hint, else the ends of the subject (never the whole id). */
export function subjectLabel(link: Pick<LinkedIdentity, "externalSubject" | "subjectHint">): string {
  if (link.subjectHint) return link.subjectHint;
  const s = link.externalSubject ?? "";
  return s.length <= 8 ? `…${s.slice(-3)}` : `${s.slice(0, 4)}…${s.slice(-4)}`;
}
