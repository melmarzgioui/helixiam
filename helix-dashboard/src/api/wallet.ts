/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AdminApiError, adminJson } from "./adminError";
import type { PidClaimInfo } from "../pages/walletProvider";

/** One certificate's public facts (server CertificateView). */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  ca: boolean;
  selfSigned: boolean;
  dnsNames: string[];
  keyAlgorithm: string;
  /** Why it cannot be a wallet trust anchor; null when it can. */
  trustAnchorProblem: string | null;
}

/** A verifier access key of the realm (server VerifierKeyView). Never carries the private key. */
export interface VerifierKey {
  keyRef: string;
  name: string;
  algorithm: string;
  createdAt: string | null;
  chainLength: number;
  certificate: CertificateInfo;
}

export interface VerifierKeyImport {
  name: string;
  privateKeyPem: string;
  certificateChainPem: string;
}

/** GET /admin/realms/{r}/wallet/metadata. */
export interface WalletMetadata {
  pidClaims: PidClaimInfo[];
  defaultRequestedClaims: string[];
  credentialFormats: string[];
  /** The server runs the dev profile: direct_post and the raw dev key are allowed. */
  devProfile: boolean;
}

/** The admin API behind the EUDI wallet provider form. Errors are AdminApiError (400 carries fieldErrors). */
export interface WalletAdminApi {
  listKeys(realmId: string): Promise<VerifierKey[]>;
  importKey(realmId: string, body: VerifierKeyImport): Promise<VerifierKey>;
  metadata(realmId: string): Promise<WalletMetadata>;
  previewCertificates(realmId: string, pem: string): Promise<CertificateInfo[]>;
}

export function createWalletHttpClient(baseUrl = ""): WalletAdminApi {
  const base = baseUrl.replace(/\/$/, "");
  const realm = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}`;
  const post = (url: string, body: unknown) =>
    fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return {
    listKeys: (realmId) => fetch(`${realm(realmId)}/verifier-keys`).then((r) => adminJson<VerifierKey[]>(r)),
    importKey: (realmId, body) => post(`${realm(realmId)}/verifier-keys`, body).then((r) => adminJson<VerifierKey>(r)),
    metadata: (realmId) => fetch(`${realm(realmId)}/wallet/metadata`).then((r) => adminJson<WalletMetadata>(r)),
    previewCertificates: (realmId, pem) => post(`${realm(realmId)}/wallet/certificates/preview`, { pem })
      .then((r) => adminJson<{ certificates: CertificateInfo[] }>(r)).then((b) => b.certificates),
  };
}

/** The PID claim catalogue as the server lists it (DcqlQueryBuilder), for the memory client and stories. */
export const SAMPLE_PID_CLAIMS: PidClaimInfo[] = [
  "family_name", "given_name", "birthdate", "place_of_birth", "nationalities", "picture", "address.formatted",
  "address.country", "address.region", "address.locality", "address.postal_code", "address.street_address",
  "address.house_number", "personal_administrative_number", "birth_family_name", "birth_given_name", "sex", "email",
  "phone_number", "date_of_expiry", "issuing_authority", "issuing_country", "document_number", "issuing_jurisdiction",
  "date_of_issuance", "trust_anchor", "attestation_legal_category",
].map((name) => ({ name, mdoc: name !== "address.house_number" }));

/** In-memory client for stories and tests. `preview` maps a PEM bundle to certificates (default: one CA root). */
export function createWalletMemoryClient(opts: {
  keys?: VerifierKey[];
  devProfile?: boolean;
  preview?: (pem: string) => CertificateInfo[];
} = {}): WalletAdminApi {
  const keys = [...(opts.keys ?? [])];
  return {
    listKeys: async () => [...keys],
    importKey: async (realmId, body) => {
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(body.name)) {
        throw new AdminApiError("Key name must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'.", 400,
          { name: "Key name must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'." });
      }
      if (keys.some((k) => k.name === body.name)) {
        throw new AdminApiError(`A signing key named '${body.name}' already exists in this realm`, 400,
          { name: `A signing key named '${body.name}' already exists in this realm` });
      }
      const key: VerifierKey = {
        keyRef: `software:${realmId}/${body.name}`, name: body.name, algorithm: "ES256", createdAt: new Date().toISOString(),
        chainLength: 2, certificate: sampleCertificate({ subject: `CN=${body.name}.verifier.example`, dnsNames: [`${body.name}.verifier.example`] }),
      };
      keys.push(key);
      return key;
    },
    metadata: async () => ({
      pidClaims: SAMPLE_PID_CLAIMS, defaultRequestedClaims: ["given_name", "family_name", "birthdate"],
      credentialFormats: ["dc+sd-jwt", "mso_mdoc"], devProfile: !!opts.devProfile,
    }),
    previewCertificates: async (_realmId, pem) => {
      if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
        throw new AdminApiError("The text could not be read as PEM certificates (only BEGIN CERTIFICATE blocks).", 400,
          { pem: "The text could not be read as PEM certificates (only BEGIN CERTIFICATE blocks)." });
      }
      return opts.preview ? opts.preview(pem) : [sampleCertificate({ ca: true, selfSigned: true })];
    },
  };
}

/** A plausible certificate for stories (an EC P-256 verifier leaf unless overridden). */
export function sampleCertificate(over: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    subject: "CN=verifier.example,O=Acme Services B.V.,C=NL",
    issuer: "CN=Acme Access CA,O=Acme Services B.V.,C=NL",
    serialNumber: "1f3a9c",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2027-01-01T00:00:00Z",
    ca: false,
    selfSigned: false,
    dnsNames: ["verifier.example"],
    keyAlgorithm: "EC P-256",
    trustAnchorProblem: null,
    ...over,
  };
}
