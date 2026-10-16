/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  canActivate,
  canAttachCertificate,
  canRetire,
  commonName,
  csrFileName,
  daysUntil,
  expiryTone,
  fieldErrorsFromServer,
  hasPemBlock,
  keyLabel,
  splitDnsNames,
  shortFingerprint,
  stagingState,
  statusLabelKey,
  validateSigningSettings,
  statusTone,
  validateCertificate,
  validateCsr,
  validateImport,
} from "./realmKeys";
import type { RealmKey } from "../api/keys";
import { AdminApiError } from "../api/adminError";

const KEY = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";
const RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
const EC_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----";
const CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const ENC = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE\n-----END ENCRYPTED PRIVATE KEY-----";

const key = (over: Partial<RealmKey> = {}): RealmKey => ({
  keyId: "6f1c2e0a-0000-4000-8000-000000000001",
  algorithm: "RS256",
  status: "ACTIVE",
  publicKey: "MIIB",
  createdAt: Date.UTC(2026, 9, 16),
  rotatedAt: null,
  kid: "abc",
  source: "GENERATED",
  activatedAt: null,
  hasCsr: false,
  publicKeyFingerprint: "AA:BB",
  certificate: null,
  ...over,
});

describe("validateImport", () => {
  it("needs both PEM blocks", () => {
    expect(validateImport({ privateKeyPem: "", certificateChainPem: "" })).toEqual({
      privateKeyPem: "realmKeys.v.keyRequired",
      certificateChainPem: "realmKeys.v.chainRequired",
    });
  });
  it("accepts PKCS#8, PKCS#1 and SEC1 keys with a certificate", () => {
    for (const k of [KEY, RSA_KEY, EC_KEY]) {
      expect(validateImport({ privateKeyPem: k, certificateChainPem: CERT + CERT })).toEqual({});
    }
  });
  it("refuses encrypted keys, a certificate pasted as key, and a key pasted as chain", () => {
    expect(validateImport({ privateKeyPem: ENC, certificateChainPem: CERT }).privateKeyPem).toBe("realmKeys.v.keyEncrypted");
    expect(validateImport({ privateKeyPem: CERT, certificateChainPem: CERT }).privateKeyPem).toBe("realmKeys.v.keyFormat");
    expect(validateImport({ privateKeyPem: KEY, certificateChainPem: KEY }).certificateChainPem).toBe("realmKeys.v.chainFormat");
    expect(validateImport({ privateKeyPem: KEY, certificateChainPem: CERT + KEY }).certificateChainPem).toBe("realmKeys.v.chainFormat");
  });
});

describe("validateCsr", () => {
  it("needs a supported algorithm and a DN subject", () => {
    expect(validateCsr({ algorithm: "RS256", subject: "CN=idp.example.com, O=Example", dnsNames: "" })).toEqual({});
    expect(validateCsr({ algorithm: "HS256", subject: "", dnsNames: "" })).toEqual({
      algorithm: "realmKeys.v.algorithm",
      subject: "realmKeys.v.subjectRequired",
    });
    expect(validateCsr({ algorithm: "ES256", subject: "idp.example.com", dnsNames: "" }).subject).toBe("realmKeys.v.subjectFormat");
  });
  it("checks every DNS name", () => {
    expect(validateCsr({ algorithm: "ES256", subject: "CN=x", dnsNames: "idp.example.com, *.example.com" })).toEqual({});
    expect(validateCsr({ algorithm: "ES256", subject: "CN=x", dnsNames: "idp.example.com bad_name!" }).dnsNames).toBe("realmKeys.v.dnsName");
    expect(validateCsr({ algorithm: "ES256", subject: "CN=x", dnsNames: Array.from({ length: 21 }, (_, i) => `h${i}.ex.com`).join(" ") }).dnsNames)
      .toBe("realmKeys.v.dnsTooMany");
  });
  it("splits DNS names on commas, spaces and new lines", () => {
    expect(splitDnsNames(" a.example.com,b.example.com\nc.example.com ")).toEqual(["a.example.com", "b.example.com", "c.example.com"]);
  });
});

describe("validateCertificate", () => {
  it("needs certificates only", () => {
    expect(validateCertificate({ certificateChainPem: "" }).certificateChainPem).toBe("realmKeys.v.chainRequired");
    expect(validateCertificate({ certificateChainPem: KEY }).certificateChainPem).toBe("realmKeys.v.chainFormat");
    expect(validateCertificate({ certificateChainPem: CERT })).toEqual({});
  });
  it("hasPemBlock recognises block types", () => {
    expect(hasPemBlock(CERT, "CERTIFICATE")).toBe(true);
    expect(hasPemBlock("garbage", "CERTIFICATE")).toBe(false);
  });
});

describe("labels and states", () => {
  it("never uses the key id as the name", () => {
    expect(keyLabel(key({ certificate: cert({ subject: "CN=idp.example.com,O=Example" }) }), "en"))
      .toEqual({ kind: "cn", name: "idp.example.com" });
    const generated = keyLabel(key(), "en");
    expect(generated.kind).toBe("generated");
    expect(JSON.stringify(generated)).not.toContain("6f1c2e0a");
    expect(commonName("O=Example,CN=a\\,b")).toBe("a,b");
    expect(commonName("O=Example")).toBeNull();
  });
  it("maps statuses: ROTATED reads as Retained", () => {
    expect(statusLabelKey("PENDING")).toBe("realmKeys.status.pending");
    expect(statusLabelKey("ROTATED")).toBe("realmKeys.status.retained");
    expect(statusTone("ACTIVE")).toBe("success");
    expect(statusTone("PENDING")).toBe("accent");
    expect(statusTone("RETIRED")).toBe("neutral");
  });
  it("expiry chips: warning under 30 days, danger when expired", () => {
    const now = Date.UTC(2026, 9, 16);
    expect(daysUntil(now + 10 * 86_400_000, now)).toBe(10);
    expect(expiryTone(cert({ expiry: "EXPIRING" }))).toBe("warning");
    expect(expiryTone(cert({ expiry: "EXPIRED" }))).toBe("danger");
    expect(expiryTone(cert({ expiry: "OK" }))).toBeNull();
    expect(expiryTone(null)).toBeNull();
  });
  it("actions follow the lifecycle", () => {
    expect(canActivate(key({ status: "PENDING" }))).toBe(true);
    expect(canActivate(key())).toBe(false);
    expect(canRetire(key())).toBe(false);
    expect(canRetire(key({ algorithm: "ES256" }))).toBe(true); // the EC key may go; the RSA key never
    expect(canRetire(key({ status: "ROTATED" }))).toBe(true);
    expect(canRetire(key({ status: "PENDING" }))).toBe(true);
    expect(canRetire(key({ status: "RETIRED" }))).toBe(false);
    expect(canAttachCertificate(key({ status: "PENDING" }))).toBe(true);
    expect(canAttachCertificate(key({ status: "ROTATED" }))).toBe(false);
  });
  it("names the CSR file after the subject, not the key id", () => {
    expect(csrFileName("CN=idp.example.com, O=Example")).toBe("idp.example.com.csr");
    expect(csrFileName("O=Example")).toBe("realm-signing-key.csr");
  });
  it("maps server field errors onto the form fields", () => {
    const e = new AdminApiError("bad", 400, { certificateChainPem: "The leaf certificate has expired" });
    expect(fieldErrorsFromServer(e, ["privateKeyPem", "certificateChainPem"])).toEqual({
      certificateChainPem: "The leaf certificate has expired",
    });
    expect(fieldErrorsFromServer(new Error("x"), ["a"])).toEqual({});
  });
});

function cert(over: Partial<NonNullable<RealmKey["certificate"]>> = {}): NonNullable<RealmKey["certificate"]> {
  return {
    subject: "CN=idp.example.com",
    issuer: "CN=Example CA",
    serialNumber: "1",
    notBefore: 0,
    notAfter: Date.UTC(2027, 0, 1),
    sha256Fingerprint: "AA",
    selfSigned: false,
    chainLength: 2,
    expiry: "OK",
    ...over,
  };
}

describe("staging", () => {
  const now = Date.UTC(2026, 9, 16, 12, 0);
  it("says how long a pending key has been published and whether it may be activated", () => {
    const k = key({ status: "PENDING", createdAt: now - 3 * 60_000, activatableAt: now + 2 * 60_000 });
    expect(stagingState(k, now)).toEqual({ publishedMinutes: 3, ready: false, waitMinutes: 2 });
    expect(stagingState({ ...k, activatableAt: now - 1 }, now)).toEqual({ publishedMinutes: 3, ready: true, waitMinutes: 0 });
    expect(stagingState(key({ status: "PENDING", createdAt: now - 30_000, activatableAt: now + 270_001 }), now))
      .toEqual({ publishedMinutes: 0, ready: false, waitMinutes: 5 });
    expect(stagingState(key({ status: "PENDING", createdAt: null, activatableAt: null }), now).ready).toBe(true);
  });
});

describe("shortFingerprint", () => {
  it("shows the first 16 hex characters and an ellipsis", () => {
    expect(shortFingerprint("66:A8:B6:40:94:2F:60:33:2E:AD:F1:E6")).toBe("66A8B640942F6033…");
    expect(shortFingerprint("66:A8")).toBe("66A8");
    expect(shortFingerprint(null)).toBe("");
  });
});

describe("validateSigningSettings", () => {
  it("only offers algorithms with an active key", () => {
    expect(validateSigningSettings({ defaultAlg: "RS256", samlAlg: "RS256" }, ["RS256", "PS256"])).toEqual({});
    expect(validateSigningSettings({ defaultAlg: "ES256", samlAlg: "ES256" }, ["RS256", "PS256"])).toEqual({
      defaultAlg: "realmKeys.v.noActiveKey",
      samlAlg: "realmKeys.v.noActiveKey",
    });
    expect(validateSigningSettings({ defaultAlg: "PS256", samlAlg: "PS256" }, ["RS256", "PS256"]).samlAlg)
      .toBe("realmKeys.v.samlAlg");
    expect(validateSigningSettings({ defaultAlg: "HS256", samlAlg: "RS256" }, ["RS256"]).defaultAlg)
      .toBe("realmKeys.v.defaultAlg");
  });
});
