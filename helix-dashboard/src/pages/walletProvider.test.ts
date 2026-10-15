/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  DEFAULT_WALLET_FORM,
  clearEditedErrors,
  commonName,
  expiryState,
  firstErrorSection,
  isWalletProtocol,
  parseHostList,
  sanCheck,
  splitWalletServerErrors,
  validateKeyImport,
  validateWallet,
  walletConfigFromForm,
  walletFormFromConfig,
  walletFormsEqual,
  walletWarnings,
  trustedAuthoritiesEffective,
  releasableClaims,
  walletLinkOptions,
  defaultWalletAlias,
  type WalletForm,
  type WalletValidationContext,
} from "./walletProvider";

const CATALOGUE = [
  { name: "family_name", mdoc: true },
  { name: "given_name", mdoc: true },
  { name: "birthdate", mdoc: true },
  { name: "place_of_birth", mdoc: true },
  { name: "nationalities", mdoc: true },
  { name: "address.house_number", mdoc: false },
  { name: "personal_administrative_number", mdoc: true },
  { name: "issuing_country", mdoc: true },
];

const ANCHOR = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

/** A form that passes every rule in production. */
const valid = (over: Partial<WalletForm> = {}): WalletForm => ({
  ...DEFAULT_WALLET_FORM,
  accessKeyRef: "software:acme/access-2026",
  trustAnchors: ANCHOR,
  ...over,
});

const prod = (over: Partial<WalletValidationContext> = {}): WalletValidationContext => ({
  devProfile: false, pidClaims: CATALOGUE, ...over,
});

describe("isWalletProtocol", () => {
  it("accepts the three protocol names the server accepts, case-insensitively and padded", () => {
    for (const p of ["eudi-wallet", "openid4vp", "wallet", " EUDI-Wallet ", "OpenID4VP"]) expect(isWalletProtocol(p)).toBe(true);
    for (const p of ["oidc", "saml", "eidas", ""]) expect(isWalletProtocol(p)).toBe(false);
  });
});

describe("walletFormFromConfig", () => {
  it("gives the server defaults for an empty map", () => {
    const f = walletFormFromConfig({});
    expect(f.clientIdScheme).toBe("x509_hash");
    expect(f.responseMode).toBe("direct_post.jwt");
    expect(f.credentialFormats).toEqual(["dc+sd-jwt", "mso_mdoc"]);
    expect(f.requestedClaims).toEqual(["given_name", "family_name", "birthdate"]);
    expect(f.subjectStrategy).toBe("ADMINISTRATIVE_NUMBER");
    expect(f.acknowledgeWeakSubject).toBe(false);
    expect(f.onUnavailable).toBe("FAIL_CLOSED");
    expect(f.statusRequired).toBe(false);
    expect(f.minimumLoa).toBe("http://eidas.europa.eu/LoA/high");
    expect(f.transactionTtlSeconds).toBe("");
    expect(f.statusMaxCacheSeconds).toBe("");
    expect(f.revocationChecking).toBe("HARD_FAIL");
    expect(f.acknowledgeRevocationOff).toBe(false);
  });

  it("reads revocationChecking by name, case-insensitively; an unknown value shows the HARD_FAIL default", () => {
    expect(walletFormFromConfig({ revocationChecking: "SOFT_FAIL" }).revocationChecking).toBe("SOFT_FAIL");
    expect(walletFormFromConfig({ revocationChecking: "off" }).revocationChecking).toBe("OFF");
    expect(walletFormFromConfig({ revocationChecking: "maybe" }).revocationChecking).toBe("HARD_FAIL");
  });

  it("reads the OFF acknowledgement, case-insensitively", () => {
    expect(walletFormFromConfig({ revocationChecking: "OFF", "revocationChecking.acknowledgeOff": "TRUE" })
      .acknowledgeRevocationOff).toBe(true);
    expect(walletFormFromConfig({ revocationChecking: "OFF" }).acknowledgeRevocationOff).toBe(false);
  });

  it("reads the stored flat map: JSON lists, enums by name or wire value, booleans", () => {
    const f = walletFormFromConfig({
      accessKeyRef: "software:acme/k", clientIdScheme: "X509_SAN_DNS", clientIdHost: "verifier.example",
      credentialFormats: '["mso_mdoc"]', "pid.requestedClaims": '["given_name","place_of_birth"]',
      "subject.strategy": "attribute_tuple", "subject.acknowledgeWeakSubject": "TRUE",
      "statusList.required": "true", "statusList.onUnavailable": "FAIL_OPEN_WITH_AUDIT",
      "statusList.maxCacheSeconds": "120", "statusList.allowedHosts": '["status.example","s2.example"]',
      responseMode: "DIRECT_POST", transactionTtlSeconds: "600", trustAnchors: ANCHOR,
      minimumLoa: "http://eidas.europa.eu/LoA/substantial",
    });
    expect(f).toMatchObject({
      accessKeyRef: "software:acme/k", clientIdScheme: "x509_san_dns", clientIdHost: "verifier.example",
      credentialFormats: ["mso_mdoc"], requestedClaims: ["given_name", "place_of_birth"],
      subjectStrategy: "ATTRIBUTE_TUPLE", acknowledgeWeakSubject: true, statusRequired: true,
      onUnavailable: "FAIL_OPEN_WITH_AUDIT", statusMaxCacheSeconds: "120", statusAllowedHosts: "status.example, s2.example",
      responseMode: "direct_post", transactionTtlSeconds: "600", trustAnchors: ANCHOR,
      minimumLoa: "http://eidas.europa.eu/LoA/substantial",
    });
  });

  it("never throws on a malformed stored list: it keeps the default", () => {
    expect(walletFormFromConfig({ credentialFormats: "not json" }).credentialFormats).toEqual(["dc+sd-jwt", "mso_mdoc"]);
    expect(walletFormFromConfig({ "pid.requestedClaims": '{"a":1}' }).requestedClaims).toEqual(["given_name", "family_name", "birthdate"]);
  });
});

describe("walletConfigFromForm", () => {
  it("writes the stored flat map the server reads, keeping keys the form does not edit", () => {
    const out = walletConfigFromForm(valid({
      clientIdScheme: "x509_san_dns", clientIdHost: " verifier.example ", statusAllowedHosts: "a.example,\n b.example",
      transactionTtlSeconds: "120", statusMaxCacheSeconds: "60", subjectStrategy: "ATTRIBUTE_TUPLE", acknowledgeWeakSubject: true,
    }), { "pid.sdJwtVcts": '["urn:eudi:pid:1"]', logoUrl: "https://x/logo.svg" });
    expect(out).toEqual({
      "pid.sdJwtVcts": '["urn:eudi:pid:1"]', logoUrl: "https://x/logo.svg",
      accessKeyRef: "software:acme/access-2026", clientIdScheme: "x509_san_dns", clientIdHost: "verifier.example",
      trustAnchors: ANCHOR, revocationChecking: "HARD_FAIL", "revocationChecking.acknowledgeOff": "false",
      credentialFormats: '["dc+sd-jwt","mso_mdoc"]',
      "pid.requestedClaims": '["given_name","family_name","birthdate"]',
      "subject.strategy": "ATTRIBUTE_TUPLE", "subject.acknowledgeWeakSubject": "true",
      minimumLoa: "http://eidas.europa.eu/LoA/high", "statusList.required": "false",
      "statusList.onUnavailable": "FAIL_CLOSED", "statusList.maxCacheSeconds": "60",
      "statusList.allowedHosts": '["a.example","b.example"]', responseMode: "direct_post.jwt", transactionTtlSeconds: "120",
    });
  });

  it("drops blank optional keys (blank means the server default) and a host that x509_hash does not use", () => {
    const out = walletConfigFromForm(valid({ clientIdHost: "old.example" }), {
      transactionTtlSeconds: "500", accessCertificateChain: "old", clientIdHost: "old.example",
    });
    expect(out).not.toHaveProperty("transactionTtlSeconds");
    expect(out).not.toHaveProperty("statusList.maxCacheSeconds");
    expect(out).not.toHaveProperty("accessCertificateChain");
    expect(out).not.toHaveProperty("clientIdHost");
  });

  it("round-trips through walletFormFromConfig", () => {
    const f = valid({ requestedClaims: ["given_name", "address.house_number"], credentialFormats: ["dc+sd-jwt"], statusAllowedHosts: "s.example" });
    expect(walletFormsEqual(walletFormFromConfig(walletConfigFromForm(f, {})), f)).toBe(true);
  });
});

describe("validateWallet (mirrors WalletConfigValidator)", () => {
  it("passes a complete production form", () => {
    expect(validateWallet(valid(), prod())).toEqual({});
  });

  it("requires an access key (accessKeyRef) and trust anchors", () => {
    const e = validateWallet(valid({ accessKeyRef: " ", trustAnchors: "" }), prod());
    expect(e.accessKeyRef).toBe("wallet.err.accessKeyRequired");
    expect(e.trustAnchors).toBe("wallet.err.trustAnchorsRequired");
  });

  it("refuses trust anchors without a PEM certificate block", () => {
    expect(validateWallet(valid({ trustAnchors: "hello" }), prod()).trustAnchors).toBe("wallet.err.trustAnchorsPem");
  });

  it("x509_san_dns needs a host, and the host must be a DNS SAN of the chosen key when the SANs are known", () => {
    expect(validateWallet(valid({ clientIdScheme: "x509_san_dns" }), prod()).clientIdHost).toBe("wallet.err.hostRequired");
    expect(validateWallet(valid({ clientIdScheme: "x509_san_dns", clientIdHost: "other.example" }),
      prod({ keyDnsNames: ["verifier.example"] })).clientIdHost).toBe("wallet.err.hostNotInSan");
    expect(validateWallet(valid({ clientIdScheme: "x509_san_dns", clientIdHost: "Verifier.Example" }),
      prod({ keyDnsNames: ["verifier.example"] }))).toEqual({});
    // SANs not known (key not listed): the server decides.
    expect(validateWallet(valid({ clientIdScheme: "x509_san_dns", clientIdHost: "other.example" }), prod())).toEqual({});
    // x509_hash ignores the host.
    expect(validateWallet(valid({ clientIdHost: "" }), prod())).toEqual({});
  });

  it("needs at least one credential format, only known ones, no repeats", () => {
    expect(validateWallet(valid({ credentialFormats: [] }), prod()).credentialFormats).toBe("wallet.err.formatsRequired");
    expect(validateWallet(valid({ credentialFormats: ["jwt_vc"] }), prod()).credentialFormats).toBe("wallet.err.formatUnknown");
    expect(validateWallet(valid({ credentialFormats: ["mso_mdoc", "mso_mdoc"] }), prod()).credentialFormats).toBe("wallet.err.formatRepeated");
  });

  it("needs at least one known, non-repeated PID claim", () => {
    expect(validateWallet(valid({ requestedClaims: [] }), prod())["pid.requestedClaims"]).toBe("wallet.err.claimsRequired");
    expect(validateWallet(valid({ requestedClaims: ["age_over_18"] }), prod())["pid.requestedClaims"]).toBe("wallet.err.claimUnknown");
    expect(validateWallet(valid({ requestedClaims: ["given_name", "given_name"] }), prod())["pid.requestedClaims"]).toBe("wallet.err.claimRepeated");
  });

  it("refuses mso_mdoc whenever none of the claims has an mdoc element, also with dc+sd-jwt (the query builder's rule)", () => {
    expect(validateWallet(valid({ credentialFormats: ["dc+sd-jwt", "mso_mdoc"], requestedClaims: ["address.house_number"] }), prod())["pid.requestedClaims"])
      .toBe("wallet.err.claimsNoMdoc");
    expect(validateWallet(valid({ credentialFormats: ["dc+sd-jwt"], requestedClaims: ["address.house_number"] }), prod())).toEqual({});
  });

  it("refuses an mdoc-only request whose claims have no mdoc element", () => {
    expect(validateWallet(valid({ credentialFormats: ["mso_mdoc"], requestedClaims: ["address.house_number"] }), prod())["pid.requestedClaims"])
      .toBe("wallet.err.claimsNoMdoc");
    expect(validateWallet(valid({ credentialFormats: ["mso_mdoc"], requestedClaims: ["address.house_number", "given_name"] }), prod())).toEqual({});
  });

  it("ATTRIBUTE_TUPLE needs acknowledgeWeakSubject (reported on subject.strategy, as the server does)", () => {
    expect(validateWallet(valid({ subjectStrategy: "ATTRIBUTE_TUPLE" }), prod())["subject.strategy"]).toBe("wallet.err.ackRequired");
    expect(validateWallet(valid({ subjectStrategy: "ATTRIBUTE_TUPLE", acknowledgeWeakSubject: true }), prod())).toEqual({});
  });

  // pentest-a INFO-1: turning off issuer-cert revocation checking must require an explicit confirmation.
  it("revocationChecking=OFF needs acknowledgeRevocationOff (reported on revocationChecking)", () => {
    expect(validateWallet(valid({ revocationChecking: "OFF" }), prod()).revocationChecking).toBe("wallet.err.revocationOffAckRequired");
    expect(validateWallet(valid({ revocationChecking: "OFF", acknowledgeRevocationOff: true }), prod())).toEqual({});
    // HARD_FAIL/SOFT_FAIL never need it, even if the checkbox was left checked from a previous OFF selection.
    expect(validateWallet(valid({ revocationChecking: "HARD_FAIL", acknowledgeRevocationOff: false }), prod())).toEqual({});
    expect(validateWallet(valid({ revocationChecking: "SOFT_FAIL", acknowledgeRevocationOff: false }), prod())).toEqual({});
  });

  it("direct_post (unencrypted) only in the dev profile", () => {
    expect(validateWallet(valid({ responseMode: "direct_post" }), prod()).responseMode).toBe("wallet.err.directPostDevOnly");
    expect(validateWallet(valid({ responseMode: "direct_post" }), prod({ devProfile: true }))).toEqual({});
  });

  it("TTL is a whole number of seconds between 60 and 900; blank is the default", () => {
    for (const bad of ["59", "901", "5m", "1.5", "-60"]) {
      expect(validateWallet(valid({ transactionTtlSeconds: bad }), prod()).transactionTtlSeconds).toBe("wallet.err.ttlRange");
    }
    for (const ok of ["", "60", " 900 ", "300"]) expect(validateWallet(valid({ transactionTtlSeconds: ok }), prod())).toEqual({});
  });

  it("status-list cache is 0-900 seconds and allowed hosts are bare host names", () => {
    expect(validateWallet(valid({ statusMaxCacheSeconds: "901" }), prod())["statusList.maxCacheSeconds"]).toBe("wallet.err.cacheRange");
    expect(validateWallet(valid({ statusMaxCacheSeconds: "0" }), prod())).toEqual({});
    for (const bad of ["https://status.example", "status.example:443", "status.example/list", "-bad.example"]) {
      expect(validateWallet(valid({ statusAllowedHosts: bad }), prod())["statusList.allowedHosts"]).toBe("wallet.err.allowedHosts");
    }
    expect(validateWallet(valid({ statusAllowedHosts: "status.example, s-2.example" }), prod())).toEqual({});
  });

  it("minimumLoa must be on the eIDAS ladder", () => {
    expect(validateWallet(valid({ minimumLoa: "loa3" }), prod()).minimumLoa).toBe("wallet.err.loa");
  });

  describe("the dev-only raw private key (accessCertificatePrivateKey)", () => {
    it("outside dev a stored or new one is refused: import it and set accessKeyRef", () => {
      expect(validateWallet(valid({ accessKeyRef: "" }), prod({ devKey: { stored: true, pending: false, clearing: false } })).accessCertificatePrivateKey)
        .toBe("wallet.err.devKeyOutsideDev");
      // Removing it clears the error; the key ref is then required.
      const removed = validateWallet(valid({ accessKeyRef: "" }), prod({ devKey: { stored: true, pending: false, clearing: true } }));
      expect(removed.accessCertificatePrivateKey).toBeUndefined();
      expect(removed.accessKeyRef).toBe("wallet.err.accessKeyRequired");
    });

    it("in dev it replaces accessKeyRef, needs the chain, and never goes together with a key ref", () => {
      const dev = (stored: boolean, pending: boolean) => prod({ devProfile: true, devKey: { stored, pending, clearing: false } });
      expect(validateWallet(valid({ accessKeyRef: "", accessCertificateChain: ANCHOR }), dev(false, true))).toEqual({});
      expect(validateWallet(valid({ accessKeyRef: "" }), dev(true, false)).accessCertificateChain).toBe("wallet.err.chainRequired");
      expect(validateWallet(valid({ accessCertificateChain: ANCHOR }), dev(true, false)).accessCertificatePrivateKey).toBe("wallet.err.keyRefAndDevKey");
    });
  });
});

describe("issuer certificate revocation (revocationChecking)", () => {
  it("is written to the stored map and survives a round trip", () => {
    for (const mode of ["OFF", "SOFT_FAIL", "HARD_FAIL"] as const) {
      const stored = walletConfigFromForm(valid({ revocationChecking: mode }));
      expect(stored.revocationChecking).toBe(mode);
      expect(walletFormFromConfig(stored).revocationChecking).toBe(mode);
    }
  });

  it("is a form key, so a stale stored value is replaced, not carried over", () => {
    const stored = walletConfigFromForm(valid({ revocationChecking: "HARD_FAIL" }), { revocationChecking: "OFF" });
    expect(stored.revocationChecking).toBe("HARD_FAIL");
  });

  it("warns when revocation is relaxed (SOFT_FAIL) or off, never for HARD_FAIL", () => {
    expect(walletWarnings(valid({ revocationChecking: "HARD_FAIL" }))).not.toContain("revocationSoftFail");
    expect(walletWarnings(valid({ revocationChecking: "HARD_FAIL" }))).not.toContain("revocationOff");
    expect(walletWarnings(valid({ revocationChecking: "SOFT_FAIL" }))).toContain("revocationSoftFail");
    expect(walletWarnings(valid({ revocationChecking: "OFF" }))).toContain("revocationOff");
  });

  it("server errors on revocationChecking land on the credentials section", () => {
    expect(firstErrorSection({ revocationChecking: "x" })).toBe("credentials");
  });
});

describe("walletWarnings", () => {
  it("warns above five claims", () => {
    expect(walletWarnings(valid({ requestedClaims: ["a", "b", "c", "d", "e"] }))).not.toContain("manyClaims");
    expect(walletWarnings(valid({ requestedClaims: ["a", "b", "c", "d", "e", "f"] }))).toContain("manyClaims");
  });

  it("warns when the administrative number is requested without the ADMINISTRATIVE_NUMBER strategy", () => {
    const claims = ["given_name", "personal_administrative_number"];
    expect(walletWarnings(valid({ requestedClaims: claims }))).not.toContain("adminNumberWithoutStrategy");
    expect(walletWarnings(valid({ requestedClaims: claims, subjectStrategy: "ATTRIBUTE_TUPLE" }))).toContain("adminNumberWithoutStrategy");
  });

  it("warns that toggling place_of_birth on an existing provider orphans tuple links (not on a new one)", () => {
    const original = valid();
    expect(walletWarnings(valid({ requestedClaims: [...original.requestedClaims, "place_of_birth"] }), original)).toContain("placeOfBirthOrphans");
    expect(walletWarnings(valid({ requestedClaims: [...original.requestedClaims, "place_of_birth"] }))).not.toContain("placeOfBirthOrphans");
    const withPob = valid({ requestedClaims: ["given_name", "place_of_birth"] });
    expect(walletWarnings(valid({ requestedClaims: ["given_name"] }), withPob)).toContain("placeOfBirthOrphans");
    expect(walletWarnings(valid({ requestedClaims: ["place_of_birth", "given_name"] }), withPob)).not.toContain("placeOfBirthOrphans");
  });

  it("flags the weak tuple subject and fail-open status checking", () => {
    expect(walletWarnings(valid({ subjectStrategy: "ATTRIBUTE_TUPLE" }))).toContain("weakTuple");
    expect(walletWarnings(valid({ onUnavailable: "FAIL_OPEN_WITH_AUDIT" }))).toContain("failOpen");
    expect(walletWarnings(valid())).toEqual([]);
  });
});

describe("sanCheck", () => {
  it("compares the host with the leaf's DNS SANs, case-insensitively", () => {
    expect(sanCheck("", ["a.example"])).toBe("none");
    expect(sanCheck("a.example", undefined)).toBe("unknown");
    expect(sanCheck(" A.Example ", ["a.example"])).toBe("match");
    expect(sanCheck("b.example", ["a.example"])).toBe("mismatch");
  });
});

describe("parseHostList", () => {
  it("splits on commas, spaces and new lines", () => {
    expect(parseHostList(" a.example,b.example\n c.example ,, ")).toEqual(["a.example", "b.example", "c.example"]);
    expect(parseHostList("")).toEqual([]);
  });
});

describe("splitWalletServerErrors", () => {
  it("maps the admin API's config.<field> keys onto the form fields; the rest goes to a banner", () => {
    const { fields, other } = splitWalletServerErrors({
      "config.clientIdHost": "clientIdHost must be a DNS subjectAltName of the access certificate (x509_san_dns)",
      "config.clearAccessCertificatePrivateKey": "Give a new accessCertificatePrivateKey or clear the stored one, not both.",
      displayName: "Display name is required.",
      "config.limits.maxJwtBytes": "limits.maxJwtBytes must be positive",
      protocol: "nope",
    });
    expect(fields).toEqual({
      clientIdHost: "clientIdHost must be a DNS subjectAltName of the access certificate (x509_san_dns)",
      accessCertificatePrivateKey: "Give a new accessCertificatePrivateKey or clear the stored one, not both.",
      displayName: "Display name is required.",
    });
    expect(other).toEqual(["limits.maxJwtBytes must be positive", "nope"]);
  });
});

describe("firstErrorSection", () => {
  it("names the form section of the first error, in the form's order", () => {
    expect(firstErrorSection({ transactionTtlSeconds: "x", trustAnchors: "y" })).toBe("credentials");
    expect(firstErrorSection({ responseMode: "x" })).toBe("policies");
    expect(firstErrorSection({ clientIdHost: "x", displayName: "y" })).toBe("general");
    expect(firstErrorSection({ accessKeyRef: "x" })).toBe("access");
    expect(firstErrorSection({})).toBeNull();
  });
});

describe("commonName", () => {
  it("reads the CN of an RFC 2253 DN, with escapes, else the DN", () => {
    expect(commonName("CN=verifier.example,O=Acme,C=NL")).toBe("verifier.example");
    expect(commonName("O=Acme,CN=Acme\\, Inc. Root")).toBe("Acme, Inc. Root");
    expect(commonName("O=Acme,C=NL")).toBe("O=Acme,C=NL");
  });
});

describe("expiryState", () => {
  const now = new Date("2026-10-12T00:00:00Z");
  it("is expired, soon (30 days) or ok", () => {
    expect(expiryState("2026-10-11T00:00:00Z", now)).toBe("expired");
    expect(expiryState("2026-11-01T00:00:00Z", now)).toBe("soon");
    expect(expiryState("2027-10-12T00:00:00Z", now)).toBe("ok");
  });
});

describe("validateKeyImport", () => {
  const ok = { name: "access-2026", privateKeyPem: "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----", certificateChainPem: ANCHOR };
  it("passes a complete import", () => {
    expect(validateKeyImport(ok)).toEqual({});
    expect(validateKeyImport({ ...ok, privateKeyPem: "-----BEGIN EC PRIVATE KEY-----\nAA" })).toEqual({});
  });
  it("requires each field and checks its shape, before anything is sent", () => {
    expect(validateKeyImport({ name: "", privateKeyPem: "", certificateChainPem: "" })).toEqual({
      name: "wallet.import.err.nameRequired", privateKeyPem: "wallet.import.err.keyRequired",
      certificateChainPem: "wallet.import.err.chainRequired",
    });
    expect(validateKeyImport({ ...ok, name: "bad/name" }).name).toBe("wallet.import.err.nameFormat");
    expect(validateKeyImport({ ...ok, name: "x".repeat(65) }).name).toBe("wallet.import.err.nameFormat");
    expect(validateKeyImport({ ...ok, privateKeyPem: "-----BEGIN RSA PRIVATE KEY-----" }).privateKeyPem).toBe("wallet.import.err.keyPem");
    expect(validateKeyImport({ ...ok, certificateChainPem: "x" }).certificateChainPem).toBe("wallet.import.err.chainPem");
  });
});

describe("clearEditedErrors", () => {
  it("drops the error of the field a change touches, and keeps the others", () => {
    const errors = { clientIdHost: "not a SAN", "pid.requestedClaims": "x", "subject.strategy": "ack" };
    expect(clearEditedErrors(errors, { clientIdHost: "a.example" })).toEqual({ "pid.requestedClaims": "x", "subject.strategy": "ack" });
    expect(clearEditedErrors(errors, { requestedClaims: [] })).toEqual({ clientIdHost: "not a SAN", "subject.strategy": "ack" });
    expect(clearEditedErrors(errors, { acknowledgeWeakSubject: true })).toEqual({ clientIdHost: "not a SAN", "pid.requestedClaims": "x" });
    expect(clearEditedErrors(errors, { minimumLoa: "x" })).toBe(errors);
  });
});

describe("DCQL trusted_authorities (HAIP §5)", () => {
  it("reads an unset value as the default, and true/false as on/off", () => {
    expect(walletFormFromConfig({}).trustedAuthorities).toBe("default");
    expect(walletFormFromConfig({ "dcql.trustedAuthorities": "TRUE" }).trustedAuthorities).toBe("on");
    expect(walletFormFromConfig({ "dcql.trustedAuthorities": "false" }).trustedAuthorities).toBe("off");
    expect(walletFormFromConfig({ "dcql.trustedAuthorities": "maybe" }).trustedAuthorities).toBe("default");
  });

  it("writes on/off, and leaves the key out for the default (which the server decides)", () => {
    expect(walletConfigFromForm(valid({ trustedAuthorities: "on" }))["dcql.trustedAuthorities"]).toBe("true");
    expect(walletConfigFromForm(valid({ trustedAuthorities: "off" }))["dcql.trustedAuthorities"]).toBe("false");
    const stored = walletConfigFromForm(valid({ trustedAuthorities: "default" }), { "dcql.trustedAuthorities": "false" });
    expect(stored).not.toHaveProperty("dcql.trustedAuthorities");
  });

  it("is on by default under the HAIP profile (x509_hash + direct_post.jwt) only, like the server", () => {
    expect(trustedAuthoritiesEffective(valid({ trustedAuthorities: "default" }))).toBe(true);
    expect(trustedAuthoritiesEffective(valid({ trustedAuthorities: "default", clientIdScheme: "x509_san_dns" }))).toBe(false);
    expect(trustedAuthoritiesEffective(valid({ trustedAuthorities: "default", responseMode: "direct_post" }))).toBe(false);
    expect(trustedAuthoritiesEffective(valid({ trustedAuthorities: "on", clientIdScheme: "x509_san_dns" }))).toBe(true);
    expect(trustedAuthoritiesEffective(valid({ trustedAuthorities: "off" }))).toBe(false);
  });
});


describe("trusted lists on the wallet form", () => {
  const PID = "http://uri.etsi.org/Svc/Svctype/Provider/PID";

  it("reads and writes the sources and the service-type filter, only when set", () => {
    const f = walletFormFromConfig({ "trustedLists.sources": '["eu-pid","nl"]', "trustedLists.serviceTypes": `["${PID}"]` });
    expect(f.trustedListSources).toEqual(["eu-pid", "nl"]);
    expect(f.trustedListServiceTypes).toBe(PID);
    const out = walletConfigFromForm(valid({ trustedListSources: ["eu-pid"], trustedListServiceTypes: `${PID}\n` }));
    expect(out["trustedLists.sources"]).toBe('["eu-pid"]');
    expect(out["trustedLists.serviceTypes"]).toBe(`["${PID}"]`);
    const none = walletConfigFromForm(valid(), { "trustedLists.sources": '["old"]', "trustedLists.serviceTypes": '["x"]' });
    expect(none).not.toHaveProperty("trustedLists.sources");
    expect(none).not.toHaveProperty("trustedLists.serviceTypes");
  });

  it("makes pasted anchors optional once a trusted list is chosen", () => {
    expect(validateWallet(valid({ trustAnchors: "", trustedListSources: ["eu-pid"] }), prod())).toEqual({});
    expect(validateWallet(valid({ trustedListSources: ["eu-pid"] }), prod())).toEqual({});
    expect(validateWallet(valid({ trustAnchors: "hello", trustedListSources: ["eu-pid"] }), prod()).trustAnchors)
      .toBe("wallet.err.trustAnchorsPem");
  });

  it("needs pasted anchors or a trusted list", () => {
    expect(validateWallet(valid({ trustAnchors: "", trustedListSources: [] }), prod()).trustAnchors)
      .toBe("wallet.err.trustAnchorsRequired");
  });

  it("checks the service-type filter and unknown sources", () => {
    expect(validateWallet(valid({ trustedListSources: ["eu-pid"], trustedListServiceTypes: "not a uri" }), prod())
      ["trustedLists.serviceTypes"]).toBe("wallet.err.trustedListTypes");
    expect(validateWallet(valid({ trustedListSources: ["gone"] }), prod({ trustedListNames: ["eu-pid"] }))
      ["trustedLists.sources"]).toBe("wallet.err.trustedListUnknown");
    expect(validateWallet(valid({ trustedListSources: ["eu-pid"] }), prod({ trustedListNames: ["eu-pid"] }))).toEqual({});
  });

  it("puts server errors on the trusted-list fields in the credentials section", () => {
    const { fields, other } = splitWalletServerErrors({ "config.trustedLists.sources": "unknown" });
    expect(fields).toEqual({ "trustedLists.sources": "unknown" });
    expect(other).toEqual([]);
    expect(firstErrorSection({ "trustedLists.serviceTypes": "x" })).toBe("credentials");
    expect(clearEditedErrors({ "trustedLists.sources": "x" }, { trustedListSources: [] })).toEqual({});
  });
});

describe("verify-only mode (subject.strategy NONE)", () => {
  const RELEASABLE = CATALOGUE.map((c) => ({ ...c, releasable: c.name !== "personal_administrative_number" && c.name !== "address.house_number" ? true : c.name === "address.house_number" }));
  const verify = (over: Partial<WalletForm> = {}): WalletForm => valid({
    subjectStrategy: "NONE",
    verifyLinkedProvider: "eudi-wallet",
    requestedClaims: ["birthdate", "nationalities"],
    verifyReleasedClaims: ["age_over_18", "nationalities"],
    ...over,
  });
  const ctx = (over: Partial<WalletValidationContext> = {}) => prod({ pidClaims: RELEASABLE, alias: "eudi-verify", ...over });

  it("reads and writes verify.linkedProvider and verify.releasedClaims, only for NONE", () => {
    const form = walletFormFromConfig({ "subject.strategy": "NONE", "verify.linkedProvider": " eudi-wallet ",
      "verify.releasedClaims": "[\"age_over_18\"]" });
    expect(form.subjectStrategy).toBe("NONE");
    expect(form.verifyLinkedProvider).toBe("eudi-wallet");
    expect(form.verifyReleasedClaims).toEqual(["age_over_18"]);
    const out = walletConfigFromForm(verify());
    expect(out["subject.strategy"]).toBe("NONE");
    expect(out["subject.acknowledgeWeakSubject"]).toBe("false");
    expect(out["verify.linkedProvider"]).toBe("eudi-wallet");
    expect(out["verify.releasedClaims"]).toBe("[\"age_over_18\",\"nationalities\"]");
    const login = walletConfigFromForm(verify({ subjectStrategy: "ADMINISTRATIVE_NUMBER" }),
      { "verify.linkedProvider": "stale", "verify.releasedClaims": "[\"x\"]" });
    expect(login).not.toHaveProperty("verify.linkedProvider");
    expect(login).not.toHaveProperty("verify.releasedClaims");
    expect(walletFormFromConfig(walletConfigFromForm(verify()))).toEqual(verify());
  });

  it("defaults to nothing released and no linked connection", () => {
    expect(DEFAULT_WALLET_FORM.verifyLinkedProvider).toBe("");
    expect(DEFAULT_WALLET_FORM.verifyReleasedClaims).toEqual([]);
    expect(walletConfigFromForm(verify({ verifyReleasedClaims: [] }))).not.toHaveProperty("verify.releasedClaims");
  });

  it("passes a complete verify-only form", () => {
    expect(validateWallet(verify(), ctx())).toEqual({});
    expect(validateWallet(verify({ verifyReleasedClaims: [] }), ctx())).toEqual({});
  });

  it("needs a linked sign-in connection: an alias, not itself, one of the realm's wallet connections when known", () => {
    expect(validateWallet(verify({ verifyLinkedProvider: " " }), ctx())["verify.linkedProvider"]).toBe("wallet.err.linkedRequired");
    expect(validateWallet(verify({ verifyLinkedProvider: "not an alias" }), ctx())["verify.linkedProvider"]).toBe("wallet.err.linkedAlias");
    expect(validateWallet(verify({ verifyLinkedProvider: "eudi-verify" }), ctx())["verify.linkedProvider"]).toBe("wallet.err.linkedSelf");
    expect(validateWallet(verify(), ctx({ linkedAliases: ["other"] }))["verify.linkedProvider"]).toBe("wallet.err.linkedUnknown");
    expect(validateWallet(verify(), ctx({ linkedAliases: ["eudi-wallet"] }))).toEqual({});
    expect(validateWallet(verify(), ctx({ linkedAliases: [] }))["verify.linkedProvider"]).toBe("wallet.err.linkedNone");
    expect(validateWallet(verify({ verifyLinkedProvider: "" }), ctx({ linkedAliases: [] }))["verify.linkedProvider"])
      .toBe("wallet.err.linkedNone");
  });

  it("releases only requested releasable claims and age thresholds 1-150 with birthdate requested, no repeats", () => {
    const err = (released: string[], requested = ["birthdate", "nationalities", "personal_administrative_number"]) =>
      validateWallet(verify({ requestedClaims: requested, verifyReleasedClaims: released }), ctx())["verify.releasedClaims"];
    expect(err(["given_name"])).toBe("wallet.err.releasedNotRequested");
    expect(err(["personal_administrative_number"])).toBe("wallet.err.releasedNotReleasable");
    expect(err(["age_over_18"], ["nationalities"])).toBe("wallet.err.releasedAgeNeedsBirthdate");
    for (const bad of ["age_over_0", "age_over_151", "age_over_018", "age_over_x"]) expect(err([bad])).toBe("wallet.err.releasedAge");
    expect(err(["age_over_18", "age_over_18"])).toBe("wallet.err.releasedRepeated");
    expect(err(["age_over_1", "age_over_150", "birthdate"])).toBeUndefined();
  });

  it("refuses the weak-subject acknowledgement with NONE (the linked connection decides)", () => {
    expect(validateWallet(verify({ acknowledgeWeakSubject: true }), ctx())["subject.strategy"]).toBe("wallet.err.verifyNoAck");
  });

  it("server errors on the verify settings land on the policies section", () => {
    const split = splitWalletServerErrors({ "config.verify.linkedProvider": "m1", "config.verify.releasedClaims": "m2" });
    expect(split.fields).toEqual({ "verify.linkedProvider": "m1", "verify.releasedClaims": "m2" });
    expect(firstErrorSection(split.fields)).toBe("policies");
    expect(clearEditedErrors(split.fields, { verifyLinkedProvider: "x" })).toEqual({ "verify.releasedClaims": "m2" });
    expect(clearEditedErrors(split.fields, { verifyReleasedClaims: [] })).toEqual({ "verify.linkedProvider": "m1" });
  });

  it("releasableClaims lists the requested releasable claims, then the age thresholds when birthdate is requested", () => {
    expect(releasableClaims(verify({ requestedClaims: ["nationalities", "birthdate", "personal_administrative_number"] }), RELEASABLE))
      .toEqual(["nationalities", "birthdate", "age_over_16", "age_over_18", "age_over_21", "age_over_65"]);
    expect(releasableClaims(verify({ requestedClaims: ["nationalities"], verifyReleasedClaims: ["age_over_30"] }), RELEASABLE))
      .toEqual(["nationalities", "age_over_30"]);
  });

  it("does not warn about the admin number for a verify-only connection (it binds the wallet)", () => {
    expect(walletWarnings(verify({ requestedClaims: ["birthdate", "personal_administrative_number"] })))
      .not.toContain("adminNumberWithoutStrategy");
  });
});

describe("walletLinkOptions", () => {
  it("offers the realm's other wallet sign-in connections, never a verify-only one or itself", () => {
    const idp = (alias: string, protocol: string, config: Record<string, string> = {}) =>
      ({ alias, protocol, displayName: alias.toUpperCase(), config });
    expect(walletLinkOptions([
      idp("eudi-wallet", "eudi-wallet"), idp("w2", "OpenID4VP", { "subject.strategy": "ATTRIBUTE_TUPLE" }),
      idp("digid", "saml"), idp("eudi-verify", "eudi-wallet", { "subject.strategy": "none" }), idp("self", "wallet"),
    ], "self")).toEqual([{ alias: "eudi-wallet", displayName: "EUDI-WALLET" }, { alias: "w2", displayName: "W2" }]);
  });
});

describe("flow engine warning (verify-only)", () => {
  it("warns about a verify-only connection when the server's flow engine is off", () => {
    const verifyForm = valid({ subjectStrategy: "NONE", verifyLinkedProvider: "eudi-wallet" });
    expect(walletWarnings(verifyForm, null, { flowEngineEnabled: false })).toContain("flowEngineOff");
    expect(walletWarnings(verifyForm, null, { flowEngineEnabled: true })).not.toContain("flowEngineOff");
    expect(walletWarnings(verifyForm)).not.toContain("flowEngineOff");
    expect(walletWarnings(valid(), null, { flowEngineEnabled: false })).not.toContain("flowEngineOff");
  });
});

describe("defaultWalletAlias", () => {
  it("is eudi-wallet, else the first free eudi-wallet-N; eudi-wallet-verify for a verify-only connection", () => {
    expect(defaultWalletAlias([], false)).toBe("eudi-wallet");
    expect(defaultWalletAlias(["eudi-wallet"], false)).toBe("eudi-wallet-2");
    expect(defaultWalletAlias(["eudi-wallet", "eudi-wallet-2"], false)).toBe("eudi-wallet-3");
    expect(defaultWalletAlias(["eudi-wallet"], true)).toBe("eudi-wallet-verify");
    expect(defaultWalletAlias(["eudi-wallet-verify"], true)).toBe("eudi-wallet-verify-2");
  });

  it("never makes the existing sign-in connection look like itself in the link options", () => {
    const existing = [{ alias: "eudi-wallet", protocol: "eudi-wallet", displayName: "Wallet", config: {} }];
    const own = defaultWalletAlias(existing.map((p) => p.alias), true);
    expect(walletLinkOptions(existing, own)).toEqual([{ alias: "eudi-wallet", displayName: "Wallet" }]);
  });
});
