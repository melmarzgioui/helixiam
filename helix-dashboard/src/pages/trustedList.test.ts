/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  DEFAULT_TRUSTED_LIST_FORM,
  TRUSTED_LIST_PRESETS,
  GRANTED,
  RECOGNISED,
  applyPreset,
  formFromTrustedList,
  splitLines,
  signerWarnings,
  statusTone,
  trustedListWrite,
  validateTrustedList,
  type TrustedListForm,
} from "./trustedList";
import type { TrustedList } from "../api/trustedLists";

const SIGNER = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const PID = "http://uri.etsi.org/Svc/Svctype/Provider/PID";

const valid = (over: Partial<TrustedListForm> = {}): TrustedListForm => ({
  ...DEFAULT_TRUSTED_LIST_FORM,
  name: "eudi-test",
  url: "https://trustedlist.example/LOTL.xml",
  signerCertificates: SIGNER,
  serviceTypes: PID,
  ...over,
});

describe("validateTrustedList", () => {
  it("accepts a complete form", () => {
    expect(validateTrustedList(valid())).toEqual({});
  });

  it("requires a name, an https URL, a PEM signer and a service type", () => {
    const e = validateTrustedList({ ...DEFAULT_TRUSTED_LIST_FORM });
    expect(e.name).toBe("tl.err.nameRequired");
    expect(e.url).toBe("tl.err.urlRequired");
    expect(e.signerCertificates).toBe("tl.err.signerRequired");
    expect(e.serviceTypes).toBe("tl.err.typesRequired");
  });

  it("refuses a bad name, plain http, non-PEM signers and non-URI types", () => {
    const e = validateTrustedList(valid({ name: "has space", url: "http://x.example/l.xml",
      signerCertificates: "abc", serviceTypes: "not a uri" }));
    expect(e).toEqual({ name: "tl.err.nameFormat", url: "tl.err.urlHttps", signerCertificates: "tl.err.signerPem",
      serviceTypes: "tl.err.typesFormat" });
    expect(validateTrustedList(valid({ url: "https://user@x.example/l.xml" })).url).toBe("tl.err.urlHttps");
    expect(validateTrustedList(valid({ url: "not a url" })).url).toBe("tl.err.urlHttps");
  });

  it("refuses repeated types and statuses, and requires one status", () => {
    expect(validateTrustedList(valid({ serviceTypes: `${PID}\n${PID}` })).serviceTypes).toBe("tl.err.typesFormat");
    expect(validateTrustedList(valid({ acceptedStatuses: [] })).acceptedStatuses).toBe("tl.err.statusRequired");
  });

  it("checks territories and the grace period", () => {
    expect(validateTrustedList(valid({ territories: "NL, DE" }))).toEqual({});
    expect(validateTrustedList(valid({ territories: "nl, de" }))).toEqual({});
    expect(validateTrustedList(valid({ territories: "NL nl" })).territories).toBe("tl.err.territories");
    expect(validateTrustedList(valid({ territories: "NLD" })).territories).toBe("tl.err.territories");
    expect(validateTrustedList(valid({ territories: "NL NL" })).territories).toBe("tl.err.territories");
    expect(validateTrustedList(valid({ graceHours: "721" })).graceHours).toBe("tl.err.grace");
    expect(validateTrustedList(valid({ graceHours: "-1" })).graceHours).toBe("tl.err.grace");
    expect(validateTrustedList(valid({ graceHours: "1.5" })).graceHours).toBe("tl.err.grace");
    expect(validateTrustedList(valid({ graceHours: "" })).graceHours).toBe("tl.err.grace");
    expect(validateTrustedList(valid({ graceHours: "0" }))).toEqual({});
  });
});

describe("form <-> API", () => {
  it("writes lists from free text and the grace as a number", () => {
    expect(trustedListWrite(valid({ serviceTypes: `${PID}\n urn:x:y ,`, territories: "nl de", graceHours: "48" })))
      .toEqual({
        name: "eudi-test", url: "https://trustedlist.example/LOTL.xml", format: "ETSI_119612_XML",
        signerCertificates: SIGNER, serviceTypes: [PID, "urn:x:y"], acceptedStatuses: [GRANTED, RECOGNISED],
        territories: ["NL", "DE"], graceHours: 48, enabled: true,
      });
  });

  it("reads a stored source back into the form", () => {
    const stored = {
      id: "1", name: "eu", url: "https://x.example/l.json", format: "ETSI_119602_JSON", signerCertificates: SIGNER,
      serviceTypes: [PID, "urn:a"], acceptedStatuses: [], effectiveStatuses: [GRANTED, RECOGNISED], territories: ["NL"],
      graceHours: 12, enabled: false,
    } as unknown as TrustedList;
    expect(formFromTrustedList(stored)).toEqual({
      name: "eu", url: "https://x.example/l.json", format: "ETSI_119602_JSON", signerCertificates: SIGNER,
      serviceTypes: `${PID}\nurn:a`, acceptedStatuses: [GRANTED, RECOGNISED], territories: "NL", graceHours: "12",
      enabled: false,
    });
  });

  it("splits lines on new lines, commas and spaces", () => {
    expect(splitLines(" a, b\nc  d ,\n")).toEqual(["a", "b", "c", "d"]);
  });
});

describe("presets", () => {
  it("fill the URL, format and service types but never a signer", () => {
    for (const p of TRUSTED_LIST_PRESETS) {
      const f = applyPreset(valid({ signerCertificates: "" }), p.id);
      expect(f.url).toBe(p.url);
      expect(f.format).toBe(p.format);
      expect(splitLines(f.serviceTypes)).toEqual(p.serviceTypes);
      expect(f.signerCertificates).toBe("");
      expect(f.url.startsWith("https://")).toBe(true);
    }
  });

  it("an unknown preset changes nothing", () => {
    expect(applyPreset(valid(), "nope")).toEqual(valid());
  });
});

describe("statusTone", () => {
  it("maps each status to a badge tone", () => {
    expect(statusTone("OK")).toBe("success");
    expect(statusTone("FAILING")).toBe("warning");
    expect(statusTone("STALE")).toBe("warning");
    expect(statusTone("EXPIRED")).toBe("danger");
    expect(statusTone("ERROR")).toBe("danger");
    expect(statusTone("NEVER")).toBe("neutral");
    expect(statusTone("DISABLED")).toBe("neutral");
    expect(statusTone("DEGRADED")).toBe("warning");
  });

  it("warns about pinned signers that expired or expire within 30 days", () => {
    const now = new Date("2026-10-15T00:00:00Z");
    const cert = (notAfter: string) => ({ subject: "CN=x", notAfter }) as never;
    expect(signerWarnings([cert("2026-07-04T00:00:00Z"), cert("2026-11-01T00:00:00Z"), cert("2027-10-01T00:00:00Z")], now))
      .toEqual([{ subject: "CN=x", notAfter: "2026-07-04T00:00:00Z", expired: true },
        { subject: "CN=x", notAfter: "2026-11-01T00:00:00Z", expired: false }]);
  });
});
