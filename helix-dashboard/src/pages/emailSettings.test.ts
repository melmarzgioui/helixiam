/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import type { MessagingProvider } from "../api/messaging";
import {
  defaultPort,
  describeTestResult,
  formFromProvider,
  initialEmailDriver,
  isDirty,
  otherEnabledEmailDrivers,
  resolveTlsMode,
  setPort,
  setTlsMode,
  splitServerErrors,
  toWrite,
  validateEmailForm,
  validateTestRecipient,
  isEmailAddress,
  type EmailForm,
} from "./emailSettings";

const provider = (over: Partial<MessagingProvider>): MessagingProvider => ({
  id: "p1", realmId: "acme", channel: "EMAIL", driver: "SMTP", enabled: true,
  fromAddress: "no-reply@example.com", fromName: "Acme", config: {}, secretSet: false, ...over,
});

const smtp = (over: Partial<EmailForm> = {}): EmailForm => ({
  ...formFromProvider("SMTP"),
  fromAddress: "no-reply@example.com",
  config: { host: "smtp.example.com", tlsMode: "STARTTLS_REQUIRED", port: "587" },
  ...over,
});

const cloudflare = (over: Partial<EmailForm> = {}): EmailForm => ({
  ...formFromProvider("CLOUDFLARE"),
  fromAddress: "no-reply@example.com",
  config: { accountId: "0123abcd" },
  secret: { stored: false, replacing: false, value: "cf-token" },
  ...over,
});

describe("resolveTlsMode (mirrors SmtpTlsMode.resolve)", () => {
  it("prefers tlsMode, case-insensitively", () => {
    expect(resolveTlsMode({ tlsMode: "implicit", starttls: "true" })).toBe("IMPLICIT");
  });
  it("maps the deprecated starttls boolean", () => {
    expect(resolveTlsMode({ starttls: "true" })).toBe("STARTTLS_REQUIRED");
    expect(resolveTlsMode({ starttls: "FALSE" })).toBe("STARTTLS_OPTIONAL");
  });
  it("defaults to STARTTLS_REQUIRED", () => {
    expect(resolveTlsMode({})).toBe("STARTTLS_REQUIRED");
    expect(resolveTlsMode({ starttls: "maybe" })).toBe("STARTTLS_REQUIRED");
    expect(resolveTlsMode({ tlsMode: "bogus" })).toBe("STARTTLS_REQUIRED");
  });
  it("gives 465 for implicit TLS and 587 otherwise", () => {
    expect(defaultPort("IMPLICIT")).toBe(465);
    expect(defaultPort("STARTTLS_REQUIRED")).toBe(587);
    expect(defaultPort("STARTTLS_OPTIONAL")).toBe(587);
    expect(defaultPort("NONE")).toBe(587);
  });
});

describe("formFromProvider", () => {
  it("maps a legacy starttls config to tlsMode and drops the deprecated key", () => {
    const f = formFromProvider("SMTP", provider({ config: { host: "mail", starttls: "false", port: "25" } }));
    expect(f.config.tlsMode).toBe("STARTTLS_OPTIONAL");
    expect(f.config).not.toHaveProperty("starttls");
    expect(f.config.port).toBe("25");
    expect(f.portTouched).toBe(true);
  });

  it("fills the default port for the mode when none is stored, as not typed", () => {
    const f = formFromProvider("SMTP", provider({ config: { host: "mail", tlsMode: "IMPLICIT" } }));
    expect(f.config.port).toBe("465");
    expect(f.portTouched).toBe(false);
  });

  it("treats a stored port equal to the mode default as not typed", () => {
    expect(formFromProvider("SMTP", provider({ config: { host: "m", port: "587" } })).portTouched).toBe(false);
  });

  it("never carries a secret, only whether one is stored", () => {
    const f = formFromProvider("CLOUDFLARE", provider({ driver: "CLOUDFLARE", secretSet: true, config: { accountId: "a" } }));
    expect(f.secret).toEqual({ stored: true, replacing: false, value: "" });
  });

  it("starts a new provider from the carried from address and name", () => {
    const f = formFromProvider("CLOUDFLARE", undefined, { fromAddress: "a@b.co", fromName: "B" });
    expect(f.fromAddress).toBe("a@b.co");
    expect(f.fromName).toBe("B");
    expect(f.enabled).toBe(true);
    expect(f.secret.stored).toBe(false);
  });

  it("starts a new provider off when asked (another provider is already on)", () => {
    expect(formFromProvider("LOG", undefined, undefined, false).enabled).toBe(false);
    expect(formFromProvider("LOG", provider({ driver: "LOG", enabled: true }), undefined, false).enabled).toBe(true);
  });

  it("starts a new SMTP provider on STARTTLS_REQUIRED and port 587", () => {
    const f = formFromProvider("SMTP");
    expect(f.config.tlsMode).toBe("STARTTLS_REQUIRED");
    expect(f.config.port).toBe("587");
  });
});

describe("port follows the TLS mode unless the user typed one", () => {
  it("switches 587 → 465 → 587 while the port is automatic", () => {
    let f = smtp();
    f = setTlsMode(f, "IMPLICIT");
    expect(f.config.port).toBe("465");
    f = setTlsMode(f, "STARTTLS_OPTIONAL");
    expect(f.config.port).toBe("587");
  });

  it("keeps a typed port", () => {
    let f = setPort(smtp(), "2525");
    f = setTlsMode(f, "IMPLICIT");
    expect(f.config.port).toBe("2525");
    expect(f.config.tlsMode).toBe("IMPLICIT");
  });

  it("goes back to automatic when the port is cleared", () => {
    let f = setPort(smtp(), "");
    expect(f.portTouched).toBe(false);
    f = setTlsMode(f, "IMPLICIT");
    expect(f.config.port).toBe("465");
  });
});

describe("toWrite", () => {
  it("never sends starttls, trims values and drops empty ones", () => {
    const w = toWrite(smtp({ config: { host: " smtp.example.com ", tlsMode: "IMPLICIT", port: "465", ehloName: "", starttls: "true" } }));
    expect(w.config).toEqual({ host: "smtp.example.com", tlsMode: "IMPLICIT", port: "465" });
    expect(w).toMatchObject({ channel: "EMAIL", driver: "SMTP", fromAddress: "no-reply@example.com" });
  });

  it("keeps a stored secret by sending null when not replacing", () => {
    const w = toWrite(smtp({ secret: { stored: true, replacing: false, value: "" } }));
    expect(w.secret).toBeNull();
  });

  it("never sends an empty secret", () => {
    expect(toWrite(smtp({ secret: { stored: true, replacing: true, value: "   " } })).secret).toBeNull();
    expect(toWrite(smtp({ secret: { stored: false, replacing: false, value: "" } })).secret).toBeNull();
  });

  it("sends a new secret exactly as typed", () => {
    expect(toWrite(smtp({ secret: { stored: true, replacing: true, value: " p@ss " } })).secret).toBe(" p@ss ");
    expect(toWrite(cloudflare()).secret).toBe("cf-token");
  });

  it("keeps unknown config keys (settings this form does not show)", () => {
    const w = toWrite(cloudflare({ config: { accountId: "a1", futureKey: "x" } }));
    expect(w.config).toEqual({ accountId: "a1", futureKey: "x" });
  });

  it("sends null for an empty from name", () => {
    expect(toWrite(smtp({ fromName: "  " })).fromName).toBeNull();
  });
});

describe("isEmailAddress", () => {
  it("accepts plain addresses", () => {
    expect(isEmailAddress("no-reply@example.com")).toBe(true);
    expect(isEmailAddress("a.b+tag@sub.example.co.uk")).toBe(true);
    expect(isEmailAddress("dev@localhost")).toBe(true);
  });
  it("rejects display names, lists and junk", () => {
    expect(isEmailAddress("Acme <no-reply@example.com>")).toBe(false);
    expect(isEmailAddress("a@b.com, c@d.com")).toBe(false);
    expect(isEmailAddress("no-reply")).toBe(false);
    expect(isEmailAddress("@example.com")).toBe(false);
    expect(isEmailAddress("a@")).toBe(false);
    expect(isEmailAddress("a b@example.com")).toBe(false);
    expect(isEmailAddress("a@@example.com")).toBe(false);
  });
});

describe("validateEmailForm — from address and name", () => {
  it("passes a valid SMTP form", () => {
    expect(validateEmailForm(smtp())).toEqual({});
  });
  it("requires the from address for every driver but LOG", () => {
    for (const driver of ["SMTP", "CLOUDFLARE", "HTTP"] as const) {
      const f = { ...formFromProvider(driver), fromAddress: "" };
      expect(validateEmailForm(f).fromAddress).toBe("email.err.fromRequired");
    }
    expect(validateEmailForm({ ...formFromProvider("LOG"), fromAddress: "" })).toEqual({});
  });
  it("rejects a malformed from address", () => {
    expect(validateEmailForm(smtp({ fromAddress: "Acme <a@b.com>" })).fromAddress).toBe("email.err.fromInvalid");
  });
  it("rejects a multi-line or overlong from name", () => {
    expect(validateEmailForm(smtp({ fromName: "a\nb" })).fromName).toBe("email.err.fromName");
    expect(validateEmailForm(smtp({ fromName: "x".repeat(201) })).fromName).toBe("email.err.fromName");
    expect(validateEmailForm(smtp({ fromName: "x".repeat(200) })).fromName).toBeUndefined();
  });
});

describe("validateEmailForm — SMTP", () => {
  it("requires a host and checks its characters", () => {
    expect(validateEmailForm(smtp({ config: { tlsMode: "IMPLICIT" } }))["config.host"]).toBe("email.err.hostRequired");
    expect(validateEmailForm(smtp({ config: { host: "smtp example.com" } }))["config.host"]).toBe("email.err.hostInvalid");
    expect(validateEmailForm(smtp({ config: { host: "[2001:db8::1]" } }))["config.host"]).toBeUndefined();
  });
  it("checks the port range and that it is a whole number", () => {
    const port = (p: string) => validateEmailForm(smtp({ config: { host: "h", port: p } }))["config.port"];
    expect(port("0")).toBe("email.err.port");
    expect(port("65536")).toBe("email.err.port");
    expect(port("58.7")).toBe("email.err.port");
    expect(port("abc")).toBe("email.err.port");
    expect(port("1")).toBeUndefined();
    expect(port("65535")).toBeUndefined();
    expect(port("")).toBeUndefined();
  });
  it("checks the timeouts are 100–300000 ms", () => {
    const f = smtp({ config: { host: "h", connectTimeoutMs: "99", readTimeoutMs: "300001" } });
    const e = validateEmailForm(f);
    expect(e["config.connectTimeoutMs"]).toBe("email.err.timeout");
    expect(e["config.readTimeoutMs"]).toBe("email.err.timeout");
    expect(validateEmailForm(smtp({ config: { host: "h", connectTimeoutMs: "100", readTimeoutMs: "300000" } }))).toEqual({});
  });
  it("checks the EHLO name", () => {
    expect(validateEmailForm(smtp({ config: { host: "h", ehloName: "mail_host" } }))["config.ehloName"]).toBe("email.err.ehlo");
    expect(validateEmailForm(smtp({ config: { host: "h", ehloName: "mail.example.com" } }))["config.ehloName"]).toBeUndefined();
  });
  it("checks the CA bundle looks like PEM certificates", () => {
    const bad = validateEmailForm(smtp({ config: { host: "h", caBundle: "not a cert" } }));
    expect(bad["config.caBundle"]).toBe("email.err.caBundle");
    const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    expect(validateEmailForm(smtp({ config: { host: "h", caBundle: pem } }))["config.caBundle"]).toBeUndefined();
  });
  it("does not require a password (relays may not authenticate)", () => {
    expect(validateEmailForm(smtp({ config: { host: "h", username: "u" } })).secret).toBeUndefined();
  });
  it("asks for the new password when Replace was chosen but left empty", () => {
    expect(validateEmailForm(smtp({ secret: { stored: true, replacing: true, value: "" } })).secret).toBe("email.err.secretReplaceEmpty");
  });
});

describe("validateEmailForm — Cloudflare", () => {
  it("passes a valid form", () => {
    expect(validateEmailForm(cloudflare())).toEqual({});
  });
  it("requires the account id and checks its characters", () => {
    expect(validateEmailForm(cloudflare({ config: {} }))["config.accountId"]).toBe("email.err.accountIdRequired");
    expect(validateEmailForm(cloudflare({ config: { accountId: "abc/def" } }))["config.accountId"]).toBe("email.err.accountIdInvalid");
    expect(validateEmailForm(cloudflare({ config: { accountId: "a".repeat(65) } }))["config.accountId"]).toBe("email.err.accountIdInvalid");
  });
  it("requires the API token unless one is stored", () => {
    expect(validateEmailForm(cloudflare({ secret: { stored: false, replacing: false, value: "" } })).secret).toBe("email.err.tokenRequired");
    expect(validateEmailForm(cloudflare({ secret: { stored: true, replacing: false, value: "" } })).secret).toBeUndefined();
  });
  it("requires an https base URL without credentials, query or fragment", () => {
    const base = (u: string) => validateEmailForm(cloudflare({ config: { accountId: "a", baseUrl: u } }))["config.baseUrl"];
    expect(base("https://api.cloudflare.com/client/v4")).toBeUndefined();
    expect(base("")).toBeUndefined();
    expect(base("http://proxy.internal/client/v4")).toBe("email.err.httpsRequired");
    expect(base("api.cloudflare.com")).toBe("email.err.urlInvalid");
    expect(base("https://user:pw@proxy.example")).toBe("email.err.urlCredentials");
    expect(base("https://proxy.example/v4?x=1")).toBe("email.err.urlQuery");
    expect(base("https://proxy.example/v4#frag")).toBe("email.err.urlQuery");
  });
  it("checks the timeouts", () => {
    expect(validateEmailForm(cloudflare({ config: { accountId: "a", readTimeoutMs: "5" } }))["config.readTimeoutMs"]).toBe("email.err.timeout");
  });
});

describe("validateEmailForm — HTTP relay", () => {
  const http = (url?: string): EmailForm => ({ ...formFromProvider("HTTP"), fromAddress: "a@b.co", config: url === undefined ? {} : { url } });
  it("requires an absolute http(s) URL", () => {
    expect(validateEmailForm(http())["config.url"]).toBe("email.err.urlRequired");
    expect(validateEmailForm(http("ftp://relay"))["config.url"]).toBe("email.err.urlInvalid");
    expect(validateEmailForm(http("http://relay.internal/send"))["config.url"]).toBeUndefined();
    expect(validateEmailForm(http("https://u:p@relay/send"))["config.url"]).toBe("email.err.urlCredentials");
  });
});

describe("validateTestRecipient", () => {
  it("requires one valid address", () => {
    expect(validateTestRecipient("")).toBe("email.err.testToRequired");
    expect(validateTestRecipient("nope")).toBe("email.err.testToInvalid");
    expect(validateTestRecipient(" me@example.com ")).toBeNull();
  });
});

describe("splitServerErrors", () => {
  it("keeps field errors for fields on the form and lists the rest", () => {
    const s = splitServerErrors("SMTP", {
      "config.host": "The SMTP host is required.",
      "config.starttls": "starttls must be true or false.",
      fromAddress: "The from address is required.",
      driver: "Unknown EMAIL driver.",
    });
    expect(s.fields).toEqual({ "config.host": "The SMTP host is required.", fromAddress: "The from address is required." });
    expect(s.other).toEqual(["starttls must be true or false.", "Unknown EMAIL driver."]);
  });
  it("puts a Cloudflare baseUrl error on the field", () => {
    expect(splitServerErrors("CLOUDFLARE", { "config.baseUrl": "The URL must use https." }).fields)
      .toEqual({ "config.baseUrl": "The URL must use https." });
  });
});

describe("initialEmailDriver / otherEnabledEmailDrivers", () => {
  const list = [
    provider({ driver: "SMTP", enabled: false }),
    provider({ driver: "CLOUDFLARE", enabled: true }),
    provider({ channel: "SMS", driver: "HTTP", enabled: true }),
  ];
  it("opens on the enabled email provider", () => {
    expect(initialEmailDriver(list)).toBe("CLOUDFLARE");
  });
  it("falls back to a configured one, then SMTP", () => {
    expect(initialEmailDriver([provider({ driver: "LOG", enabled: false })])).toBe("LOG");
    expect(initialEmailDriver([])).toBe("SMTP");
    expect(initialEmailDriver([provider({ driver: "SENDGRID", enabled: true })])).toBe("SMTP");
  });
  it("lists the other enabled email drivers only", () => {
    expect(otherEnabledEmailDrivers(list, "SMTP")).toEqual(["CLOUDFLARE"]);
    expect(otherEnabledEmailDrivers(list, "CLOUDFLARE")).toEqual([]);
  });
});

describe("isDirty", () => {
  it("is false for an untouched form and true after an edit or a new secret", () => {
    const base = formFromProvider("SMTP", provider({ config: { host: "h", tlsMode: "STARTTLS_REQUIRED", port: "587" } }));
    expect(isDirty(base, base)).toBe(false);
    expect(isDirty({ ...base, config: { ...base.config, host: "h2" } }, base)).toBe(true);
    expect(isDirty({ ...base, enabled: !base.enabled }, base)).toBe(true);
    expect(isDirty({ ...base, secret: { stored: false, replacing: false, value: "x" } }, base)).toBe(true);
    // Replace chosen but nothing typed yet: still unsaved, so Save validates and asks for the value.
    expect(isDirty({ ...base, secret: { stored: true, replacing: true, value: "" } }, { ...base, secret: { stored: true, replacing: false, value: "" } })).toBe(true);
  });
});

describe("describeTestResult", () => {
  it("maps each classified status to a tone and title", () => {
    const d = (result: string, sent: boolean) => describeTestResult({ sent, message: "", result, reason: "NONE" }, "SMTP");
    expect(d("ACCEPTED", true)).toMatchObject({ tone: "success", title: "email.test.status.ACCEPTED" });
    expect(d("QUEUED", true)).toMatchObject({ tone: "info", title: "email.test.status.QUEUED" });
    expect(d("PERMANENT_FAILURE", false)).toMatchObject({ tone: "danger", title: "email.test.status.PERMANENT_FAILURE" });
    expect(d("TRANSIENT_FAILURE", false)).toMatchObject({ tone: "warning", title: "email.test.status.TRANSIENT_FAILURE" });
  });

  it("gives Cloudflare token and domain guidance on authentication failures", () => {
    const d = describeTestResult({ sent: false, message: "Test email not delivered.", result: "TRANSIENT_FAILURE", reason: "AUTHENTICATION", diagnostic: "HTTP 403: 10000 Authentication error" }, "CLOUDFLARE");
    expect(d.reason).toBe("email.test.reason.AUTHENTICATION");
    expect(d.guidance).toBe("email.test.guide.cloudflareAuth");
    expect(d.diagnostic).toBe("HTTP 403: 10000 Authentication error");
  });

  it("recognises 401/403 in the diagnostic even without the AUTHENTICATION reason", () => {
    const d = describeTestResult({ sent: false, message: "", result: "TRANSIENT_FAILURE", reason: "PROVIDER_ERROR", diagnostic: "HTTP 401 Unauthorized" }, "CLOUDFLARE");
    expect(d.guidance).toBe("email.test.guide.cloudflareAuth");
  });

  it("gives SMTP credential guidance for SMTP authentication failures", () => {
    const d = describeTestResult({ sent: false, message: "", result: "PERMANENT_FAILURE", reason: "AUTHENTICATION", diagnostic: "535 5.7.8 Authentication failed" }, "SMTP");
    expect(d.guidance).toBe("email.test.guide.smtpAuth");
  });

  it("suggests an HTTPS driver when SMTP cannot connect", () => {
    const d = describeTestResult({ sent: false, message: "", result: "TRANSIENT_FAILURE", reason: "NETWORK", diagnostic: "Connection refused" }, "SMTP");
    expect(d.guidance).toBe("email.test.guide.smtpNetwork");
  });

  it("explains a bounce", () => {
    const d = describeTestResult({ sent: false, message: "", result: "PERMANENT_FAILURE", reason: "RECIPIENT_BOUNCED" }, "CLOUDFLARE");
    expect(d.guidance).toBe("email.test.guide.bounced");
  });

  it("keeps the provider message id", () => {
    const d = describeTestResult({ sent: true, message: "Test email sent.", result: "ACCEPTED", reason: "NONE", providerMessageId: "<abc@helix>" }, "SMTP");
    expect(d.providerMessageId).toBe("<abc@helix>");
    expect(d.guidance).toBeUndefined();
  });

  it("falls back to the server message when the answer is not classified", () => {
    const d = describeTestResult({ sent: false, message: "No enabled EMAIL provider for this realm." }, "SMTP");
    expect(d).toMatchObject({ tone: "danger", title: "email.test.notSent", message: "No enabled EMAIL provider for this realm.", guidance: "email.test.guide.noProvider" });
  });
});
