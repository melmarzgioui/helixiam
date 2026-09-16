import { describe, it, expect } from "vitest";
import { validateSamlClient, createSamlClientHttpClient, SamlClientWrite } from "./samlClients";

describe("validateSamlClient", () => {
  const valid: SamlClientWrite = {
    entityId: "helix-sandbox-sp",
    assertionConsumerServiceUrl: "http://localhost:9090/saml/acs",
    singleLogoutServiceUrl: "http://localhost:9090/saml/slo",
  };

  it("accepts a well-formed relying party", () => {
    expect(validateSamlClient(valid)).toEqual({});
  });

  it("requires entityId and ACS URL", () => {
    const errors = validateSamlClient({ entityId: "", assertionConsumerServiceUrl: "" });
    expect(errors.entityId).toBeTruthy();
    expect(errors.assertionConsumerServiceUrl).toBeTruthy();
  });

  it("rejects a non-http ACS or SLO URL", () => {
    expect(validateSamlClient({ ...valid, assertionConsumerServiceUrl: "ftp://x" }).assertionConsumerServiceUrl).toBeTruthy();
    expect(validateSamlClient({ ...valid, singleLogoutServiceUrl: "not-a-url" }).singleLogoutServiceUrl).toBeTruthy();
  });

  it("allows an empty (optional) SLO URL", () => {
    expect(validateSamlClient({ ...valid, singleLogoutServiceUrl: "" }).singleLogoutServiceUrl).toBeUndefined();
  });

  it("requires an encryption certificate when assertion encryption is enabled", () => {
    const errors = validateSamlClient({ ...valid, options: { encryptAssertion: true, encryptionCertificate: "" } });
    expect(errors.encryptionCertificate).toBeTruthy();
  });

  it("accepts assertion encryption when a certificate is supplied", () => {
    const errors = validateSamlClient({ ...valid, options: { encryptAssertion: true, encryptionCertificate: "-----BEGIN CERTIFICATE-----abc-----END CERTIFICATE-----" } });
    expect(errors.encryptionCertificate).toBeUndefined();
  });

  it("rejects a non-http additional ACS URL", () => {
    const errors = validateSamlClient({ ...valid, options: { additionalAcsUrls: ["https://app/acs2", "not-a-url"] } });
    expect(errors.additionalAcsUrls).toBeTruthy();
  });

  it("rejects a non-http extra recipient", () => {
    const errors = validateSamlClient({ ...valid, options: { extraRecipients: ["ftp://nope"] } });
    expect(errors.extraRecipients).toBeTruthy();
  });

  it("allows well-formed advanced options", () => {
    const errors = validateSamlClient({
      ...valid,
      options: {
        signAssertion: true, signResponse: true, includeAttributes: true,
        additionalAcsUrls: ["https://app/acs2"], extraRecipients: ["https://app/acs"],
        extraAudiences: ["urn:app:audience"], assertionLifetimeSeconds: 300,
      },
    });
    expect(errors).toEqual({});
  });
});

describe("createSamlClientHttpClient", () => {
  it("builds realm-scoped, entity-encoded URLs", async () => {
    const calls: Array<{ url: string; method: string }> = [];
    const fakeFetch = (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET" });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) } as Response);
    };
    // @ts-expect-error inject a fake fetch for the test
    globalThis.fetch = fakeFetch;
    const api = createSamlClientHttpClient("http://localhost:8083");

    await api.list("master");
    await api.remove("master", "https://sp.example/meta");

    expect(calls[0].url).toBe("http://localhost:8083/admin/realms/master/saml-clients");
    expect(calls[1].method).toBe("DELETE");
    // the entityId (a URL itself) must be percent-encoded into the path
    expect(calls[1].url).toBe(
      "http://localhost:8083/admin/realms/master/saml-clients/https%3A%2F%2Fsp.example%2Fmeta",
    );
  });
});
