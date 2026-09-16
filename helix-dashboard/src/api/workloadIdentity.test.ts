/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { validateWorkloadIdentity, type WorkloadIdentityWrite } from "./workloadIdentity";

const base: WorkloadIdentityWrite = {
  name: "k8s-prod",
  issuer: "https://kubernetes.default.svc.cluster.local",
  subject: "system:serviceaccount:apps:billing",
  audience: "helix",
  clientId: "billing-service",
};

describe("validateWorkloadIdentity", () => {
  it("accepts a fully specified credential", () => {
    expect(validateWorkloadIdentity(base)).toEqual([]);
  });

  it("requires a name", () => {
    expect(validateWorkloadIdentity({ ...base, name: "  " })).toContain("name");
  });

  it("requires an absolute http(s) issuer", () => {
    expect(validateWorkloadIdentity({ ...base, issuer: "kubernetes.local" })).toContain("issuer");
    expect(validateWorkloadIdentity({ ...base, issuer: "" })).toContain("issuer");
  });

  it("requires a subject", () => {
    expect(validateWorkloadIdentity({ ...base, subject: "" })).toContain("subject");
  });

  it("requires an audience", () => {
    expect(validateWorkloadIdentity({ ...base, audience: "" })).toContain("audience");
  });

  it("requires a client identity", () => {
    expect(validateWorkloadIdentity({ ...base, clientId: "" })).toContain("clientId");
  });

  it("rejects a non-http jwksUri when one is given (blank is allowed)", () => {
    expect(validateWorkloadIdentity({ ...base, jwksUri: "ftp://x" })).toContain("jwksUri");
    expect(validateWorkloadIdentity({ ...base, jwksUri: "" })).toEqual([]);
    expect(validateWorkloadIdentity({ ...base, jwksUri: "https://k8s/openid/v1/jwks" })).toEqual([]);
  });

  it("reports every failing field at once", () => {
    expect(validateWorkloadIdentity({ name: "", issuer: "", subject: "", audience: "", clientId: "" }).sort()).toEqual(
      ["audience", "clientId", "issuer", "name", "subject"],
    );
  });
});
