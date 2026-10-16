/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { linkActions, provenanceKey, type LinkedIdentity } from "./federatedIdentities";

const link = (trustedForAdmins: boolean): LinkedIdentity =>
  ({ idpAlias: "corp", externalSubject: "s", createdVia: "AUTO", linkedAt: null, trustedForAdmins });

describe("linked identity actions", () => {
  it("offers nothing to an admin who is not a realm admin", () => {
    expect(linkActions(link(false), false)).toEqual([]);
    expect(linkActions(link(true), false)).toEqual([]);
  });
  it("offers confirm for an untrusted link and revoke for a trusted one", () => {
    expect(linkActions(link(false), true)).toEqual(["confirm"]);
    expect(linkActions(link(true), true)).toEqual(["revoke"]);
  });
  it("reads an unknown provenance as AUTO", () => {
    expect(provenanceKey("LEGACY")).toBe("userIdentities.via.LEGACY");
    expect(provenanceKey(" self ")).toBe("userIdentities.via.SELF");
    expect(provenanceKey("admin-api")).toBe("userIdentities.via.AUTO");
    expect(provenanceKey(null)).toBe("userIdentities.via.AUTO");
  });
});
