/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { walletContext } from "./WalletProviderForm";
import { DEFAULT_WALLET_FORM, validateWallet } from "../pages/walletProvider";
import { sampleTrustedList } from "../api/trustedLists";

const ANCHOR = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const meta = { pidClaims: [], defaultRequestedClaims: [], credentialFormats: [], devProfile: false };

describe("walletContext", () => {
  it("passes the realm's trusted list names, so an unknown source is refused before saving", () => {
    const form = { ...DEFAULT_WALLET_FORM, accessKeyRef: "software:r/k", trustAnchors: ANCHOR, trustedListSources: ["gone"] };
    const ctx = walletContext(form, meta, [], undefined, [sampleTrustedList({ name: "eu-pid" })]);
    expect(ctx.trustedListNames).toEqual(["eu-pid"]);
    expect(validateWallet(form, ctx)["trustedLists.sources"]).toBe("wallet.err.trustedListUnknown");
  });

  it("does not check names while the lists are not loaded", () => {
    const form = { ...DEFAULT_WALLET_FORM, accessKeyRef: "software:r/k", trustAnchors: ANCHOR, trustedListSources: ["x"] };
    expect(walletContext(form, meta, [], undefined, null).trustedListNames).toBeUndefined();
  });
});
