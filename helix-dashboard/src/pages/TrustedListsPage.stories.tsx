/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import type { ReactNode } from "react";
import { ToastProvider } from "../components/ToastProvider";
import { LocaleProvider } from "../i18n/LocaleContext";
import {
  createTrustedListMemoryClient, sampleTrustedList, type TrustedListAnchor, type TrustedListMember,
} from "../api/trustedLists";
import { TrustedListDetailPage, TrustedListsPage } from "./TrustedListsPage";

const meta: Meta<typeof TrustedListsPage> = {
  title: "Pages/TrustedListsPage",
  component: TrustedListsPage,
  parameters: { layout: "fullscreen" },
};
export default meta;
type Story = StoryObj<typeof TrustedListsPage>;

const wrap = (node: ReactNode) => (
  <LocaleProvider initialLocale="en">
    <ToastProvider>{node}</ToastProvider>
  </LocaleProvider>
);

const anchor = (cn: string, country: string, usable = true): TrustedListAnchor => ({
  subject: `CN=${cn},O=EUDI Wallet Reference Implementation,C=${country}`,
  issuer: `CN=${cn},O=EUDI Wallet Reference Implementation,C=${country}`, serialNumber: cn.length.toString(16),
  notAfter: "2032-11-27T18:34:16Z", serviceName: "PID issuance", provider: `${country} Services`, country,
  serviceType: "http://uri.etsi.org/Svc/Svctype/Provider/PID",
  status: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel", usable,
  problem: usable ? null : "A trust anchor is not a CA certificate",
});

const member = (territory: string, status: TrustedListMember["status"], anchorCount: number,
  lastError: string | null = null): TrustedListMember => ({
  territory, location: `https://trustedlist.serviceproviders.eudiw.dev/TL/${territory}/01.xml`, status,
  anchorsInUse: status === "OK" || status === "FAILING" || status === "STALE", sequenceNumber: 4,
  listIssuedAt: "2026-09-30T08:00:00Z", nextUpdate: "2026-10-27T14:28:34Z", anchorsUsableUntil: "2026-10-28T14:28:34Z",
  lastAttemptAt: "2026-10-15T08:12:40Z", lastSuccessAt: "2026-10-15T08:12:40Z", lastError, serviceCount: anchorCount,
  anchorCount,
});

const lists = [
  sampleTrustedList({ status: "DEGRADED", listOfLists: true, members: [
    member("AT", "OK", 2), member("FR", "FAILING", 5, "FETCH: the list could not be fetched: fetch timed out"),
    member("NL", "OK", 2), member("SK", "ERROR", 0, "POLICY: the list URL must be https"),
  ] }),
  sampleTrustedList({ id: "tl-2", name: "ec-pid-providers", format: "ETSI_119602_JSON",
    url: "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json", status: "ERROR",
    anchorsInUse: false, anchorCount: 0, lastError: "SIGNER: the pinned signer certificate expired on "
      + "2026-09-15T08:22:10Z (ETSI TS 119 615 PRO-4.1.4: an expired signer makes the list indeterminate)" }),
];
lists.push(sampleTrustedList({ id: "tl-3", name: "tampered", status: "INTEGRITY", anchorsInUse: false, anchorCount: 0,
  lastError: "INTEGRITY: the stored settings failed the integrity check (missing or wrong MAC); check and save them again" }));
const api = () => createTrustedListMemoryClient({ lists: lists.map((l) => ({ ...l })),
  anchors: [anchor("PID Issuer CA - UT 01", "UT"), anchor("PID Issuer CA - NL 01", "NL"),
    anchor("reader-issuer@idakto.com", "FR", false)] });

export const List: Story = {
  render: () => wrap(<TrustedListsPage api={api()} realmId="master" onOpen={() => undefined} />),
};

export const Empty: Story = {
  render: () => wrap(<TrustedListsPage api={createTrustedListMemoryClient()} realmId="master" onOpen={() => undefined} />),
};

export const DetailDegraded: Story = {
  render: () => wrap(<TrustedListDetailPage api={api()} realmId="master" id="tl-1" onBack={() => undefined} />),
};

export const DetailSignerExpired: Story = {
  render: () => wrap(<TrustedListDetailPage api={api()} realmId="master" id="tl-2" onBack={() => undefined} />),
};

export const DetailIntegrity: Story = {
  render: () => wrap(<TrustedListDetailPage api={api()} realmId="master" id="tl-3" onBack={() => undefined} />),
};
