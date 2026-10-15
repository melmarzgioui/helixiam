/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Meta, StoryObj } from "@storybook/react";
import "../styles/app.css";
import { ProviderWizard } from "./ProviderWizard";
import { ConnectionDetailPage } from "../pages/ConnectionDetailPage";
import { createMemoryClient } from "../api/client";
import { createWalletMemoryClient, sampleCertificate, type VerifierKey } from "../api/wallet";

/**
 * The EUDI Wallet (OpenID4VP) provider: the "Add identity provider" wizard (pick "EUDI Wallet") and the connection
 * detail page (tabs Access key / Credentials / Policies), on in-memory APIs.
 */
const meta: Meta = {
  title: "Identity/EUDI Wallet provider",
  parameters: { layout: "padded" },
};
export default meta;
type Story = StoryObj;

const KEY: VerifierKey = {
  keyRef: "software:gov/eudi-access-2026", name: "eudi-access-2026", algorithm: "ES256",
  createdAt: "2026-09-01T10:00:00Z", chainLength: 2,
  certificate: sampleCertificate({ subject: "CN=login.gemeente.example,O=Gemeente Voorbeeld,C=NL", dnsNames: ["login.gemeente.example"] }),
};

const ANCHORS = "-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB…\n-----END CERTIFICATE-----\n";

const walletApi = (devProfile = false, flowEngineEnabled = true) => createWalletMemoryClient({
  keys: [KEY], devProfile, flowEngineEnabled,
  preview: () => [
    sampleCertificate({ subject: "CN=PID Issuer Root CA,O=Member State,C=DE", issuer: "CN=PID Issuer Root CA,O=Member State,C=DE", ca: true, selfSigned: true, notAfter: "2035-01-01T00:00:00Z" }),
    sampleCertificate({ subject: "CN=pid-issuer.example,O=Member State,C=DE", issuer: "CN=PID Issuer Root CA,O=Member State,C=DE", trustAnchorProblem: "A trust anchor is not a CA certificate" }),
  ],
});

const stored = createMemoryClient([{
  realmId: "gov", alias: "eudi-wallet", protocol: "eudi-wallet", displayName: "EUDI Wallet", enabled: true,
  config: {
    accessKeyRef: KEY.keyRef, clientIdScheme: "x509_san_dns", clientIdHost: "login.gemeente.example", trustAnchors: ANCHORS,
    credentialFormats: '["dc+sd-jwt","mso_mdoc"]', "pid.requestedClaims": '["given_name","family_name","birthdate"]',
    "subject.strategy": "ADMINISTRATIVE_NUMBER", "statusList.onUnavailable": "FAIL_CLOSED", responseMode: "direct_post.jwt",
  },
}]);

export const AddWithWizard: Story = {
  render: () => <ProviderWizard realmId="gov" walletApi={walletApi()} onComplete={(r) => console.log("create", r)} onCancel={() => {}} />,
};

export const DetailPage: Story = {
  render: () => <ConnectionDetailPage api={stored} walletApi={walletApi()} realmId="gov" alias="eudi-wallet" onBack={() => {}} />,
};

export const DetailPageDevProfile: Story = {
  render: () => <ConnectionDetailPage api={stored} walletApi={walletApi(true)} realmId="gov" alias="eudi-wallet" onBack={() => {}} />,
};

/** Verify-only / step-up (subject.strategy NONE): linked to the sign-in connection, releasing an age check. */
const withVerifyOnly = createMemoryClient([
  {
    realmId: "gov", alias: "eudi-wallet", protocol: "eudi-wallet", displayName: "EUDI Wallet", enabled: true,
    config: { accessKeyRef: KEY.keyRef, trustAnchors: ANCHORS, "subject.strategy": "ADMINISTRATIVE_NUMBER" },
  },
  {
    realmId: "gov", alias: "eudi-verify", protocol: "eudi-wallet", displayName: "EUDI Wallet check", enabled: true,
    config: {
      accessKeyRef: KEY.keyRef, trustAnchors: ANCHORS, credentialFormats: '["dc+sd-jwt","mso_mdoc"]',
      "pid.requestedClaims": '["birthdate","nationalities"]', "subject.strategy": "NONE",
      "verify.linkedProvider": "eudi-wallet", "verify.releasedClaims": '["age_over_18"]',
    },
  },
]);

export const DetailPageVerifyOnly: Story = {
  render: () => <ConnectionDetailPage api={withVerifyOnly} walletApi={walletApi()} realmId="gov" alias="eudi-verify" onBack={() => {}} />,
};

/** The wizard offers the realm's wallet sign-in connections as the linked connection of a verify-only one. */
export const AddWithWizardLinkedOptions: Story = {
  render: () => <ProviderWizard realmId="gov" walletApi={walletApi()} onComplete={(r) => console.log("create", r)}
    onCancel={() => {}} providers={[{ alias: "eudi-wallet", protocol: "eudi-wallet", displayName: "EUDI Wallet", config: {} }]} />,
};

/** The flow engine is off on the server: the verify-only connection warns that its step cannot run after a password. */
export const DetailPageVerifyOnlyEngineOff: Story = {
  render: () => <ConnectionDetailPage api={withVerifyOnly} walletApi={walletApi(false, false)} realmId="gov" alias="eudi-verify" onBack={() => {}} />,
};
