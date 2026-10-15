/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { FlowExecution } from "../api/flows";
import { isWalletProtocol } from "./walletProvider";

/**
 * The flow editor's "EU Digital Identity Wallet verification" step (WalletVerifyAuthenticator on the server): it
 * names the realm's verify-only wallet connection in its config (`providerAlias`). Pure, unit-tested; the server's
 * flow save refuses a step without one (400 on `executions[i].config.providerAlias`).
 */
export const WALLET_VERIFY_ID = "eudi-wallet-verify";
export const PROVIDER_ALIAS = "providerAlias";

export interface VerifyConnection { alias: string; displayName: string; }

/** The realm's verify-only wallet connections (subject.strategy NONE): what the step can use. */
export function verifyOnlyConnections(
  idps: { alias: string; protocol: string; displayName: string; config?: Record<string, string> }[],
): VerifyConnection[] {
  return idps
    .filter((p) => isWalletProtocol(p.protocol) && (p.config?.["subject.strategy"] ?? "").trim().toUpperCase() === "NONE")
    .map((p) => ({ alias: p.alias, displayName: p.displayName }));
}

/**
 * executionId → i18n key for every wallet verification step that cannot be saved: no connection chosen, or (when the
 * realm's verify-only connections are known) one that is not among them. Empty: the flow may be saved.
 */
export function walletVerifyStepErrors(execs: FlowExecution[], connections: string[] | undefined): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const e of execs) {
    if (e.authenticatorId !== WALLET_VERIFY_ID) continue;
    const alias = (e.config?.[PROVIDER_ALIAS] ?? "").trim();
    if (!alias) errors[e.executionId] = "authFlow.walletVerify.err.required";
    else if (connections && !connections.includes(alias)) errors[e.executionId] = "authFlow.walletVerify.err.unknown";
  }
  return errors;
}

/** The executions with step `executionId`'s connection set to `alias` (a new array; the step gets a new object). */
export function setWalletVerifyProvider(execs: FlowExecution[], executionId: string, alias: string): FlowExecution[] {
  return execs.map((e) => (e.executionId === executionId ? { ...e, config: { ...(e.config ?? {}), [PROVIDER_ALIAS]: alias } } : e));
}
