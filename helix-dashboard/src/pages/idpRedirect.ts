import { FlowExecution } from "../api/flows";

/**
 * Helper for the Application → Login tab's "Single sign-on" control. An app's federation setting is a
 * single top-level `idp-redirect` step in its bound flow, which {@code LoginController} reads to decide:
 *   - REDIRECT   → skip the local screen and go straight to one provider;
 *   - OPTION     → show the local form plus the selected provider buttons (one or more);
 *   - LOCAL_ONLY → show the local form with no provider buttons.
 * These pure functions read and rewrite that step so the app view can present it as a friendly picker
 * without the admin ever opening the flow editor.
 */

export const IDP_REDIRECT_ID = "idp-redirect";
export const MODE_REDIRECT = "REDIRECT";
export const MODE_OPTION = "OPTION";
export const MODE_LOCAL_ONLY = "LOCAL_ONLY";
export type SsoMode = typeof MODE_REDIRECT | typeof MODE_OPTION | typeof MODE_LOCAL_ONLY;

export interface SsoSetting {
  mode: SsoMode;
  /** For REDIRECT: the single provider (index 0). For OPTION: the providers shown as alternatives. */
  aliases: string[];
}

const newExecId = (): string =>
  globalThis.crypto?.randomUUID?.() ?? `sso-${Math.random().toString(36).slice(2)}`;

const splitAliases = (csv?: string): string[] =>
  (csv ?? "").split(",").map((s) => s.trim()).filter(Boolean);

/**
 * The app's current SSO setting, read from the first top-level `idp-redirect` step. Returns null when
 * there is no such step (the app uses the login page's default — local + all enabled providers).
 */
export function readIdpRedirect(execs: FlowExecution[]): SsoSetting | null {
  const step = execs.find((e) => e.parentId == null && e.authenticatorId === IDP_REDIRECT_ID);
  if (!step) return null;
  const c = step.config ?? {};
  if (c.mode === MODE_LOCAL_ONLY) return { mode: MODE_LOCAL_ONLY, aliases: [] };
  if (c.mode === MODE_OPTION) {
    const aliases = splitAliases(c.providerAliases || c.providerAlias);
    return aliases.length ? { mode: MODE_OPTION, aliases } : null;
  }
  // REDIRECT (explicit or legacy default).
  const single = (c.providerAlias || splitAliases(c.providerAliases)[0] || "").trim();
  return single ? { mode: MODE_REDIRECT, aliases: [single] } : null;
}

/**
 * Return a new execution list with the app's SSO step set to `(mode, aliases)`. A "default" setting
 * (REDIRECT/OPTION with no aliases) removes the step so the app falls back to the login page default.
 * Any existing top-level `idp-redirect` steps are replaced, and a fresh step runs first (lowest
 * priority) so the redirect/option decision precedes factors.
 */
export function upsertIdpRedirect(execs: FlowExecution[], mode: SsoMode, aliases: string[]): FlowExecution[] {
  const withoutIdp = execs.filter((e) => !(e.parentId == null && e.authenticatorId === IDP_REDIRECT_ID));
  const clean = aliases.map((a) => a.trim()).filter(Boolean);
  // Nothing meaningful to persist (no providers and not an explicit local-only) → remove the step.
  if (mode !== MODE_LOCAL_ONLY && clean.length === 0) return withoutIdp;

  const config: Record<string, string> = { mode };
  if (mode === MODE_REDIRECT) config.providerAlias = clean[0];
  else if (mode === MODE_OPTION) config.providerAliases = clean.join(",");

  const topPriorities = withoutIdp.filter((e) => e.parentId == null).map((e) => e.priority);
  const priority = topPriorities.length ? Math.min(...topPriorities) - 10 : 0;
  const step: FlowExecution = {
    executionId: newExecId(),
    parentId: null,
    authenticatorId: IDP_REDIRECT_ID,
    requirement: "REQUIRED",
    condition: false,
    priority,
    config,
  };
  return [step, ...withoutIdp];
}
