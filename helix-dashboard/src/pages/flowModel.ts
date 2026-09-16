/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { FlowExecution, AuthenticatorCatalogEntry, isConditionCatalogEntry } from "../api/flows";

/**
 * Helix IAM — the humanised model behind the Authentication editor. Turns the engine's raw execution
 * tree (REQUIRED/ALTERNATIVE/CONDITIONAL sub-flows) into plain-language "sign-in journey" stages and a
 * preview of the screens an end user actually sees. Pure + unit-tested so both the Simple (journey) and
 * Advanced (canvas) views — and the live login preview — stay in lock-step with one source of truth.
 */

export type ReqTone = "accent" | "neutral" | "warning" | "danger";

export interface RequirementMeta {
  /** plain-language label shown to admins instead of the engine keyword */
  label: string;
  /** one-line explanation of what it means for the user */
  hint: string;
  tone: ReqTone;
}

const REQUIREMENTS: Record<string, RequirementMeta> = {
  REQUIRED: { label: "Always", hint: "Every user must pass this to sign in.", tone: "accent" },
  ALTERNATIVE: { label: "Any one of", hint: "The user picks one of the methods here.", tone: "neutral" },
  CONDITIONAL: { label: "Only when", hint: "Runs only when its conditions are met.", tone: "warning" },
  DISABLED: { label: "Off", hint: "Skipped — not part of sign-in.", tone: "danger" },
};

export function requirementMeta(requirement: string): RequirementMeta {
  return REQUIREMENTS[requirement] ?? { label: requirement, hint: "", tone: "neutral" };
}

/** The four requirements as options for a plain-language selector. */
export const REQUIREMENT_OPTIONS = Object.keys(REQUIREMENTS).map((value) => ({ value, label: REQUIREMENTS[value].label }));

export interface JourneyMethod {
  execId: string;
  authenticatorId: string;
  label: string;
  loa: number;
  requirement: string;
  /** Per-execution admin config carried through from the raw execution (e.g. idp-redirect settings). */
  config?: Record<string, string>;
}

export interface JourneyCondition {
  execId: string;
  authenticatorId: string;
  label: string;
}

export interface JourneyStage {
  /** execution id of the stage node (a sub-flow, or a lone authenticator) */
  id: string;
  title: string;
  isGroup: boolean;
  requirement: string;
  /** condition children (factor-less predicates like "user has MFA enabled") */
  conditions: JourneyCondition[];
  /** real authenticator children (or the single authenticator for a lone stage) */
  methods: JourneyMethod[];
  /** ALL = every method runs; ANY = the user chooses one (alternative children) */
  selectMode: "ALL" | "ANY";
}

const isCondition = isConditionCatalogEntry;

const byPriority = (a: FlowExecution, b: FlowExecution) => a.priority - b.priority;

/** Derive the ordered, humanised sign-in stages from the raw execution tree. */
export function toJourney(execs: FlowExecution[], catalog: AuthenticatorCatalogEntry[]): JourneyStage[] {
  const cat = (id: string | null) => (id ? catalog.find((c) => c.id === id) : undefined);
  const label = (id: string | null) => cat(id)?.displayName ?? id ?? "Step";
  const childrenOf = (parentId: string | null) =>
    execs.filter((e) => (e.parentId ?? null) === parentId).sort(byPriority);

  return childrenOf(null).map((node) => {
    if (node.authenticatorId != null) {
      // A lone authenticator at the top level = a single-method stage.
      const c = cat(node.authenticatorId);
      return {
        id: node.executionId,
        title: label(node.authenticatorId),
        isGroup: false,
        requirement: node.requirement,
        conditions: [],
        methods: [{ execId: node.executionId, authenticatorId: node.authenticatorId, label: label(node.authenticatorId), loa: c?.levelOfAssurance ?? 0, requirement: node.requirement, config: node.config }],
        selectMode: "ALL",
      } satisfies JourneyStage;
    }

    const kids = childrenOf(node.executionId);
    const conditions: JourneyCondition[] = [];
    const methods: JourneyMethod[] = [];
    for (const k of kids) {
      const c = cat(k.authenticatorId);
      if (k.condition || isCondition(c)) {
        conditions.push({ execId: k.executionId, authenticatorId: k.authenticatorId ?? "", label: label(k.authenticatorId) });
      } else {
        methods.push({ execId: k.executionId, authenticatorId: k.authenticatorId ?? "", label: label(k.authenticatorId), loa: c?.levelOfAssurance ?? 0, requirement: k.requirement, config: k.config });
      }
    }
    const anyOf = methods.length > 1 && methods.every((m) => m.requirement === "ALTERNATIVE");
    return {
      id: node.executionId,
      title: stageTitle(conditions, methods),
      isGroup: true,
      requirement: node.requirement,
      conditions,
      methods,
      selectMode: anyOf ? "ANY" : "ALL",
    } satisfies JourneyStage;
  });
}

function stageTitle(conditions: JourneyCondition[], methods: JourneyMethod[]): string {
  if (methods.length === 0) return conditions.length ? "Conditions" : "Sub-flow";
  const maxLoa = Math.max(0, ...methods.map((m) => m.loa));
  if (maxLoa >= 3) return "Strong verification";
  if (methods.length > 1) return "Second factor";
  return methods[0].label;
}

/** A one-line, plain-English summary of the compiled journey — the "Resulting flow" read-out. */
export function summarizeJourney(stages: JourneyStage[]): string {
  const segments = ["Email & password"];
  for (const s of stages) {
    if (s.requirement === "DISABLED" || s.methods.length === 0) continue;
    const names = s.methods.map((m) => m.label);
    let seg = s.selectMode === "ANY" ? names.join(" or ") : names.join(" + ");
    if (s.conditions.length) seg += ` (only when ${s.conditions.map((c) => c.label).join(" and ")})`;
    segments.push(seg);
  }
  return segments.join(" → ");
}

export interface PreviewScreen {
  kind: "identify" | "factor" | "consent";
  title: string;
  methods: string[];
  /** true when the stage is conditional (the user may not see it) */
  optional: boolean;
}

/** The ordered screens an end user would actually walk through, for the live preview pane. */
export function previewScreens(stages: JourneyStage[]): PreviewScreen[] {
  const screens: PreviewScreen[] = [];
  for (const s of stages) {
    if (s.requirement === "DISABLED") continue;
    if (s.methods.length === 0) continue; // pure condition group with nothing to show
    const optional = s.requirement === "CONDITIONAL";
    const consentOnly = s.methods.every((m) => m.loa === 0);
    if (consentOnly) {
      screens.push({ kind: "consent", title: s.methods[0]?.label ?? "Review", methods: s.methods.map((m) => m.label), optional });
      continue;
    }
    const title = s.selectMode === "ANY" || s.methods.length > 1 ? "Choose how to verify" : `Verify with ${s.methods[0].label}`;
    screens.push({ kind: "factor", title, methods: s.methods.map((m) => m.label), optional });
  }
  return screens;
}
