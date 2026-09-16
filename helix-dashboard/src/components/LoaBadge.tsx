import { Badge } from "./Badge";

export type LoaLevel = "low" | "substantial" | "high";

const LABEL: Record<LoaLevel, string> = {
  low: "LoA Low",
  substantial: "LoA Substantial",
  high: "LoA High",
};

const TONE: Record<LoaLevel, "neutral" | "accent" | "success"> = {
  low: "neutral",
  substantial: "accent",
  high: "success",
};

export interface LoaBadgeProps {
  level: LoaLevel;
  /** Override the default Dutch label (e.g. with the eIDAS English term). */
  label?: string;
}

/** Level-of-assurance pill. Defaults to the Dutch eID ladder; pass `label` for eIDAS wording. */
export function LoaBadge({ level, label }: LoaBadgeProps) {
  return <Badge tone={TONE[level]}>{label ?? LABEL[level]}</Badge>;
}
