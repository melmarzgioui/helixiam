export type LogoVariant = "lockup" | "wordmark" | "mark";
export type LogoSize = "sm" | "md" | "lg";

export interface LogoProps {
  variant?: LogoVariant;
  size?: LogoSize;
}

const SIZES: Record<LogoSize, { mark: number; word: string }> = {
  sm: { mark: 26, word: "1.4rem" },
  md: { mark: 34, word: "1.75rem" },
  lg: { mark: 48, word: "2.5rem" },
};

/** The HelixIAM spark mark — a four-pointed star, drawn in a 0..125 viewBox. */
const SPARK =
  "M 115.0625 65.007812 L 88.875 77.605469 L 72.496094 85.519531 L 65.570312 115.921875 " +
  "L 65.363281 116.910156 L 61.667969 116.910156 L 61.667969 62.769531 L 9.9375 62.769531 " +
  "L 10.164062 61.816406 L 10.441406 61.3125 L 11.5 60.808594 L 54.8125 39.949219 " +
  "L 61.753906 9.546875 L 62.066406 8.160156 L 62.257812 8.089844 L 62.761719 8.332031 " +
  "L 64.027344 8.941406 L 64.027344 62.769531 L 114.558594 62.769531 L 114.785156 63.636719 Z";

/**
 * HelixIAM brand lockup — built exactly like the KubeDNA logotype: the "Helix" (--fg) + "IAM"
 * (--wordmark-accent = deep KubeDNA cyan, one colour on every ground) wordmark in Work Sans 800
 * (self-hosted, KubeDNA's own face), with the spark sitting cap-height at the bottom-right, on the baseline.
 */
export function Logo({ variant = "lockup", size = "md" }: LogoProps) {
  const s = SIZES[size];
  if (variant === "mark") {
    return (
      <svg width={s.mark} height={s.mark} viewBox="0 0 125 125" role="img" aria-label="HelixIAM">
        <path d={SPARK} fill="var(--wordmark-accent)" />
      </svg>
    );
  }
  return (
    <span
      style={{
        font: `800 ${s.word} var(--font)`,
        letterSpacing: "-0.02em",
        color: "var(--fg)",
        whiteSpace: "nowrap",
        lineHeight: 1,
      }}
    >
      Helix<span style={{ color: "var(--wordmark-accent)" }}>IAM</span>
      {/* trailing spark — cap-height, on the baseline, like KubeDNA's mark */}
      <svg
        viewBox="0 0 125 125"
        aria-hidden="true"
        style={{ height: "0.72em", width: "0.72em", marginLeft: "0.03em", verticalAlign: "baseline" }}
      >
        <path d={SPARK} fill="var(--wordmark-accent)" />
      </svg>
    </span>
  );
}
