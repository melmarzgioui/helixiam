import { CopyButton } from "./CopyButton";

/** A read-only label + monospace value with a copy-to-clipboard icon (used for endpoint/URL lists). */
export function CopyRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: ".5rem" }}>
      <span style={{ width: 156, flexShrink: 0, color: "var(--fg-muted)", fontSize: ".8rem" }}>{label}</span>
      <code style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: "var(--font-mono, monospace)", fontSize: ".8rem", color: "var(--fg)" }} title={value}>{value}</code>
      <CopyButton value={value} label={`Copy ${label}`} />
    </div>
  );
}
