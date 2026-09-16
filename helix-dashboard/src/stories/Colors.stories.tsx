import type { Meta, StoryObj } from "@storybook/react";

const meta: Meta = {
  title: "Foundations/Colors",
  parameters: { layout: "fullscreen" },
};
export default meta;

type Story = StoryObj;

type Swatch = { name: string; varName: string; note?: string };

const brand: Swatch[] = [
  { name: "Cucumber", varName: "--kd-cucumber", note: "primary" },
  { name: "Cucumber dark", varName: "--kd-cucumber-d", note: "hover" },
  { name: "Cucumber light", varName: "--kd-cucumber-l", note: "dark-mode primary" },
  { name: "Jade", varName: "--kd-jade", note: "dark-mode accent" },
  { name: "Jade soft", varName: "--kd-jade-soft" },
  { name: "Black Cat", varName: "--kd-blackcat" },
  { name: "Ink", varName: "--kd-ink", note: "text" },
  { name: "Willow", varName: "--kd-willow", note: "surface" },
  { name: "Willow 2", varName: "--kd-willow-2" },
  { name: "Slate", varName: "--kd-slate", note: "secondary text" },
  { name: "Faint", varName: "--kd-faint", note: "tertiary text" },
  { name: "Line", varName: "--kd-line", note: "hairline" },
  { name: "Daylight", varName: "--kd-daylight", note: "accent only" },
  { name: "Genie", varName: "--kd-genie", note: "accent only" },
];

const semantic: Swatch[] = [
  { name: "bg", varName: "--bg" },
  { name: "surface", varName: "--surface" },
  { name: "fg", varName: "--fg" },
  { name: "fg-muted", varName: "--fg-muted" },
  { name: "fg-faint", varName: "--fg-faint" },
  { name: "border", varName: "--border" },
  { name: "border-strong", varName: "--border-strong" },
  { name: "primary", varName: "--primary" },
  { name: "primary-hover", varName: "--primary-hover" },
  { name: "accent", varName: "--accent" },
  { name: "on-primary", varName: "--on-primary" },
];

function Grid({ title, swatches }: { title: string; swatches: Swatch[] }) {
  return (
    <section style={{ marginBottom: "2.5rem" }}>
      <h3 style={{ margin: "0 0 1rem", color: "var(--fg)" }}>{title}</h3>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: "1rem" }}>
        {swatches.map((s) => (
          <div key={s.varName} style={{ border: "1px solid var(--border)", borderRadius: "var(--r-sm)", overflow: "hidden" }}>
            <div style={{ height: 72, background: `var(${s.varName})`, borderBottom: "1px solid var(--border)" }} />
            <div style={{ padding: ".6rem .7rem" }}>
              <div style={{ fontWeight: 600, color: "var(--fg)", fontSize: ".9rem" }}>{s.name}</div>
              <div style={{ fontFamily: "var(--mono)", color: "var(--fg-muted)", fontSize: ".78rem" }}>{s.varName}</div>
              {s.note && <div style={{ color: "var(--fg-faint)", fontSize: ".75rem", marginTop: ".15rem" }}>{s.note}</div>}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

export const Palette: Story = {
  render: () => (
    <div style={{ padding: "2rem", background: "var(--bg)", minHeight: "100vh" }}>
      <Grid title="Brand palette" swatches={brand} />
      <Grid title="Semantic tokens (theme-aware)" swatches={semantic} />
      <p style={{ color: "var(--fg-faint)", fontSize: ".85rem", maxWidth: 640 }}>
        Switch the theme toolbar to <strong>dark</strong> to see semantic tokens flip to Black Cat surfaces
        and Jade accents. Daylight / Genie blues are accent-only and never appear in dark mode.
      </p>
    </div>
  ),
};
