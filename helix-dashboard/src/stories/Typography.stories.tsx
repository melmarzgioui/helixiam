import type { Meta, StoryObj } from "@storybook/react";

const meta: Meta = {
  title: "Foundations/Typography",
  parameters: { layout: "fullscreen" },
};
export default meta;

type Story = StoryObj;

export const Scale: Story = {
  render: () => (
    <div style={{ padding: "2rem", background: "var(--bg)", minHeight: "100vh", color: "var(--fg)" }}>
      <h2 style={{ marginTop: 0 }}>Work Sans</h2>
      <p style={{ color: "var(--fg-muted)", maxWidth: 640 }}>
        Headings use a tight <code>-0.02em</code> tracking and 1.1 line-height; body copy runs at 16px / 1.6.
      </p>

      <div style={{ display: "grid", gap: "1.2rem", marginTop: "2rem", maxWidth: 760 }}>
        <div style={{ fontWeight: 800, fontSize: "3rem", letterSpacing: "-0.02em", lineHeight: 1.1 }}>
          Identity, governed. — 48 / 800
        </div>
        <div style={{ fontWeight: 700, fontSize: "2.25rem", letterSpacing: "-0.02em", lineHeight: 1.1 }}>
          Connections &amp; brokers — 36 / 700
        </div>
        <div style={{ fontWeight: 700, fontSize: "1.5rem", letterSpacing: "-0.02em" }}>
          DigiD CombiConnect — 24 / 700
        </div>
        <div style={{ fontWeight: 600, fontSize: "1.05rem" }}>Card title — 17 / 600</div>
        <div style={{ fontSize: "1rem", color: "var(--fg)" }}>
          Body — 16 / 400. The Helix admin console lets operators register, configure, and monitor
          identity-provider connections without touching YAML.
        </div>
        <div style={{ fontSize: ".9rem", color: "var(--fg-muted)" }}>
          Secondary — 14.4 / muted. SAML2 · BSN · LoA Substantieel.
        </div>
        <div style={{ fontSize: ".8rem", color: "var(--fg-faint)" }}>
          Caption — 12.8 / faint. Last metadata refresh 2 hours ago.
        </div>
      </div>

      <h2 style={{ marginTop: "3rem" }}>Roboto Mono</h2>
      <pre
        style={{
          fontFamily: "var(--mono)",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-sm)",
          padding: "1rem 1.2rem",
          maxWidth: 760,
          overflowX: "auto",
        }}
      >
{`urn:nl-eid-gdi:1.0:id:legacy-BSN
urn:nl-eid-gdi:1.0:LoA:Substantieel
http://eidas.europa.eu/LoA/substantial`}
      </pre>
    </div>
  ),
};
