import React from "react";

export type ProviderKind =
  | "oidc"
  | "saml"
  | "ldap"
  | "social"
  | "digid"
  | "eherkenning"
  | "eidas"
  | "google"
  | "microsoft"
  | "github"
  | "facebook"
  | "gitlab"
  | "linkedin"
  | "instagram"
  | "twitter"
  | "bitbucket"
  | "paypal"
  | "stackoverflow"
  | "openshift"
  | "apple";

export interface ProviderLogoProps {
  kind: ProviderKind;
  size?: number;
}

/**
 * Provider mark for the connection picker. Google/Microsoft/GitHub use their recognizable
 * marks; the Dutch/EU eIDs use branded monogram tiles in each scheme's colours (representative —
 * swap in licensed official assets in production). Generic protocols use a tokenised glyph.
 */
export function ProviderLogo({ kind, size = 36 }: ProviderLogoProps) {
  const r = Math.round(size * 0.28);
  const tile = (bg: string, children: React.ReactNode, ring = false): React.ReactElement => (
    <span
      style={{
        width: size,
        height: size,
        flexShrink: 0,
        borderRadius: r,
        background: bg,
        border: ring ? "1px solid var(--border)" : "none",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        overflow: "hidden",
      }}
    >
      {children}
    </span>
  );

  const monogram = (text: string, color = "#fff", fs = size * 0.36) => (
    <span style={{ color, font: `800 ${fs}px var(--font)`, letterSpacing: "-0.02em" }}>{text}</span>
  );

  switch (kind) {
    case "google":
      return tile(
        "#fff",
        <svg width={size * 0.56} height={size * 0.56} viewBox="0 0 48 48" aria-hidden="true">
          <path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z" />
          <path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7C7.96 41.07 15.4 46 24 46z" />
          <path fill="#FBBC05" d="M11.69 28.18c-.44-1.32-.69-2.73-.69-4.18s.25-2.86.69-4.18v-5.7H4.34A21.99 21.99 0 002 24c0 3.55.85 6.91 2.34 9.88l7.35-5.7z" />
          <path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7c1.73-5.2 6.58-9.07 12.31-9.07z" />
        </svg>,
        true
      );
    case "microsoft":
      return tile(
        "#fff",
        <svg width={size * 0.52} height={size * 0.52} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#F25022" d="M1 1h10v10H1z" />
          <path fill="#7FBA00" d="M13 1h10v10H13z" />
          <path fill="#00A4EF" d="M1 13h10v10H1z" />
          <path fill="#FFB900" d="M13 13h10v10H13z" />
        </svg>,
        true
      );
    case "github":
      return tile(
        "#24292f",
        <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 24 24" fill="#fff" aria-hidden="true">
          <path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.5 2.87 8.32 6.84 9.67.5.1.68-.22.68-.49l-.01-1.7c-2.78.62-3.37-1.37-3.37-1.37-.46-1.18-1.11-1.5-1.11-1.5-.91-.64.07-.62.07-.62 1 .07 1.53 1.06 1.53 1.06.9 1.57 2.36 1.12 2.94.86.09-.67.35-1.12.63-1.38-2.22-.26-4.55-1.14-4.55-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05a9.3 9.3 0 015 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9l-.01 2.82c0 .27.18.6.69.49A10.02 10.02 0 0022 12.26C22 6.58 17.52 2 12 2z" />
        </svg>
      );
    case "facebook":
      return tile(
        "#1877F2",
        <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 24 24" fill="#fff" aria-hidden="true">
          <path d="M14 9V7c0-.9.6-1 1-1h2V3h-3c-2.2 0-4 1.8-4 4v2H8v3h2v9h4v-9h2.5l.5-3z" />
        </svg>
      );
    case "gitlab":
      return tile(
        "#fff",
        <svg width={size * 0.62} height={size * 0.62} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#E24329" d="M12 21l3.3-10.2H8.7z" />
          <path fill="#FC6D26" d="M12 21L8.7 10.8H4.1z" />
          <path fill="#FCA326" d="M4.1 10.8L3.1 14c-.1.3 0 .6.3.8L12 21z" />
          <path fill="#E24329" d="M4.1 10.8h4.6L6.7 4.6c-.1-.3-.5-.3-.6 0z" />
          <path fill="#FC6D26" d="M12 21l3.3-10.2h4.6z" />
          <path fill="#FCA326" d="M19.9 10.8l1 3.2c.1.3 0 .6-.3.8L12 21z" />
          <path fill="#E24329" d="M19.9 10.8h-4.6l2-6.2c.1-.3.5-.3.6 0z" />
        </svg>,
        true
      );
    case "linkedin":
      return tile(
        "#0A66C2",
        <svg width={size * 0.58} height={size * 0.58} viewBox="0 0 24 24" fill="#fff" aria-hidden="true">
          <path d="M6.5 8.5h-3V20h3V8.5zM5 4a1.75 1.75 0 100 3.5A1.75 1.75 0 005 4zM20.5 20v-6.4c0-3.4-1.8-5-4.2-5-1.6 0-2.7.9-3.1 1.7V8.5H10.3V20h3v-6.1c0-1.3.7-2.1 1.8-2.1s1.6.8 1.6 2.1V20h3.8z" />
        </svg>
      );
    case "instagram":
      return tile(
        "radial-gradient(circle at 30% 110%, #FFD600, #FF7A00 25%, #FF0069 50%, #D300C5 75%, #7638FA)",
        <svg width={size * 0.56} height={size * 0.56} viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" aria-hidden="true">
          <rect x="3" y="3" width="18" height="18" rx="5" />
          <circle cx="12" cy="12" r="4" />
          <circle cx="17.5" cy="6.5" r="1.2" fill="#fff" stroke="none" />
        </svg>
      );
    case "twitter":
      return tile(
        "#000",
        <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="#fff" aria-hidden="true">
          <path d="M18.2 2h3.3l-7.2 8.3L22.8 22h-6.6l-5.2-6.8L5.1 22H1.8l7.7-8.8L1.2 2h6.8l4.7 6.2L18.2 2zm-1.2 18h1.8L7.1 3.9H5.2L17 20z" />
        </svg>
      );
    case "bitbucket":
      return tile(
        "#fff",
        <svg width={size * 0.62} height={size * 0.62} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#2684FF" d="M3 4.5c-.4 0-.7.3-.6.7l2.6 14c.1.4.4.7.8.7h11.4c.3 0 .6-.2.6-.5l2.6-14.2c.1-.4-.2-.7-.6-.7H3z" />
          <path fill="#fff" d="M14.1 14.6H9.9L9.3 9.4h5.5z" />
        </svg>,
        true
      );
    case "paypal":
      return tile(
        "#fff",
        <svg width={size * 0.56} height={size * 0.56} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#003087" d="M7 20l.5-3h2.6c3.8 0 6.6-1.7 7.3-5.4.5-2.7-.6-4.3-2.4-5.1.3 2.6-1.3 5.1-5 5.1H9.5L8 20H7z" />
          <path fill="#0070E0" d="M9.2 4h5c2.7 0 4.6 1.4 4.2 4.2-.5 3.4-3 5-6.5 5H9.2l-1 5.8H5.4L7.7 4h1.5z" />
        </svg>,
        true
      );
    case "stackoverflow":
      return tile(
        "#fff",
        <svg width={size * 0.6} height={size * 0.6} viewBox="0 0 24 24" aria-hidden="true">
          <path fill="#BCBBBB" d="M6 18v-4H4v6h14v-6h-2v4z" />
          <path fill="#F48024" d="M7 14.7l7.5 1.6.4-2-7.5-1.6zM8 10.3l6.9 3.2.8-1.8-6.9-3.2zM10 6.3l5.8 4.9 1.3-1.5-5.8-4.9zM14 2.3l-1.6 1.2 4.5 6.1 1.6-1.2zM7 16.5h7.7v-2H7z" />
        </svg>,
        true
      );
    case "openshift":
      return tile("#EE0000", monogram("OS"));
    case "apple":
      return tile(
        "#000",
        <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="#fff" aria-hidden="true">
          <path d="M16 13c0-2.2 1.8-3.2 1.9-3.3-1-1.5-2.6-1.7-3.2-1.7-1.4-.1-2.7.8-3.3.8s-1.7-.8-2.8-.8C7 8 5.6 8.9 4.9 10.3c-1.5 2.6-.4 6.4 1.1 8.5.7 1 1.6 2.2 2.7 2.1 1.1 0 1.5-.7 2.8-.7s1.7.7 2.8.7c1.2 0 1.9-1 2.6-2 .8-1.2 1.2-2.3 1.2-2.4-.1 0-2.3-.9-2.3-3.5zM13.8 6.4c.6-.7 1-1.7.9-2.7-.9 0-1.9.6-2.5 1.3-.5.6-1 1.6-.9 2.6 1 .1 1.9-.5 2.5-1.2z" />
        </svg>
      );
    case "digid":
      return tile("#e17000", monogram("DigiD", "#fff", size * 0.26));
    case "eherkenning":
      return tile("#2b3a8c", monogram("eH"));
    case "eidas":
      return tile(
        "#003399",
        <svg width={size * 0.62} height={size * 0.62} viewBox="0 0 48 48" aria-hidden="true">
          {Array.from({ length: 12 }).map((_, i) => {
            const a = (i / 12) * Math.PI * 2 - Math.PI / 2;
            const cx = 24 + Math.cos(a) * 15;
            const cy = 24 + Math.sin(a) * 15;
            return <Star key={i} cx={cx} cy={cy} r={2.4} />;
          })}
        </svg>
      );
    case "oidc":
      return tile("#f7931e", monogram("ID"));
    case "saml":
      return tile(
        "var(--kd-slate)",
        <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V5z" stroke="#fff" strokeWidth="1.6" strokeLinejoin="round" />
          <path d="M9 12l2 2 4-4" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "ldap":
      return tile(
        "var(--kd-cucumber)",
        <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="5" r="2.3" stroke="#fff" strokeWidth="1.6" />
          <circle cx="6" cy="18" r="2.3" stroke="#fff" strokeWidth="1.6" />
          <circle cx="18" cy="18" r="2.3" stroke="#fff" strokeWidth="1.6" />
          <path d="M12 7.5v4M12 11.5H6v4M12 11.5h6v4" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      );
    case "social":
    default:
      return tile(
        "var(--kd-jade-soft)",
        <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="8" r="3.2" stroke="var(--kd-cucumber-d)" strokeWidth="1.6" />
          <path d="M5 19a7 7 0 0114 0" stroke="var(--kd-cucumber-d)" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      );
  }
}

function Star({ cx, cy, r }: { cx: number; cy: number; r: number }) {
  const pts = Array.from({ length: 10 }).map((_, i) => {
    const a = (i / 10) * Math.PI * 2 - Math.PI / 2;
    const rad = i % 2 === 0 ? r : r * 0.42;
    return `${cx + Math.cos(a) * rad},${cy + Math.sin(a) * rad}`;
  });
  return <polygon points={pts.join(" ")} fill="#FFCC00" />;
}
