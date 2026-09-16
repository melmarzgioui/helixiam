import React from "react";

export interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactElement;
  side?: "top" | "bottom";
}

/** Lightweight hover/focus tooltip. */
export function Tooltip({ content, children, side = "top" }: TooltipProps) {
  const [open, setOpen] = React.useState(false);
  return (
    <span
      style={{ position: "relative", display: "inline-flex" }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {open && (
        <span
          role="tooltip"
          style={{
            position: "absolute",
            left: "50%",
            transform: "translateX(-50%)",
            [side === "top" ? "bottom" : "top"]: "calc(100% + 7px)",
            zIndex: 40,
            padding: ".4rem .6rem",
            borderRadius: "calc(var(--r-sm) - 2px)",
            background: "var(--kd-blackcat)",
            color: "#fff",
            font: "500 .8rem var(--font)",
            whiteSpace: "nowrap",
            boxShadow: "var(--shadow)",
            pointerEvents: "none",
          }}
        >
          {content}
        </span>
      )}
    </span>
  );
}
