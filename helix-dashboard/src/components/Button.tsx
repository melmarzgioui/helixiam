import React from "react";

export type ButtonVariant = "primary" | "ghost" | "danger";
export type ButtonSize = "md" | "lg";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  block?: boolean;
}

/** Brand button — primary (Cucumber gradient), ghost, or danger. Premium hover/focus via components.css. */
export function Button({ variant = "primary", size = "md", block, className, ...props }: ButtonProps) {
  const cls = ["hx-btn", `hx-btn--${variant}`, size === "lg" && "hx-btn--lg", block && "hx-btn--block", className]
    .filter(Boolean)
    .join(" ");
  return <button className={cls} {...props} />;
}
