/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { createPortal } from "react-dom";
import { Logo } from "./Logo";
import { Select } from "./Select";
import { useIsCompact } from "../hooks/useMediaQuery";
import { LanguageSwitcher } from "./LanguageSwitcher";
import { useT } from "../i18n/LocaleContext";
import "../styles/app.css";

export interface NavItemDef {
  id: string;
  label: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
}

export interface NavSection {
  title?: string;
  items: NavItemDef[];
}

export interface AppShellProps {
  sections: NavSection[];
  activeId: string;
  onNavigate?: (id: string) => void;
  realms?: { value: string; label: string }[];
  activeRealm?: string;
  onRealmChange?: (realm: string) => void;
  user?: { name: string; email?: string };
  /** Sign the admin out — renders a sign-out button on the user chip when provided. */
  onLogout?: () => void;
  title?: React.ReactNode;
  /** Current theme + toggle — renders a light/dark switch in the topbar when provided. */
  theme?: "light" | "dark";
  onToggleTheme?: () => void;
  children?: React.ReactNode;
}

/** Responsive console frame: fixed sidebar on desktop, off-canvas drawer on mobile; sticky topbar. */
export function AppShell({ sections, activeId, onNavigate, realms, activeRealm, onRealmChange, user, onLogout, theme, onToggleTheme, children }: AppShellProps) {
  const { t } = useT();
  const compact = useIsCompact();
  const [drawer, setDrawer] = React.useState(false);

  React.useEffect(() => {
    if (!compact) setDrawer(false);
  }, [compact]);

  const nav = (
    <nav className="hx-sidebar__nav">
      {sections.map((sec, si) => (
        <div key={si}>
          {sec.title && <div className="hx-navlabel">{sec.title}</div>}
          {sec.items.map((it) => {
            const on = it.id === activeId;
            return (
              <button
                key={it.id}
                className={`hx-navitem${on ? " hx-navitem--active" : ""}`}
                aria-current={on ? "page" : undefined}
                onClick={() => { onNavigate?.(it.id); setDrawer(false); }}
              >
                {it.icon && <span className="hx-navitem__icon">{it.icon}</span>}
                <span className="hx-navitem__grow">{it.label}</span>
                {it.badge}
              </button>
            );
          })}
        </div>
      ))}
    </nav>
  );

  /* The single account menu lives in the full-width header (top-right) — visible on desktop AND in the
     compact/mobile header — so the sidebar no longer carries a duplicate user chip. */
  const sidebar = nav;
  /* The mobile off-canvas drawer keeps a brand plate at its top (there's no header brand visible while
     the drawer is open on a phone). */
  const drawerContent = (
    <>
      <div className="hx-sidebar__brand"><Logo size="sm" /></div>
      {nav}
    </>
  );

  return (
    <div className="hx-shell">
      <header className="hx-topbar">
        <div className="hx-topbar__brand">
          {compact && (
            <button className="hx-iconbtn" aria-label={t("shell.menu.open")} onClick={() => setDrawer(true)}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </button>
          )}
          <Logo size="sm" variant={compact ? "mark" : undefined} />
        </div>

        <div className="hx-topbar__right">
            <LanguageSwitcher />
            {onToggleTheme && (
              <button
                className="hx-iconbtn"
                aria-label={theme === "dark" ? t("shell.theme.toLight") : t("shell.theme.toDark")}
                title={theme === "dark" ? t("shell.theme.light") : t("shell.theme.dark")}
                onClick={onToggleTheme}
              >
                {theme === "dark" ? (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <circle cx="12" cy="12" r="4.2" stroke="currentColor" strokeWidth="1.7" />
                    <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5 5l1.4 1.4M17.6 17.6L19 19M19 5l-1.4 1.4M6.4 17.6L5 19" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
                  </svg>
                ) : (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M20 14.5A8 8 0 019.5 4 7 7 0 1020 14.5z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
                  </svg>
                )}
              </button>
            )}
            {realms && realms.length > 0 && (
              <div className="hx-topbar__realm hx-topbar__realm--select" title={activeRealm}>
                <Select options={realms} value={activeRealm} onChange={onRealmChange} aria-label={t("shell.realm")} />
              </div>
            )}
            {user && <UserMenu user={user} onLogout={onLogout} />}
        </div>
      </header>

      <div className="hx-body">
        {!compact && <aside className="hx-sidebar">{sidebar}</aside>}

        <main className="hx-content">
          <div className="hx-content__inner">{children}</div>
        </main>
      </div>

      {compact && drawer && (
        <>
          <div className="hx-scrim" onClick={() => setDrawer(false)} />
          <aside className="hx-drawer hx-sidebar">{drawerContent}</aside>
        </>
      )}
    </div>
  );
}

/** The header user chip: a button showing the signed-in admin that opens a dropdown menu (profile
 *  header + Sign out). Portalled + auto-flips above the trigger when it sits near the viewport bottom
 *  (the sidebar foot), mirroring RowMenu. Falls back to a static chip when there's no logout handler. */
function UserMenu({ user, onLogout, block }: { user: { name: string; email?: string }; onLogout?: () => void; block?: boolean }) {
  const { t } = useT();
  const [open, setOpen] = React.useState(false);
  const [pos, setPos] = React.useState<{ top?: number; bottom?: number; right: number } | null>(null);
  const btnRef = React.useRef<HTMLButtonElement>(null);
  const menuRef = React.useRef<HTMLDivElement>(null);

  const place = () => {
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const right = Math.max(8, window.innerWidth - r.right);
    const estimate = 140;
    if (r.bottom + estimate > window.innerHeight) setPos({ bottom: window.innerHeight - r.top + 6, right });
    else setPos({ top: r.bottom + 6, right });
  };
  const toggle = () => { if (!open) place(); setOpen((v) => !v); };

  React.useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { const t = e.target as Node; if (!btnRef.current?.contains(t) && !menuRef.current?.contains(t)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    const onScroll = () => setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);

  const chip = (
    <>
      <span className="hx-avatar" aria-hidden="true">{initials(user.name)}</span>
      <span className="hx-userchip__meta">
        <span className="hx-userchip__name">{user.name}</span>
        {user.email && <span className="hx-userchip__email">{user.email}</span>}
      </span>
    </>
  );

  if (!onLogout) return <div className="hx-userchip">{chip}</div>;

  return (
    <>
      <button ref={btnRef} type="button" className={`hx-usermenu-trigger hx-menutrigger${block ? " hx-menutrigger--block" : ""}`}
        aria-haspopup="menu" aria-expanded={open} aria-label={t("shell.account")} onClick={toggle}>
        {chip}
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="hx-menutrigger__chevron">
          <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && pos && createPortal(
        // The menu's screen position is computed from the trigger's own bounding rect — a value CSS
        // cannot express — so it is carried as custom properties, never as literal style props.
        <div ref={menuRef} role="menu" className="hx-portalmenu hx-portalmenu--wide"
          style={{
            "--mx-top": pos.top !== undefined ? `${pos.top}px` : undefined,
            "--mx-bottom": pos.bottom !== undefined ? `${pos.bottom}px` : undefined,
            "--mx-right": `${pos.right}px`,
          } as React.CSSProperties}>
          <div className="hx-portalmenu__head">
            <div className="hx-portalmenu__head-name">{user.name}</div>
            <div className="hx-portalmenu__head-sub">{user.email || t("shell.signedIn")}</div>
          </div>
          <button role="menuitem" className="hx-portalmenu-item" onClick={() => { setOpen(false); onLogout(); }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M15 17l5-5-5-5M20 12H9M9 21H6a2 2 0 01-2-2V5a2 2 0 012-2h3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {t("shell.signOut")}
          </button>
        </div>,
        document.body,
      )}
    </>
  );
}

function initials(name: string) {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}
