import React from "react";
import { useT } from "../i18n/LocaleContext";
import { LOCALES, type Locale } from "../i18n/i18n";

/**
 * Helix admin — self-contained language switcher for the top bar.
 *
 * A globe icon-button that opens a tiny popover of the supported locales. It reads + writes the
 * current locale through {@link useT} (the LocaleContext), so dropping it anywhere inside a
 * <LocaleProvider> is enough — no extra props or wiring required. Mount it in the AppShell topbar's
 * `hx-topbar__right` cluster (see report) next to the theme toggle.
 *
 * Styling reuses the existing `hx-iconbtn` / `hx-select-panel` / `hx-option` classes so it matches
 * the console chrome without new CSS.
 */
export function LanguageSwitcher() {
  const { locale, setLocale, t } = useT();
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const choose = (next: Locale) => {
    setLocale(next);
    setOpen(false);
  };

  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        type="button"
        className="hx-iconbtn"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={t("shell.language")}
        title={t("shell.language")}
        onClick={() => setOpen((o) => !o)}
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.7" />
          <path
            d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinecap="round"
          />
        </svg>
        <span
          aria-hidden="true"
          style={{ marginLeft: 4, font: "600 .72rem var(--font)", textTransform: "uppercase" }}
        >
          {locale}
        </span>
      </button>

      {open && (
        <ul
          role="listbox"
          aria-label={t("shell.language")}
          className="hx-select-panel"
          style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, minWidth: 160, zIndex: 95 }}
        >
          {LOCALES.map((l) => {
            const isSelected = l.value === locale;
            return (
              <li
                key={l.value}
                role="option"
                aria-selected={isSelected}
                className={`hx-option${isSelected ? " hx-option--active" : ""}`}
                onClick={() => choose(l.value)}
              >
                <span style={{ fontWeight: isSelected ? 600 : 400 }}>{l.label}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
